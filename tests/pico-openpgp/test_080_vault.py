import hashlib
import os
import struct

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x448
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


VAULT_MAGIC = b"PKV1"
VAULT_ID_DOMAIN = b"PicoKeys Vault ID v1"
VAULT_ENROLL_INFO = b"PicoKeys Vault enrollment v1"
VAULT_ID_BYTES = 32
VAULT_ENROLL_CHALLENGE_BYTES = 32
SERIAL_MAX = 16
SERIAL_LENGTH_OFFSET = 68
SERIAL_OFFSET = 69
ALGORITHM_OFFSET = 85
HEADER_LENGTH = 86
NONCE_BYTES = 12
TAG_BYTES = 16
ALGORITHMS = (1, 2, 3, 4)

INS_VAULT = 0xF2
VAULT_STATUS = 0x01
VAULT_START_ENROLLMENT = 0x02
VAULT_FINISH_ENROLLMENT = 0x03
VAULT_EXPORT = 0x04
VAULT_IMPORT = 0x05
VAULT_UNENROLL = 0x06

OPENPGP_AID = bytes.fromhex("D27600012401")
PIV_AID = bytes.fromhex("A000000308")


def _vault_id(kvault):
    return hashlib.sha256(VAULT_ID_DOMAIN + kvault).digest()


def _object_hash(app, fid):
    return hashlib.sha256(bytes([app, fid >> 8, fid & 0xFF])).digest()


def _layer_algorithm(algorithm, layer):
    if algorithm == 3:
        return (1, 2)[layer]
    if algorithm == 4:
        return (2, 1)[layer]
    return algorithm


def _layer_key(kvault, vault_id, object_hash, algorithm, layer):
    info = VAULT_ENROLL_INFO + object_hash + bytes([algorithm, layer])
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=vault_id, info=info).derive(kvault)


def _aead(algorithm, key, nonce, data, aad, encrypt):
    cipher = ChaCha20Poly1305(key) if algorithm == 1 else AESGCM(key)
    if encrypt:
        return cipher.encrypt(nonce, data, aad)
    return cipher.decrypt(nonce, data, aad)


def _plain_object(app, fid):
    private_data = b"private-key-data"
    public_data = b"public-key-data"
    return b"".join((
        b"\x01",
        bytes([app]),
        fid.to_bytes(2, "big"),
        len(private_data).to_bytes(2, "big"),
        private_data,
        len(public_data).to_bytes(2, "big"),
        public_data,
    ))


def _export_blob(kvault, app, fid, algorithm, serial=b"0123456789ABCDEF", object_hash=None):
    if algorithm not in ALGORITHMS or len(serial) > SERIAL_MAX:
        raise ValueError("invalid vault blob parameters")
    vault_id = _vault_id(kvault)
    object_hash = _object_hash(app, fid) if object_hash is None else object_hash
    header = VAULT_MAGIC + vault_id + object_hash + bytes([len(serial)]) + serial.ljust(SERIAL_MAX, b"\0") + bytes([algorithm])
    layers = 2 if algorithm >= 3 else 1
    nonces = b"".join(bytes([algorithm, layer]) + bytes(NONCE_BYTES - 2) for layer in range(layers))
    encrypted = _plain_object(app, fid)
    for layer in range(layers):
        encrypted = _aead(_layer_algorithm(algorithm, layer), _layer_key(kvault, vault_id, object_hash, algorithm, layer), nonces[layer * NONCE_BYTES:(layer + 1) * NONCE_BYTES], encrypted, header, True)
    return header + nonces + encrypted


def _import_blob(kvault, blob):
    if len(blob) < HEADER_LENGTH + NONCE_BYTES + TAG_BYTES or blob[:4] != VAULT_MAGIC:
        raise ValueError("invalid vault blob")
    algorithm = blob[ALGORITHM_OFFSET]
    if algorithm not in ALGORITHMS or blob[SERIAL_LENGTH_OFFSET] > SERIAL_MAX:
        raise ValueError("invalid vault blob")
    layers = 2 if algorithm >= 3 else 1
    nonce_end = HEADER_LENGTH + layers * NONCE_BYTES
    encrypted = blob[nonce_end:]
    vault_id = blob[4:36]
    object_hash = blob[36:68]
    nonces = blob[HEADER_LENGTH:nonce_end]
    for layer in range(layers - 1, -1, -1):
        encrypted = _aead(_layer_algorithm(algorithm, layer), _layer_key(kvault, vault_id, object_hash, algorithm, layer), nonces[layer * NONCE_BYTES:(layer + 1) * NONCE_BYTES], encrypted, blob[:HEADER_LENGTH], False)
    if len(encrypted) < 8 or encrypted[0] != 1:
        raise ValueError("invalid vault object")
    app = encrypted[1]
    fid = int.from_bytes(encrypted[2:4], "big")
    private_length = int.from_bytes(encrypted[4:6], "big")
    public_length_offset = 6 + private_length
    if public_length_offset + 2 > len(encrypted):
        raise ValueError("invalid vault object")
    public_length = int.from_bytes(encrypted[public_length_offset:public_length_offset + 2], "big")
    if public_length_offset + 2 + public_length != len(encrypted):
        raise ValueError("invalid vault object")
    if _object_hash(app, fid) != object_hash:
        raise ValueError("object hash mismatch")
    return app, fid, encrypted[6:6 + private_length], encrypted[public_length_offset + 2:]


def _enrollment_packet(private_key, device_public, challenge, kvault, label):
    certificate = b"certificate"
    certificate_public = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    info = VAULT_ENROLL_INFO + challenge + certificate_public + device_public
    shared = private_key.exchange(x448.X448PublicKey.from_public_bytes(device_public))
    session_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared)
    label_bytes = label.encode()
    if len(label_bytes) > 64:
        raise ValueError("vault label is too long")
    plain = kvault + bytes([len(label_bytes)]) + label_bytes
    nonce = bytes(range(NONCE_BYTES))
    return struct.pack(">H", len(certificate)) + certificate + nonce + AESGCM(session_key).encrypt(nonce, plain, info)


def _reader(card):
    return card._OpenPGP_Card__reader


def _compose_apdu(ins, p1, p2, data=b"", le=None):
    data = bytes(data)
    apdu = bytearray([0, ins, p1, p2])
    if data:
        if len(data) < 256:
            apdu.append(len(data))
        else:
            apdu += bytes([0, len(data) >> 8, len(data) & 0xFF])
        apdu += data
    if le is not None:
        apdu += bytes([le]) if le < 256 else bytes([0, le >> 8, le & 0xFF])
    return bytes(apdu)


def _raw(card, ins, p1, p2, data=b"", le=None):
    response = _reader(card).send_cmd(_compose_apdu(ins, p1, p2, data, le))
    body, status = response[:-2], response[-2:]
    while status[0] == 0x61:
        response = _reader(card).send_cmd(_compose_apdu(0xC0, 0, 0, le=status[1]))
        body += response[:-2]
        status = response[-2:]
    return body, status


def _expect(card, ins, p1, p2, data=b"", status=b"\x90\x00"):
    body, actual = _raw(card, ins, p1, p2, data, le=0 if not data else None)
    assert actual == status
    return body


def _select(card, aid):
    return _expect(card, 0xA4, 0x04, 0, aid)


def _live_card(request):
    if os.environ.get("PICO_OPENPGP_VAULT_LIVE") != "1":
        pytest.skip("set PICO_OPENPGP_VAULT_LIVE=1 for live vault APDU tests")
    return request.getfixturevalue("card")


def _live_admin_card(request):
    card = _live_card(request)
    password = os.environ.get("PICO_OPENPGP_VAULT_PW3")
    if not password:
        pytest.skip("set PICO_OPENPGP_VAULT_PW3 for authenticated live vault tests")
    _select(card, OPENPGP_AID)
    try:
        card.verify(3, password.encode())
    except Exception as error:
        pytest.skip(f"live PW3 unavailable: {error}")
    return card


def test_vault_id_is_deterministic_and_256_bit():
    kvault = bytes(range(32))
    assert _vault_id(kvault) == _vault_id(kvault)
    assert len(_vault_id(kvault)) == VAULT_ID_BYTES
    assert _vault_id(kvault) != _vault_id(bytes(range(1, 33)))


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_pk_v1_round_trip_for_every_algorithm(algorithm):
    kvault = bytes(range(32))
    blob = _export_blob(kvault, 1, 0xB601, algorithm)
    assert blob[:4] == VAULT_MAGIC
    assert blob[ALGORITHM_OFFSET] == algorithm
    assert blob[SERIAL_LENGTH_OFFSET] == SERIAL_MAX
    assert _import_blob(kvault, blob) == (1, 0xB601, b"private-key-data", b"public-key-data")


def test_pk_v1_authenticates_header_and_ciphertext():
    blob = bytearray(_export_blob(bytes(range(32)), 1, 0xB601, 1))
    blob[SERIAL_OFFSET] ^= 1
    with pytest.raises(InvalidTag):
        _import_blob(bytes(range(32)), bytes(blob))

    blob = bytearray(_export_blob(bytes(range(32)), 1, 0xB601, 1))
    blob[-1] ^= 1
    with pytest.raises(InvalidTag):
        _import_blob(bytes(range(32)), bytes(blob))


def test_pk_v1_rejects_wrong_vault_key_and_object_identity():
    blob = _export_blob(bytes(range(32)), 1, 0xB601, 1)
    with pytest.raises(InvalidTag):
        _import_blob(bytes(range(1, 33)), blob)

    blob = _export_blob(bytes(range(32)), 1, 0xB601, 1, object_hash=_object_hash(1, 0xB602))
    with pytest.raises(ValueError, match="object hash mismatch"):
        _import_blob(bytes(range(32)), blob)


@pytest.mark.parametrize("label", ["", "A" * 64])
def test_enrollment_packet_accepts_label_boundaries(label):
    private_key = x448.X448PrivateKey.generate()
    device_private = x448.X448PrivateKey.generate()
    packet = _enrollment_packet(private_key, device_private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw), bytes(range(32)), bytes(range(32)), label)
    certificate_length = int.from_bytes(packet[:2], "big")
    assert packet[2 + certificate_length + 12:]


def test_enrollment_packet_rejects_oversized_label():
    with pytest.raises(ValueError):
        _enrollment_packet(x448.X448PrivateKey.generate(), bytes(56), bytes(32), bytes(32), "A" * 65)


def test_enrollment_packet_tampering_fails_authentication():
    private_key = x448.X448PrivateKey.generate()
    device_private = x448.X448PrivateKey.generate()
    challenge = bytes(range(32))
    kvault = bytes(range(32))
    device_public = device_private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    packet = bytearray(_enrollment_packet(private_key, device_public, challenge, kvault, "label"))
    packet[-1] ^= 1
    certificate_length = int.from_bytes(packet[:2], "big")
    certificate_public = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    info = VAULT_ENROLL_INFO + challenge + certificate_public + device_public
    shared = private_key.exchange(x448.X448PublicKey.from_public_bytes(device_public))
    session_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared)
    with pytest.raises(InvalidTag):
        AESGCM(session_key).decrypt(bytes(packet[2 + certificate_length:2 + certificate_length + NONCE_BYTES]), bytes(packet[2 + certificate_length + NONCE_BYTES:]), info)


@pytest.mark.parametrize("blob", [b"", b"PKV", b"PKV2" + b"\0" * HEADER_LENGTH, VAULT_MAGIC + b"\0" * (HEADER_LENGTH - 1)])
def test_pk_v1_rejects_malformed_blob(blob):
    with pytest.raises(ValueError):
        _import_blob(bytes(32), blob)


def test_pk_v1_serial_length_is_bounded():
    with pytest.raises(ValueError):
        _export_blob(bytes(32), 1, 0xB601, 1, b"A" * (SERIAL_MAX + 1))


def test_pk_v1_algorithm_is_bounded():
    with pytest.raises(ValueError):
        _export_blob(bytes(32), 1, 0xB601, 0)


def test_live_openpgp_vault_status_contract(request):
    card = _live_card(request)
    _select(card, OPENPGP_AID)
    status = _expect(card, INS_VAULT, VAULT_STATUS, 0)
    assert len(status) >= 37
    assert status[0] == 1
    assert status[1] in (0, 1)
    assert status[2] in (0, 1)
    assert status[3] in (0, VAULT_ID_BYTES)
    assert status[36] <= 64
    assert len(status) == 37 + status[36]


def test_live_vault_commands_require_openpgp_admin_pin(request):
    card = _live_card(request)
    _select(card, OPENPGP_AID)
    card.deauthenticate(3)
    _expect(card, INS_VAULT, VAULT_START_ENROLLMENT, 0, status=b"\x69\x82")
    _expect(card, INS_VAULT, VAULT_EXPORT, 1, status=b"\x69\x82")
    _expect(card, INS_VAULT, VAULT_UNENROLL, 0, status=b"\x69\x82")


def test_live_vault_dispatch_and_parameter_validation(request):
    card = _live_card(request)
    _select(card, OPENPGP_AID)
    _expect(card, INS_VAULT, 0x07, 0, status=b"\x6A\x86")
    _expect(card, INS_VAULT, VAULT_STATUS, 1, status=b"\x6A\x86")
    _expect(card, INS_VAULT, VAULT_EXPORT, 0, status=b"\x6A\x86")
    _expect(card, INS_VAULT, VAULT_IMPORT, 1, status=b"\x6A\x86")


def test_live_enrollment_begin_and_malformed_finish(request):
    card = _live_admin_card(request)
    response, status = _raw(card, INS_VAULT, VAULT_START_ENROLLMENT, 0)
    if status != b"\x90\x00":
        pytest.skip(f"enrollment start unavailable: {status.hex()}")
    assert len(response) == 56 + VAULT_ENROLL_CHALLENGE_BYTES
    _, status = _raw(card, INS_VAULT, VAULT_FINISH_ENROLLMENT, 0, b"\0")
    assert status != b"\x90\x00"


def test_live_unknown_vault_subcommand_is_rejected(request):
    card = _live_card(request)
    _select(card, OPENPGP_AID)
    _expect(card, INS_VAULT, 0x07, 0, status=b"\x6A\x86")


def test_live_export_import_roundtrip(request):
    if os.environ.get("PICO_OPENPGP_VAULT_ROUNDTRIP") != "1":
        pytest.skip("set PICO_OPENPGP_VAULT_ROUNDTRIP=1 for the live key round-trip")
    card = _live_admin_card(request)
    status = _expect(card, INS_VAULT, VAULT_STATUS, 0)
    if status[3] != VAULT_ID_BYTES:
        pytest.skip("OpenPGP vault is not enrolled")
    blobs = []
    for algorithm in ALGORITHMS:
        blob, result = _raw(card, INS_VAULT, VAULT_EXPORT, 1, bytes([algorithm]))
        if result != b"\x90\x00":
            pytest.skip(f"OpenPGP key handle 1 is not exportable: {result.hex()}")
        assert blob[ALGORITHM_OFFSET] == algorithm
        blobs.append(blob)
    for blob in blobs:
        _, result = _raw(card, INS_VAULT, VAULT_IMPORT, 1, blob)
        assert result == b"\x90\x00"


def test_live_unenroll_requires_explicit_opt_in(request):
    if os.environ.get("PICO_OPENPGP_VAULT_DESTRUCTIVE_TESTS") != "1":
        pytest.skip("set PICO_OPENPGP_VAULT_DESTRUCTIVE_TESTS=1 to erase the device vault")
    card = _live_admin_card(request)
    _, status = _raw(card, INS_VAULT, VAULT_UNENROLL, 0)
    assert status == b"\x90\x00"
    response = _expect(card, INS_VAULT, VAULT_STATUS, 0)
    assert response[3] == 0


def test_live_piv_vault_dispatch(request):
    card = _live_card(request)
    _, status = _raw(card, 0xA4, 0x04, 0, PIV_AID)
    if status != b"\x90\x00":
        pytest.skip("connected card does not expose the PIV application")
    response = _expect(card, INS_VAULT, VAULT_STATUS, 0)
    assert len(response) >= 37
