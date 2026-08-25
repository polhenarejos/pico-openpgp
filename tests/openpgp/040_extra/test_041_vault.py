import base64
import ctypes
import ctypes.util
import hashlib
import json
import os
import struct
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x448
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


VAULT_MAGIC = b"PKV\x01"
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
DEFAULT_ENROLLMENT = Path.home() / ".config" / "PicoKeys" / "vault" / "enrollment-35d3ddbcebc9-Test.json"

OPENPGP_VAULT_FINGERPRINT_TAGS = {
    1: 0xC7,
    2: 0xC8,
    3: 0xC9,
    # OpenPGP does not define a fingerprint DO for the symmetric AES key.
    4: 0xC5,
}


def _vault_id(kvault):
    return hashlib.sha256(VAULT_ID_DOMAIN + kvault).digest()


def _derive_passphrase(passphrase, salt):
    try:
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
        return Argon2id(salt=salt, length=32, iterations=3, lanes=4, memory_cost=64 * 1024).derive(passphrase.encode())
    except ImportError:
        library_name = ctypes.util.find_library("argon2")
        if not library_name:
            raise RuntimeError("Argon2id support is unavailable")
        library = ctypes.CDLL(library_name)
        hash_function = library.argon2id_hash_raw
        hash_function.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t]
        hash_function.restype = ctypes.c_int
        output = ctypes.create_string_buffer(32)
        password_bytes = passphrase.encode()
        result = hash_function(3, 64 * 1024, 4, password_bytes, len(password_bytes), salt, len(salt), output, 32)
        if result != 0:
            raise RuntimeError(f"Argon2id failed: {result}")
        return output.raw


def _create_enrollment(passphrase, kvault, private_key, label, certificate=b""):
    salt = bytes(range(16))
    nonce = bytes(range(12))
    private_bytes = private_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    plain = json.dumps({
        "version": 1,
        "kvault": base64.b64encode(kvault).decode(),
        "x448_private": base64.b64encode(private_bytes).decode(),
        "certificate": base64.b64encode(certificate).decode(),
        "label": label,
        "vault_id": _vault_id(kvault).hex()
    }, separators=(",", ":")).encode()
    ciphertext = AESGCM(_derive_passphrase(passphrase, salt)).encrypt(nonce, plain, b"PicoKeys Kvault envelope v1")
    return {
        "version": 1,
        "label": label,
        "vault_id": _vault_id(kvault).hex(),
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }


def _open_enrollment(value, passphrase):
    salt = base64.b64decode(value["salt"])
    nonce = base64.b64decode(value["nonce"])
    ciphertext = base64.b64decode(value["ciphertext"])
    plain = AESGCM(_derive_passphrase(passphrase, salt)).decrypt(nonce, ciphertext, b"PicoKeys Kvault envelope v1")
    return json.loads(plain)


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


def _certificate_enrollment_packet(certificate, private_key, device_public, challenge, kvault, label):
    certificate_public = x509.load_der_x509_certificate(certificate).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    info = VAULT_ENROLL_INFO + challenge + certificate_public + device_public
    shared = private_key.exchange(x448.X448PublicKey.from_public_bytes(device_public))
    session_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared)
    label_bytes = label.encode()
    if len(label_bytes) > 64:
        raise ValueError("vault label is too long")
    plain = kvault + bytes([len(label_bytes)]) + label_bytes
    nonce = os.urandom(NONCE_BYTES)
    encrypted = AESGCM(session_key).encrypt(nonce, plain, info)
    return struct.pack(">H", len(certificate)) + certificate + nonce + encrypted


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
    return request.getfixturevalue("card")


def _live_admin_card(request):
    card = _live_card(request)
    password = os.environ.get("PICO_OPENPGP_VAULT_PW3", "12345678")
    _select(card, OPENPGP_AID)
    assert card.verify(3, password.encode())
    return card


def _live_enrollment(card):
    enrollment_json = os.environ.get("PICO_OPENPGP_VAULT_ENROLLMENT_JSON")
    if enrollment_json:
        try:
            value = json.loads(enrollment_json)
        except json.JSONDecodeError as error:
            pytest.fail(f"invalid PICO_OPENPGP_VAULT_ENROLLMENT_JSON: {error}")
    else:
        path = Path(os.environ.get("PICO_OPENPGP_VAULT_ENROLLMENT", str(DEFAULT_ENROLLMENT)))
        if not path.is_file():
            pytest.fail(f"enrollment JSON does not exist: {path}")
        value = json.loads(path.read_text(encoding="utf-8"))
    passphrase = os.environ.get("PICO_OPENPGP_VAULT_PASSPHRASE") or "test"
    plain = _open_enrollment(value, passphrase)
    kvault = base64.b64decode(plain["kvault"])
    private_key = x448.X448PrivateKey.from_private_bytes(base64.b64decode(plain["x448_private"]))
    certificate = base64.b64decode(plain["certificate"])
    certificate_object = x509.load_der_x509_certificate(certificate)
    certificate_public = certificate_object.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    private_public = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert certificate_public == private_public
    assert _vault_id(kvault).hex() == plain["vault_id"]

    _select(card, OPENPGP_AID)
    password = os.environ.get("PICO_OPENPGP_VAULT_PW3", "12345678")
    assert card.verify(3, password.encode())
    response, result = _raw(card, INS_VAULT, VAULT_START_ENROLLMENT, 0)
    assert result == b"\x90\x00"
    assert len(response) == 56 + VAULT_ENROLL_CHALLENGE_BYTES
    packet = _certificate_enrollment_packet(certificate, private_key, response[:56], response[56:], kvault, plain.get("label", ""))
    vault_id, result = _raw(card, INS_VAULT, VAULT_FINISH_ENROLLMENT, 0, packet)
    assert result == b"\x90\x00"
    assert len(vault_id) == VAULT_ID_BYTES
    assert vault_id == _vault_id(kvault)
    return password


def test_vault_id_is_deterministic_and_256_bit():
    kvault = bytes(range(32))
    assert _vault_id(kvault) == _vault_id(kvault)
    assert len(_vault_id(kvault)) == VAULT_ID_BYTES
    assert _vault_id(kvault) != _vault_id(bytes(range(1, 33)))


def test_create_and_open_enrollment_json():
    value = _create_enrollment("correct horse", bytes(range(32)), x448.X448PrivateKey.generate(), "test vault")
    plain = _open_enrollment(value, "correct horse")
    assert plain["vault_id"] == value["vault_id"]
    assert plain["label"] == "test vault"
    assert len(base64.b64decode(plain["kvault"])) == 32


def test_wrong_enrollment_passphrase_is_rejected():
    value = _create_enrollment("correct horse", os.urandom(32), x448.X448PrivateKey.generate(), "")
    with pytest.raises(InvalidTag):
        _open_enrollment(value, "wrong horse")


def test_tampered_enrollment_json_is_rejected():
    value = _create_enrollment("secret", os.urandom(32), x448.X448PrivateKey.generate(), "")
    ciphertext = bytearray(base64.b64decode(value["ciphertext"]))
    ciphertext[0] ^= 1
    value["ciphertext"] = base64.b64encode(ciphertext).decode()
    with pytest.raises(InvalidTag):
        _open_enrollment(value, "secret")


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
    assert status == b"\x90\x00"
    assert len(response) == 56 + VAULT_ENROLL_CHALLENGE_BYTES
    _, status = _raw(card, INS_VAULT, VAULT_FINISH_ENROLLMENT, 0, b"\0")
    assert status != b"\x90\x00"


def test_live_unknown_vault_subcommand_is_rejected(request):
    card = _live_card(request)
    _select(card, OPENPGP_AID)
    _expect(card, INS_VAULT, 0x07, 0, status=b"\x6A\x86")


@pytest.mark.parametrize("algorithm", ALGORITHMS)
def test_live_export_import_roundtrip(request, algorithm):
    card = _live_card(request)
    _live_enrollment(card)

    blob, result = _raw(card, INS_VAULT, VAULT_EXPORT, 1, bytes([algorithm]))
    assert result == b"\x90\x00"
    assert blob[ALGORITHM_OFFSET] == algorithm
    _, result = _raw(card, INS_VAULT, VAULT_IMPORT, 1, blob)
    assert result == b"\x90\x00"


@pytest.mark.parametrize("handle,fingerprint_tag", OPENPGP_VAULT_FINGERPRINT_TAGS.items())
def test_live_export_import_roundtrip_for_every_openpgp_key(request, handle, fingerprint_tag):
    card = _live_card(request)
    _live_enrollment(card)
    fingerprint, result = _raw(card, 0xCA, 0, fingerprint_tag)
    assert result == b"\x90\x00"
    blob, result = _raw(card, INS_VAULT, VAULT_EXPORT, handle)
    assert result == b"\x90\x00"
    assert blob[:4] == VAULT_MAGIC
    _, result = _raw(card, INS_VAULT, VAULT_IMPORT, handle, blob)
    assert result == b"\x90\x00"
    restored_fingerprint, result = _raw(card, 0xCA, 0, fingerprint_tag)
    assert result == b"\x90\x00"
    assert restored_fingerprint == fingerprint


def test_live_unenroll(request):
    card = _live_admin_card(request)
    _, status = _raw(card, INS_VAULT, VAULT_UNENROLL, 0)
    assert status == b"\x90\x00"
    response = _expect(card, INS_VAULT, VAULT_STATUS, 0)
    assert response[3] == 0
    _live_enrollment(card)


def test_live_piv_vault_dispatch(request):
    card = _live_card(request)
    _, status = _raw(card, 0xA4, 0x04, 0, PIV_AID)
    assert status == b"\x90\x00"
    response = _expect(card, INS_VAULT, VAULT_STATUS, 0)
    assert len(response) >= 37
    _select(card, OPENPGP_AID)
