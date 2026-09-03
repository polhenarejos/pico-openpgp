import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec

from piv_helpers import DEFAULT_MANAGEMENT_KEY, DEFAULT_PIN, assert_apdu_error, delete_key
from yubikit.core import Tlv
from yubikit.core.smartcard import ApduError, SW
from yubikit.piv import KEY_TYPE, OBJECT_ID, PIN_POLICY, SLOT, TOUCH_POLICY


def set_management_key(piv, key, touch):
    body = bytes((0x0A, 0x9B, len(key))) + key
    piv.protocol.send_apdu(0, 0xFF, 0xFF, touch, body)


def test_piv_pin_and_puk_metadata_include_algorithm(piv):
    for reference in (0x80, 0x81):
        metadata = Tlv.parse_dict(piv.protocol.send_apdu(0, 0xF7, 0, reference))
        assert metadata[0x01] == b"\xFF"


def test_piv_management_default_flag_includes_touch_policy(managed_piv):
    original = managed_piv.get_management_key_metadata().touch_policy
    restore_touch = 0xFF if original == TOUCH_POLICY.NEVER else 0xFE
    try:
        set_management_key(managed_piv, DEFAULT_MANAGEMENT_KEY, 0xFF)
        metadata = Tlv.parse_dict(managed_piv.protocol.send_apdu(0, 0xF7, 0, 0x9B))
        assert metadata[0x02] == b"\x00\x01"
        assert metadata[0x05] == b"\x01"

        set_management_key(managed_piv, DEFAULT_MANAGEMENT_KEY, 0xFE)
        metadata = Tlv.parse_dict(managed_piv.protocol.send_apdu(0, 0xF7, 0, 0x9B))
        assert metadata[0x02] == b"\x00\x02"
        assert metadata[0x05] == b"\x00"
    finally:
        set_management_key(managed_piv, DEFAULT_MANAGEMENT_KEY, restore_touch)


def test_piv_retired_key_can_move_to_active_slot(managed_piv):
    source = SLOT.RETIRED1
    target = SLOT.AUTHENTICATION
    delete_key(managed_piv, target)
    try:
        managed_piv.generate_key(source, KEY_TYPE.ECCP256, PIN_POLICY.ONCE, TOUCH_POLICY.NEVER)
        managed_piv.move_key(source, target)
        assert managed_piv.get_slot_metadata(target).key_type == KEY_TYPE.ECCP256
        assert_apdu_error(lambda: managed_piv.get_slot_metadata(source), SW.REFERENCE_DATA_NOT_FOUND)
    finally:
        delete_key(managed_piv, source)
        delete_key(managed_piv, target)


def test_piv_attestation_slot_reports_metadata(piv):
    metadata = piv.get_slot_metadata(SLOT.ATTESTATION)
    assert metadata.key_type == KEY_TYPE.ECCP384
    assert metadata.pin_policy == PIN_POLICY.ONCE
    assert metadata.touch_policy == TOUCH_POLICY.NEVER
    assert metadata.generated
    assert metadata.public_key is not None


def test_piv_object_ids_require_the_complete_identifier(managed_piv):
    assert managed_piv.get_object(0x5FFF01)
    for object_id in (0xFF01, 0x00FF01, 0x7FFF01, 0xABFF01, 0xFF00, 0xABFF00):
        assert_apdu_error(lambda object_id=object_id: managed_piv.get_object(object_id), SW.FILE_NOT_FOUND)


@pytest.mark.parametrize("instruction", (0xFD, 0xF8, 0xF7, 0x20, 0x87, 0x47, 0xDB, 0xF6))
def test_piv_rejects_one_byte_bodies_before_dispatch(piv, instruction):
    with pytest.raises(ApduError) as raised:
        piv.protocol.send_apdu(0, instruction, 0, 0, b"\x00")
    assert raised.value.sw == SW.INCORRECT_PARAMETERS


def test_piv_rejects_secure_messaging_without_an_active_session(piv):
    assert_apdu_error(lambda: piv.protocol.send_apdu(0x0C, 0xFD, 0, 0), SW.CLASS_NOT_SUPPORTED)


def test_piv_application_template_does_not_advertise_unimplemented_secure_messaging(piv):
    response = piv.protocol.send_apdu(0, 0xA4, 0x04, 0, b"\xA0\x00\x00\x03\x08")
    template = Tlv.parse_dict(Tlv.unpack(0x61, response))[0xAC]

    assert Tlv.parse_dict(template)[0x80] == b"\x05\x07\x08\x0A\x0C\x11\x14"


@pytest.mark.parametrize(
    ("instruction", "p1", "p2", "data", "status"),
    (
        (0x20, 0x01, 0x80, b"", SW.INCORRECT_PARAMETERS),
        (0x20, 0x00, 0x81, b"", SW.INCORRECT_PARAMETERS),
        (0x20, 0xFF, 0x80, b"\x00\x00", SW.INCORRECT_PARAMETERS),
        (0x24, 0x00, 0x82, b"", SW.REFERENCE_DATA_NOT_FOUND),
        (0x24, 0x01, 0x80, b"", SW.REFERENCE_DATA_NOT_FOUND),
        (0x2C, 0x00, 0x82, b"", SW.REFERENCE_DATA_NOT_FOUND),
        (0x2C, 0x01, 0x80, b"", SW.REFERENCE_DATA_NOT_FOUND),
    ),
)
def test_piv_invalid_reference_and_framing_statuses(piv, instruction, p1, p2, data, status):
    assert_apdu_error(lambda: piv.protocol.send_apdu(0, instruction, p1, p2, data), status)


def test_piv_general_authenticate_uses_the_first_operation_tag(managed_piv):
    slot = SLOT.AUTHENTICATION
    digest = b"\x01" * 32
    try:
        managed_piv.generate_key(slot, KEY_TYPE.ECCP256, PIN_POLICY.ONCE, TOUCH_POLICY.NEVER)
        managed_piv.verify_pin(DEFAULT_PIN)
        first_ecdh = Tlv(0x7C, Tlv(0x85, b"") + Tlv(0x81, digest))
        assert_apdu_error(lambda: managed_piv.protocol.send_apdu(0, 0x87, KEY_TYPE.ECCP256, slot, first_ecdh), SW.INCORRECT_PARAMETERS)

        first_signature = Tlv(0x7C, Tlv(0x81, digest) + Tlv(0x85, b""))
        response = managed_piv.protocol.send_apdu(0, 0x87, KEY_TYPE.ECCP256, slot, first_signature)
        assert Tlv.unpack(0x82, Tlv.unpack(0x7C, response))
    finally:
        delete_key(managed_piv, slot)


def test_piv_9d_ecc_rejects_ecdsa_operation(managed_piv):
    slot = SLOT.KEY_MANAGEMENT
    try:
        managed_piv.generate_key(slot, KEY_TYPE.ECCP256, PIN_POLICY.ONCE, TOUCH_POLICY.NEVER)
        managed_piv.verify_pin(DEFAULT_PIN)
        request = Tlv(0x7C, Tlv(0x81, b"\x01" * 32))

        assert_apdu_error(lambda: managed_piv.protocol.send_apdu(0, 0x87, KEY_TYPE.ECCP256, slot, request), SW.INCORRECT_PARAMETERS)
    finally:
        delete_key(managed_piv, slot)


def test_piv_generates_rsa3072(managed_piv):
    slot = SLOT.RETIRED2
    delete_key(managed_piv, slot)
    try:
        request = Tlv(0xAC, Tlv(0x80, b"\x05"))
        response = managed_piv.protocol.send_apdu(0, 0x47, 0, slot, request)
        assert response

        metadata = Tlv.parse_dict(managed_piv.protocol.send_apdu(0, 0xF7, 0, slot))
        assert metadata[0x01] == b"\x05"
        certificate_object = Tlv.parse_dict(managed_piv.get_object(OBJECT_ID.from_slot(slot)))
        assert certificate_object[0x70].startswith(b"\x30")
        assert certificate_object[0x71] == b"\x00"
        assert managed_piv.get_certificate(slot).public_key().key_size == 3072
    finally:
        delete_key(managed_piv, slot)


@pytest.mark.parametrize("slot", (SLOT.SIGNATURE, SLOT.KEY_MANAGEMENT, SLOT.RETIRED2))
def test_piv_rejects_malformed_certificate_objects_for_all_certificate_slots(managed_piv, slot):
    malformed_certificate = Tlv(0x70, b"\x01")

    assert_apdu_error(lambda: managed_piv.put_object(OBJECT_ID.from_slot(slot), malformed_certificate), SW.WRONG_LENGTH)


@pytest.mark.parametrize(
    ("key_type", "curve"),
    ((KEY_TYPE.ECCP256, ec.SECP256R1()), (KEY_TYPE.ECCP384, ec.SECP384R1())),
)
def test_piv_9d_ecdh_returns_the_shared_secret(managed_piv, key_type, curve):
    slot = SLOT.KEY_MANAGEMENT
    peer_private_key = ec.generate_private_key(curve)
    try:
        card_public_key = managed_piv.generate_key(slot, key_type, PIN_POLICY.ONCE, TOUCH_POLICY.NEVER)
        managed_piv.verify_pin(DEFAULT_PIN)
        peer_public_key = peer_private_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        request = Tlv(0x7C, Tlv(0x82, b"") + Tlv(0x85, peer_public_key))
        response = managed_piv.protocol.send_apdu(0, 0x87, key_type, slot, request)

        shared_secret = Tlv.unpack(0x82, Tlv.unpack(0x7C, response))
        assert shared_secret == peer_private_key.exchange(ec.ECDH(), card_public_key)
    finally:
        delete_key(managed_piv, slot)


@pytest.mark.parametrize(
    ("key_type", "curve"),
    ((KEY_TYPE.ECCP256, ec.SECP256R1()), (KEY_TYPE.ECCP384, ec.SECP384R1())),
)
def test_piv_retired_key_management_ecdh_returns_the_shared_secret(managed_piv, key_type, curve):
    slot = SLOT.RETIRED1
    peer_private_key = ec.generate_private_key(curve)
    try:
        card_public_key = managed_piv.generate_key(slot, key_type, PIN_POLICY.ONCE, TOUCH_POLICY.NEVER)
        managed_piv.verify_pin(DEFAULT_PIN)
        peer_public_key = peer_private_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        request = Tlv(0x7C, Tlv(0x82, b"") + Tlv(0x85, peer_public_key))
        response = managed_piv.protocol.send_apdu(0, 0x87, key_type, slot, request)

        shared_secret = Tlv.unpack(0x82, Tlv.unpack(0x7C, response))
        assert shared_secret == peer_private_key.exchange(ec.ECDH(), card_public_key)
    finally:
        delete_key(managed_piv, slot)


def test_piv_rsa_general_authenticate_accepts_another_rsa_algorithm_id(managed_piv):
    slot = SLOT.AUTHENTICATION
    try:
        managed_piv.generate_key(slot, KEY_TYPE.RSA1024, PIN_POLICY.ONCE, TOUCH_POLICY.NEVER)
        managed_piv.verify_pin(DEFAULT_PIN)
        body = Tlv(0x7C, Tlv(0x81, b"\x00" * 127 + b"\x01"))
        response = managed_piv.protocol.send_apdu(0, 0x87, KEY_TYPE.RSA2048, slot, body)
        assert response
    finally:
        delete_key(managed_piv, slot)


def test_piv_ec_import_requires_the_field_length(managed_piv):
    slot = SLOT.RETIRED1
    try:
        for key_type in (KEY_TYPE.ECCP256, KEY_TYPE.ECCP384):
            body = Tlv(0x06, b"\x01")
            assert_apdu_error(lambda: managed_piv.protocol.send_apdu(0, 0xFE, key_type, slot, body), SW.DATA_INVALID)
    finally:
        delete_key(managed_piv, slot)


def test_piv_rejects_x25519_generation_without_creating_slot_state(managed_piv):
    slot = SLOT.RETIRED1
    delete_key(managed_piv, slot)
    request = Tlv(0xAC, Tlv(0x80, b"\xE1"))

    assert_apdu_error(lambda: managed_piv.protocol.send_apdu(0, 0x47, 0, slot, request), SW.DATA_INVALID)
    assert_apdu_error(lambda: managed_piv.get_slot_metadata(slot), SW.REFERENCE_DATA_NOT_FOUND)
    assert_apdu_error(lambda: managed_piv.get_certificate(slot), 0x6A82)


def test_piv_rejects_rsa_generation_with_nonstandard_exponent(managed_piv):
    slot = SLOT.RETIRED2
    delete_key(managed_piv, slot)
    try:
        request = Tlv(0xAC, Tlv(0x80, b"\x07") + Tlv(0x81, b"\x03"))

        assert_apdu_error(lambda: managed_piv.protocol.send_apdu(0, 0x47, 0, slot, request), SW.DATA_INVALID)
        assert_apdu_error(lambda: managed_piv.get_slot_metadata(slot), SW.REFERENCE_DATA_NOT_FOUND)
        assert_apdu_error(lambda: managed_piv.get_certificate(slot), 0x6A82)
    finally:
        delete_key(managed_piv, slot)


@pytest.mark.parametrize("pin_retries, puk_retries", ((11, 1), (1, 11), (11, 11)))
def test_piv_set_retries_rejects_values_above_standard_limit(managed_piv, pin_retries, puk_retries):
    managed_piv.verify_pin(DEFAULT_PIN)
    pin_before = managed_piv.get_pin_metadata()
    puk_before = managed_piv.get_puk_metadata()

    assert_apdu_error(lambda: managed_piv.protocol.send_apdu(0, 0xFA, pin_retries, puk_retries, b""), SW.INCORRECT_PARAMETERS)

    pin_after = managed_piv.get_pin_metadata()
    puk_after = managed_piv.get_puk_metadata()
    assert pin_after.total_attempts == pin_before.total_attempts
    assert pin_after.attempts_remaining == pin_before.attempts_remaining
    assert puk_after.total_attempts == puk_before.total_attempts
    assert puk_after.attempts_remaining == puk_before.attempts_remaining


def test_piv_reset_retry_reports_blocked_puk_without_resetting_pin(managed_piv):
    managed_piv.verify_pin(DEFAULT_PIN)
    managed_piv.protocol.send_apdu(0, 0xFA, 1, 1, b"")
    try:
        pin_before = managed_piv.get_pin_metadata()
        request = b"00000000" + DEFAULT_PIN.encode() + b"\xFF\xFF"
        assert_apdu_error(lambda: managed_piv.protocol.send_apdu(0, 0x2C, 0, 0x80, request), SW.AUTH_METHOD_BLOCKED)
        assert managed_piv.get_puk_metadata().attempts_remaining == 0

        request = b"12345678" + b"654321" + b"\xFF\xFF"
        assert_apdu_error(lambda: managed_piv.protocol.send_apdu(0, 0x2C, 0, 0x80, request), SW.AUTH_METHOD_BLOCKED)
        pin_after = managed_piv.get_pin_metadata()
        assert pin_after.total_attempts == pin_before.total_attempts
        assert pin_after.attempts_remaining == pin_before.attempts_remaining
    finally:
        managed_piv.protocol.send_apdu(0, 0xFA, 3, 3, b"")


@pytest.mark.parametrize(("instruction", "p2"), ((0x24, 0x80), (0x24, 0x81), (0x2C, 0x80)))
def test_piv_reference_changes_require_two_wire_blocks(piv, instruction, p2):
    assert_apdu_error(lambda: piv.protocol.send_apdu(0, instruction, 0, p2, b"12345678"), SW.INCORRECT_PARAMETERS)


@pytest.mark.parametrize("body", (b"123456", b"123456789"))
def test_piv_verify_requires_the_wire_length_without_burning_a_retry(piv, body):
    piv.verify_pin(DEFAULT_PIN)
    assert_apdu_error(lambda: piv.protocol.send_apdu(0, 0x20, 0, 0x80, body), SW.INCORRECT_PARAMETERS)
    assert_apdu_error(lambda: piv.protocol.send_apdu(0, 0x20, 0, 0x80, b""), 0x63C3)


def test_piv_card_authentication_key_is_pin_free_by_default(managed_piv):
    slot = SLOT.CARD_AUTH
    try:
        managed_piv.generate_key(slot, KEY_TYPE.ECCP256, PIN_POLICY.DEFAULT, TOUCH_POLICY.NEVER)
        request = Tlv(0x7C, Tlv(0x81, b"\x01" * 32))
        response = managed_piv.protocol.send_apdu(0, 0x87, KEY_TYPE.ECCP256, slot, request)
        assert response
    finally:
        delete_key(managed_piv, slot)


def test_piv_generated_key_uses_no_touch_by_default(managed_piv):
    slot = SLOT.AUTHENTICATION
    try:
        managed_piv.generate_key(slot, KEY_TYPE.ECCP256, PIN_POLICY.ONCE, TOUCH_POLICY.DEFAULT)
        assert managed_piv.get_slot_metadata(slot).touch_policy == TOUCH_POLICY.NEVER
    finally:
        delete_key(managed_piv, slot)


@pytest.mark.parametrize("policy", (Tlv(0xAA, b"\x00"), Tlv(0xAB, b"\x00"), Tlv(0xAA, b"\xFF")))
def test_piv_explicit_zero_or_undefined_policy_is_rejected(managed_piv, policy):
    slot = SLOT.RETIRED1
    delete_key(managed_piv, slot)
    try:
        request = Tlv(0xAC, Tlv(0x80, bytes([KEY_TYPE.ECCP256])) + policy)
        assert_apdu_error(lambda: managed_piv.protocol.send_apdu(0, 0x47, 0, slot, request), SW.INCORRECT_PARAMETERS)
        assert_apdu_error(lambda: managed_piv.get_slot_metadata(slot), SW.REFERENCE_DATA_NOT_FOUND)
    finally:
        delete_key(managed_piv, slot)
