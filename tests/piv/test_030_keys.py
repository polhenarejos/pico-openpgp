import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from itertools import product

from piv_helpers import DEFAULT_PIN, assert_apdu_error, delete_key
from yubikit.core.smartcard import SW
from yubikit.piv import KEY_TYPE, PIN_POLICY, SLOT, TOUCH_POLICY


SUPPORTED_KEY_TYPES = (KEY_TYPE.RSA1024, KEY_TYPE.ECCP256, KEY_TYPE.ECCP384)
COMMON_SLOTS = (SLOT.AUTHENTICATION, SLOT.SIGNATURE, SLOT.KEY_MANAGEMENT, SLOT.CARD_AUTH)
TEST_SLOTS = COMMON_SLOTS + tuple(SLOT(value) for value in range(0x82, 0x96))
KEY_CASES = tuple(product(SUPPORTED_KEY_TYPES, TEST_SLOTS))


@pytest.mark.parametrize(("key_type", "slot"), KEY_CASES)
def test_generate_and_delete_supported_key_types(managed_piv, key_type, slot):
    try:
        public_key = managed_piv.generate_key(slot, key_type, PIN_POLICY.ONCE, TOUCH_POLICY.NEVER)
        assert managed_piv.get_slot_metadata(slot).public_key.public_numbers() == public_key.public_numbers()
    finally:
        delete_key(managed_piv, slot)
    assert_apdu_error(lambda: managed_piv.get_slot_metadata(slot), SW.REFERENCE_DATA_NOT_FOUND)


@pytest.mark.parametrize(("key_type", "slot"), KEY_CASES)
def test_sign_and_verify_supported_key_types(managed_piv, key_type, slot):
    message = b"Pico PIV functional test"
    try:
        public_key = managed_piv.generate_key(slot, key_type, PIN_POLICY.ONCE, TOUCH_POLICY.NEVER)
        managed_piv.verify_pin(DEFAULT_PIN)
        signature = managed_piv.sign(slot, key_type, message, hashes.SHA256(), padding.PKCS1v15() if key_type.algorithm.value == "rsa" else None)
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        else:
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    finally:
        delete_key(managed_piv, slot)


@pytest.mark.parametrize("slot", COMMON_SLOTS)
def test_common_slots_can_sign(managed_piv, slot):
    key_type = KEY_TYPE.ECCP256
    message = b"Pico PIV common slot test"
    try:
        public_key = managed_piv.generate_key(slot, key_type, PIN_POLICY.ONCE, TOUCH_POLICY.NEVER)
        managed_piv.verify_pin(DEFAULT_PIN)
        signature = managed_piv.sign(slot, key_type, message, hashes.SHA256(), None)
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    finally:
        delete_key(managed_piv, slot)


def test_sign_requires_pin(managed_piv):
    slot = SLOT.RETIRED1
    try:
        managed_piv.generate_key(slot, KEY_TYPE.ECCP256, PIN_POLICY.ONCE, TOUCH_POLICY.NEVER)
        assert_apdu_error(lambda: managed_piv.sign(slot, KEY_TYPE.ECCP256, b"no PIN", hashes.SHA256(), None), SW.SECURITY_CONDITION_NOT_SATISFIED)
    finally:
        delete_key(managed_piv, slot)


def test_rsa_decipher(managed_piv):
    slot = SLOT.KEY_MANAGEMENT
    plaintext = b"Pico PIV RSA decipher"
    try:
        public_key = managed_piv.generate_key(slot, KEY_TYPE.RSA1024, PIN_POLICY.ONCE, TOUCH_POLICY.NEVER)
        oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        ciphertext = public_key.encrypt(plaintext, oaep)
        managed_piv.verify_pin(DEFAULT_PIN)
        assert managed_piv.decrypt(slot, ciphertext, oaep) == plaintext
    finally:
        delete_key(managed_piv, slot)


@pytest.mark.parametrize(
    ("key_type", "private_key"),
    [
        (KEY_TYPE.RSA1024, rsa.generate_private_key(public_exponent=65537, key_size=1024)),
        (KEY_TYPE.ECCP256, ec.generate_private_key(ec.SECP256R1())),
    ],
)
def test_import_key_and_use_it(managed_piv, key_type, private_key):
    slot = SLOT.RETIRED2
    try:
        assert managed_piv.put_key(slot, private_key, PIN_POLICY.ONCE, TOUCH_POLICY.NEVER) == key_type
        managed_piv.verify_pin(DEFAULT_PIN)
        message = b"imported PIV key"
        signature = managed_piv.sign(slot, key_type, message, hashes.SHA256(), padding.PKCS1v15() if key_type.algorithm.value == "rsa" else None)
        public_key = private_key.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        else:
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    finally:
        delete_key(managed_piv, slot)
