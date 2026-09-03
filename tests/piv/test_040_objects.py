from datetime import datetime, timedelta, timezone
from itertools import product

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

from piv_helpers import DEFAULT_MANAGEMENT_KEY, DEFAULT_PIN, assert_apdu_error, delete_key
from yubikit.core import Tlv
from yubikit.core.smartcard import ApduError, SW
from yubikit.piv import KEY_TYPE, OBJECT_ID, PIN_POLICY, SLOT, TOUCH_POLICY
from ykman.piv import generate_csr, generate_self_signed_certificate

from test_030_keys import SUPPORTED_KEY_TYPES, TEST_SLOTS


def test_certificate_round_trip(managed_piv):
    slot = SLOT.RETIRED1
    ca_key = ec.generate_private_key(ec.SECP256R1())
    try:
        public_key = managed_piv.generate_key(slot, KEY_TYPE.ECCP256, PIN_POLICY.ONCE, TOUCH_POLICY.NEVER)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Pico PIV test")])
        certificate = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(public_key).serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1)).not_valid_after(datetime.now(timezone.utc) + timedelta(days=1)).sign(ca_key, hashes.SHA256())
        managed_piv.put_certificate(slot, certificate)
        assert managed_piv.get_certificate(slot).public_bytes(serialization.Encoding.DER) == certificate.public_bytes(serialization.Encoding.DER)
        managed_piv.delete_certificate(slot)
        assert_apdu_error(lambda: managed_piv.get_certificate(slot), 0x6A82)
    finally:
        delete_key(managed_piv, slot)


@pytest.mark.parametrize(("key_type", "slot"), tuple(product(SUPPORTED_KEY_TYPES, TEST_SLOTS)))
def test_signature_and_certificate_round_trip_for_all_script_cases(managed_piv, key_type, slot):
    message = b"Pico PIV shell compatibility test"
    ca_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Pico PIV shell compatibility")])
    ca_certificate = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1)).not_valid_after(datetime.now(timezone.utc) + timedelta(days=1)).sign(ca_key, hashes.SHA256())
    try:
        public_key = managed_piv.generate_key(slot, key_type, PIN_POLICY.ONCE, TOUCH_POLICY.NEVER)
        managed_piv.verify_pin(DEFAULT_PIN)
        signature = managed_piv.sign(slot, key_type, message, hashes.SHA256(), padding.PKCS1v15() if isinstance(public_key, rsa.RSAPublicKey) else None)
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        else:
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))

        csr = generate_csr(managed_piv, slot, public_key, "CN=Pico PIV slot")
        assert csr.is_signature_valid
        assert csr.public_key().public_numbers() == public_key.public_numbers()
        certificate = generate_self_signed_certificate(managed_piv, slot, public_key, "CN=Pico PIV slot", datetime.now(timezone.utc) - timedelta(minutes=1), datetime.now(timezone.utc) + timedelta(days=1))
        assert certificate.subject == certificate.issuer
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(certificate.signature, certificate.tbs_certificate_bytes, padding.PKCS1v15(), hashes.SHA256())
        else:
            public_key.verify(certificate.signature, certificate.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))

        certificate = x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Pico PIV slot")])).issuer_name(name).public_key(public_key).serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1)).not_valid_after(datetime.now(timezone.utc) + timedelta(days=1)).sign(ca_key, hashes.SHA256())
        managed_piv.put_certificate(slot, certificate)
        stored = managed_piv.get_certificate(slot)
        assert stored.public_bytes(serialization.Encoding.DER) == certificate.public_bytes(serialization.Encoding.DER)
        ca_key.public_key().verify(stored.signature, stored.tbs_certificate_bytes, ec.ECDSA(stored.signature_hash_algorithm))
        ca_key.public_key().verify(ca_certificate.signature, ca_certificate.tbs_certificate_bytes, ec.ECDSA(ca_certificate.signature_hash_algorithm))
        managed_piv.delete_certificate(slot)
    finally:
        delete_key(managed_piv, slot)


def test_chuid_object_round_trip(managed_piv):
    original = None
    try:
        try:
            original = managed_piv.get_object(OBJECT_ID.CHUID)
        except ApduError as error:
            if error.sw != SW.FILE_NOT_FOUND:
                raise
        value = b"\x30\x03PIV"
        managed_piv.put_object(OBJECT_ID.CHUID, value)
        assert managed_piv.get_object(OBJECT_ID.CHUID) == value
    finally:
        managed_piv.authenticate(DEFAULT_MANAGEMENT_KEY)
        managed_piv.put_object(OBJECT_ID.CHUID, original)


def test_populated_chuid_cannot_be_replaced(managed_piv):
    try:
        original = managed_piv.get_object(OBJECT_ID.CHUID)
    except ApduError as error:
        if error.sw == SW.FILE_NOT_FOUND:
            pytest.skip("requires a populated CHUID")
        raise

    replacement = original + b"\x00"
    assert_apdu_error(lambda: managed_piv.put_object(OBJECT_ID.CHUID, replacement), 0x6A81)
    assert managed_piv.get_object(OBJECT_ID.CHUID) == original


def test_piv_authentication_certificate_rejects_invalid_der(managed_piv):
    try:
        original = managed_piv.get_object(0x5FC105)
    except ApduError as error:
        if error.sw != SW.FILE_NOT_FOUND:
            raise
        original = None

    invalid_certificate = Tlv(0x70, b"\x30\x01\x00") + Tlv(0x71, b"\x00")
    assert_apdu_error(lambda: managed_piv.put_object(0x5FC105, invalid_certificate), 0x6700)
    if original is None:
        assert_apdu_error(lambda: managed_piv.get_object(0x5FC105), SW.FILE_NOT_FOUND)
    else:
        assert managed_piv.get_object(0x5FC105) == original


def test_object_write_requires_management_authentication(piv):
    request = Tlv(0x5C, b"\x5f\xc1\x02") + Tlv(0x53, b"test")
    assert_apdu_error(lambda: piv.protocol.send_apdu(0, 0xDB, 0x3F, 0xFF, request), SW.SECURITY_CONDITION_NOT_SATISFIED)
