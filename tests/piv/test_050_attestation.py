from itertools import product

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography import x509

from piv_helpers import delete_key
from yubikit.core import Tlv
from yubikit.piv import KEY_TYPE, PIN_POLICY, SLOT, TOUCH_POLICY

from test_030_keys import SUPPORTED_KEY_TYPES, TEST_SLOTS


@pytest.mark.parametrize(("key_type", "slot"), tuple(product(SUPPORTED_KEY_TYPES, TEST_SLOTS)))
def test_attestation_chain_for_all_script_cases(managed_piv, key_type, slot):
    try:
        public_key = managed_piv.generate_key(slot, key_type, PIN_POLICY.ONCE, TOUCH_POLICY.NEVER)
        # Pico stores F9 as raw DER, not as a standard certificate object.
        response = managed_piv.protocol.send_apdu(0, 0xCB, 0x3F, 0xFF, Tlv(0x5C, b"\x5f\xff\x01"))
        issuer = x509.load_der_x509_certificate(Tlv.unpack(0x53, response))
        attested = managed_piv.attest_key(slot)
        assert attested.issuer == issuer.subject
        assert attested.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo) == public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        issuer.public_key().verify(attested.signature, attested.tbs_certificate_bytes, ec.ECDSA(attested.signature_hash_algorithm))
    finally:
        delete_key(managed_piv, slot)
