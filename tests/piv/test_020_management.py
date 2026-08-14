import pytest

from piv_helpers import DEFAULT_MANAGEMENT_KEY, assert_apdu_error
from yubikit.core import Tlv
from yubikit.core.smartcard import ApduError, SW
from yubikit.piv import KEY_TYPE, MANAGEMENT_KEY_TYPE, SLOT


def test_default_management_key_authenticates(piv):
    piv.authenticate(DEFAULT_MANAGEMENT_KEY)


def test_invalid_management_key_has_expected_status(piv):
    with pytest.raises(ApduError) as raised:
        piv.authenticate(b"\x00" * len(DEFAULT_MANAGEMENT_KEY))
    assert raised.value.sw == SW.DATA_INVALID


def test_management_key_change_round_trip(piv):
    new_key = b"Pico PIV temporary key".ljust(24, b"!")
    changed = False
    try:
        piv.authenticate(DEFAULT_MANAGEMENT_KEY)
        piv.set_management_key(MANAGEMENT_KEY_TYPE.AES192, new_key)
        changed = True
        piv.authenticate(new_key)
    finally:
        if changed:
            piv.set_management_key(MANAGEMENT_KEY_TYPE.AES192, DEFAULT_MANAGEMENT_KEY)


def test_key_generation_requires_management_authentication(piv):
    request = Tlv(0xAC, Tlv(0x80, bytes([KEY_TYPE.ECCP256])))
    assert_apdu_error(lambda: piv.protocol.send_apdu(0, 0x47, 0, SLOT.RETIRED1, request), SW.SECURITY_CONDITION_NOT_SATISFIED)
