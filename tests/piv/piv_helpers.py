import pytest

from yubikit.core.smartcard import ApduError, SW
from yubikit.piv import DEFAULT_MANAGEMENT_KEY


DEFAULT_PIN = "123456"
DEFAULT_PUK = "12345678"


def assert_apdu_error(call, status):
    with pytest.raises(ApduError) as raised:
        call()
    assert raised.value.sw == status


def delete_key(piv, slot):
    try:
        piv.authenticate(DEFAULT_MANAGEMENT_KEY)
        piv.delete_key(slot)
    except ApduError as error:
        if error.sw not in (SW.FILE_NOT_FOUND, SW.REFERENCE_DATA_NOT_FOUND):
            raise
