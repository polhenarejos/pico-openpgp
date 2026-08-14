import pytest

from piv_helpers import DEFAULT_PIN, DEFAULT_PUK
from yubikit.core import InvalidPinError


def test_pin_metadata_and_authentication(piv):
    metadata = piv.get_pin_metadata()
    assert metadata.default_value
    assert metadata.total_attempts == 3
    assert metadata.attempts_remaining == 3

    with pytest.raises(InvalidPinError) as raised:
        piv.verify_pin("000000")
    assert raised.value.attempts_remaining == 2
    piv.verify_pin(DEFAULT_PIN)


def test_pin_change_round_trip(piv):
    new_pin = "654321"
    changed = False
    try:
        piv.change_pin(DEFAULT_PIN, new_pin)
        changed = True
        piv.verify_pin(new_pin)
        with pytest.raises(InvalidPinError):
            piv.verify_pin(DEFAULT_PIN)
        piv.verify_pin(new_pin)
    finally:
        if changed:
            piv.change_pin(new_pin, DEFAULT_PIN)


def test_puk_change_and_unblock_round_trip(piv):
    new_puk = "87654321"
    new_pin = "135790"
    changed = False
    try:
        piv.change_puk(DEFAULT_PUK, new_puk)
        changed = True
        piv.unblock_pin(new_puk, new_pin)
        piv.verify_pin(new_pin)
        piv.change_pin(new_pin, DEFAULT_PIN)
    finally:
        if changed:
            piv.change_puk(new_puk, DEFAULT_PUK)
