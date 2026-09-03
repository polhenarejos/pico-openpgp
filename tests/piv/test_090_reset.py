import os

import pytest

from piv_helpers import DEFAULT_MANAGEMENT_KEY, DEFAULT_PIN, assert_apdu_error
from yubikit.core.smartcard import SW
from yubikit.piv import MANAGEMENT_KEY_TYPE, TOUCH_POLICY


@pytest.mark.skipif(not os.environ.get("PIV_RUN_DESTRUCTIVE"), reason="set PIV_RUN_DESTRUCTIVE=1 to run the destructive PIV reset test")
def test_factory_reset_restores_defaults(piv):
    piv.reset()
    assert piv.get_pin_metadata().default_value
    assert piv.get_puk_metadata().default_value
    management_metadata = piv.get_management_key_metadata()
    assert management_metadata.default_value
    assert management_metadata.key_type == MANAGEMENT_KEY_TYPE.AES192
    assert management_metadata.touch_policy == TOUCH_POLICY.NEVER
    piv.verify_pin(DEFAULT_PIN)
    piv.authenticate(DEFAULT_MANAGEMENT_KEY)
    assert_apdu_error(lambda: piv.get_slot_metadata(0x82), SW.REFERENCE_DATA_NOT_FOUND)
