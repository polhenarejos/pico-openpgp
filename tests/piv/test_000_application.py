from yubikit.core.smartcard import SW
from yubikit.core import Tlv

from piv_helpers import assert_apdu_error


def test_select_and_version(piv):
    assert tuple(piv.version) == (5, 7, 0)


def test_discovery_object(piv):
    # Pico wraps the discovery TLV in 0x53 and appends two implementation bytes.
    response = piv.protocol.send_apdu(0, 0xCB, 0x3F, 0xFF, Tlv(0x5C, b"\x7e"))
    assert Tlv.unpack(0x53, response).startswith(bytes.fromhex("4f0ba0000003080000100001005f2f024010"))


def test_unsupported_instruction_has_expected_status(piv):
    assert_apdu_error(lambda: piv.protocol.send_apdu(0, 0x00, 0, 0), SW.INVALID_INSTRUCTION)
