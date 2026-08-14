import pytest

from card_reader import get_ccid_device

yubikit_core = pytest.importorskip("yubikit.core")
yubikit_piv = pytest.importorskip("yubikit.piv")
from yubikit.core import TRANSPORT
from yubikit.core.smartcard import ApduError, SW, SmartCardConnection
from yubikit.piv import PivSession

from piv_helpers import DEFAULT_MANAGEMENT_KEY


class PyscardConnection(SmartCardConnection):
    @property
    def transport(self):
        return TRANSPORT.USB

    def __init__(self, reader):
        self.reader = reader

    def send_and_receive(self, apdu):
        response = self.reader.send_cmd(apdu)
        return response[:-2], int.from_bytes(response[-2:], "big")

    def close(self):
        self.reader.ccid_power_off()


@pytest.fixture(scope="session")
def piv_connection():
    try:
        reader = get_ccid_device()
    except Exception as error:
        pytest.skip(f"PC/SC service or card unavailable: {error}")
    connection = PyscardConnection(reader)
    yield connection
    connection.close()


@pytest.fixture(scope="function")
def piv(piv_connection):
    try:
        return PivSession(piv_connection)
    except ApduError as error:
        if error.sw in (SW.APPLET_SELECT_FAILED, SW.FILE_NOT_FOUND):
            pytest.skip("connected card does not expose the PIV application")
        raise


@pytest.fixture
def managed_piv(piv):
    piv.authenticate(DEFAULT_MANAGEMENT_KEY)
    return piv
