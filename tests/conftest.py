import pytest
from card_reader import get_ccid_device
from openpgp_card import OpenPGP_Card

def pytest_addoption(parser):
    parser.addoption("--reader", dest="reader", type=str, action="store",
                     default="gnuk", help="specify reader: gnuk or gemalto")

@pytest.fixture(scope="session")
def card():
    print()
    print("Test start!")
    reader = get_ccid_device()
    card = OpenPGP_Card(reader)
    card.cmd_select_openpgp()
    yield card
    del card
    reader.ccid_power_off()
