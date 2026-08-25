import sys
from pathlib import Path

import pytest


OPENPGP_TEST_DIR = Path(__file__).parents[1] / "openpgp"
if str(OPENPGP_TEST_DIR) not in sys.path:
    sys.path.insert(0, str(OPENPGP_TEST_DIR))


@pytest.fixture(scope="session")
def card():
    from card_reader import get_ccid_device
    from openpgp_card import OpenPGP_Card

    reader = get_ccid_device()
    openpgp_card = OpenPGP_Card(reader)
    openpgp_card.cmd_select_openpgp()
    yield openpgp_card
    reader.ccid_power_off()
