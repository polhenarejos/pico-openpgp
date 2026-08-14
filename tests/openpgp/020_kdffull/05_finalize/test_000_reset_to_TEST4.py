import pytest
from card_const import *
from constants_for_test import *

def test_setup_pw1_4(card):
    r = card.change_passwd(1, FACTORY_PASSPHRASE_PW1, PW1_TEST4)
    assert r

def test_verify_pw1_4(card):
    v = card.verify(1, PW1_TEST4)
    assert v

def test_verify_pw1_4_2(card):
    v = card.verify(2, PW1_TEST4)
    assert v
