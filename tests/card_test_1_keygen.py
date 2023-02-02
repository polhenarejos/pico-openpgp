"""
card_test_keygen.py - test key generation

Copyright (C) 2018, 2019  g10 Code GmbH
Author: NIIBE Yutaka <gniibe@fsij.org>

This file is a part of Gnuk, a GnuPG USB Token implementation.

Gnuk is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Gnuk is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from binascii import hexlify
from card_const import *
from constants_for_test import *
import pytest

class Test_Card_Keygen(object):
    def test_000_setup_pw1_0(self, card):
        if card.is_gnuk:
            pytest.skip("Gnuk doesn't support passphrase with no key")
        else:
            r = card.change_passwd(1, FACTORY_PASSPHRASE_PW1, PW1_TEST4)
            assert r

    def test_verify_pw1_0_1(self, card):
        if card.is_gnuk:
            pytest.skip("Gnuk doesn't support passphrase with no key")
        else:
            v = card.verify(1, PW1_TEST4)
            assert v

    def test_verify_pw1_0_2(self, card):
        if card.is_gnuk:
            pytest.skip("Gnuk doesn't support passphrase with no key")
        else:
            v = card.verify(2, PW1_TEST4)
            assert v

    def test_keygen_1(self, card, pk):
        pk_info = card.cmd_genkey(1)
        k = pk.PK_Crypto(keyno=0, pk_info=pk_info)
        r = card.cmd_put_data(0x00, 0xc7, k.get_fpr())
        if r:
            r = card.cmd_put_data(0x00, 0xce, k.get_timestamp())
        assert r

    def test_keygen_2(self, card, pk):
        pk_info = card.cmd_genkey(2)
        k = pk.PK_Crypto(keyno=1, pk_info=pk_info)
        r = card.cmd_put_data(0x00, 0xc8, k.get_fpr())
        if r:
            r = card.cmd_put_data(0x00, 0xcf, k.get_timestamp())
        assert r

    def test_keygen_3(self, card, pk):
        pk_info = card.cmd_genkey(3)
        k = pk.PK_Crypto(keyno=2, pk_info=pk_info)
        r = card.cmd_put_data(0x00, 0xc9, k.get_fpr())
        if r:
            r = card.cmd_put_data(0x00, 0xd0, k.get_timestamp())
        assert r

    def test_setup_pw1_0(self, card):
        if card.is_gnuk:
            r = card.change_passwd(1, FACTORY_PASSPHRASE_PW1, PW1_TEST4)
            assert r
        else:
            pytest.skip("Gnuk resets passphrase on keygen, so, change passwd")

    def test_verify_pw1(self, card):
        v = card.verify(1, PW1_TEST4)
        assert v

    def test_verify_pw1_2(self, card):
        v = card.verify(2, PW1_TEST4)
        assert v

    def test_setup_pw1_reset(self, card):
        r = card.change_passwd(1, PW1_TEST4, FACTORY_PASSPHRASE_PW1)
        assert r

    def test_verify_pw1_reset_1(self, card):
        v = card.verify(1, FACTORY_PASSPHRASE_PW1)
        assert v

    def test_verify_pw1_reset_2(self, card):
        v = card.verify(2, FACTORY_PASSPHRASE_PW1)
        assert v
