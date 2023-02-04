"""
card_test_reset_attr.py - test resetting key attributes

Copyright (C) 2021  g10 Code GmbH
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

from util import *
from card_const import *
import pytest

class Test_Reset_ATTRS(object):
    def test_verify_pw3(self, card):
        v = card.verify(3, FACTORY_PASSPHRASE_PW3)
        assert v

    def test_keyattr_reset_1(self, card):
        a = card.saved_attribute(1)
        r = card.cmd_put_data(0x00, 0xc1, a)
        assert r
        if card.is_yubikey:
            pytest.skip("Yubikey returns no attr when no key")
        else:
            a1 = get_data_object(card, 0xc1)
            if not card.is_gnuk:
                assert a1 == a
            else:
                pytest.skip("Zeitcontrol returns None when no key")

    def test_keyattr_reset_2(self, card):
        a = card.saved_attribute(2)
        r = card.cmd_put_data(0x00, 0xc2, a)
        assert r
        if card.is_yubikey:
            pytest.skip("Yubikey returns no attr when no key")
        else:
            a1 = get_data_object(card, 0xc2)
            if not card.is_gnuk:
                assert a1 == a
            else:
                pytest.skip("Zeitcontrol returns None when no key")

    def test_keyattr_reset_3(self, card):
        a = card.saved_attribute(3)
        r = card.cmd_put_data(0x00, 0xc3, a)
        assert r
        if card.is_yubikey:
            pytest.skip("Yubikey returns no attr when no key")
        else:
            a1 = get_data_object(card, 0xc3)
            if not card.is_gnuk:
                assert a1 == a
            else:
                pytest.skip("Zeitcontrol returns None when no key")
