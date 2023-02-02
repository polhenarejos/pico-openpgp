"""
card_test_set_attr.py - test setting key attributes

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

from card_const import *
import pytest

class Test_Set_ATTRS(object):
    #def test_verify_pw3(self, card):
    #    v = card.verify(3, FACTORY_PASSPHRASE_PW3)
    #    assert v

    def test_keyattr_set_1(self, card, pk):
        r = card.cmd_put_data(0x00, 0xc1, pk.key_attr_list[0])
        assert r

    def test_keyattr_set_2(self, card, pk):
        r = card.cmd_put_data(0x00, 0xc2, pk.key_attr_list[1])
        assert r

    def test_keyattr_set_3(self, card, pk):
        r = card.cmd_put_data(0x00, 0xc3, pk.key_attr_list[2])
        assert r
