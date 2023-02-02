"""
card_test_personalize_admin_less.py - test admin-less mode

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

from struct import pack
from re import match, DOTALL
from util import *
from card_const import *
from constants_for_test import *

class Test_Card_Personalize_Adminless_SECOND(object):
    def test_verify_pw3_admin_less_2(self, card):
        v = card.verify(3, PW1_TEST2)
        assert v

    def test_login_put(self, card):
        r = card.cmd_put_data(0x00, 0x5e, b"gpg_user")
        assert r

    def test_name_put(self, card):
        r = card.cmd_put_data(0x00, 0x5b, b"GnuPG User")
        assert r

    def test_lang_put(self, card):
        r = card.cmd_put_data(0x5f, 0x2d, b"ja")
        assert r

    def test_sex_put(self, card):
        r = card.cmd_put_data(0x5f, 0x35, b"1")
        assert r

    def test_url_put(self, card):
        r = card.cmd_put_data(0x5f, 0x50, b"https://www.fsij.org/gnuk/")
        assert r

    def test_pw1_status_put(self, card):
        r = card.cmd_put_data(0x00, 0xc4, b"\x01")
        assert r

    def test_login(self, card):
        login = get_data_object(card, 0x5e)
        assert login == b"gpg_user"

    def test_name_lang_sex(self, card):
        name = b"GnuPG User"
        lang = b"ja"
        sex = b"1"
        expected = b'\x5b' + pack('B', len(name)) + name \
                   +  b'\x5f\x2d' + pack('B', len(lang)) + lang \
                   + b'\x5f\x35' + pack('B', len(sex)) + sex
        name_lang_sex = get_data_object(card, 0x65)
        assert name_lang_sex == expected

    def test_url(self, card):
        url = get_data_object(card, 0x5f50)
        assert url == b"https://www.fsij.org/gnuk/"

    def test_pw1_status(self, card):
        s = get_data_object(card, 0xc4)
        assert match(b'\x01...\x03[\x00\x03]\x03', s, DOTALL)

    # Setting PW3, changed to admin-full mode

    def test_setup_pw3_1(self, card):
        r = card.change_passwd(3, PW1_TEST2, PW3_TEST1)
        assert r

    def test_verify_pw3_1(self, card):
        v = card.verify(3, PW3_TEST1)
        assert v

    def test_reset_userpass_admin(self, card):
        r = card.reset_passwd_by_admin(PW1_TEST3)
        assert r

    def test_verify_pw1_3(self, card):
        v = card.verify(1, PW1_TEST3)
        assert v

    def test_verify_pw1_3_2(self, card):
        v = card.verify(2, PW1_TEST3)
        assert v

    def test_setup_pw1_4(self, card):
        r = card.change_passwd(1, PW1_TEST3, PW1_TEST4)
        assert r

    def test_verify_pw1_4(self, card):
        v = card.verify(1, PW1_TEST4)
        assert v

    def test_verify_pw1_4_2(self, card):
        v = card.verify(2, PW1_TEST4)
        assert v

    def test_setup_pw3_2(self, card):
        r = card.change_passwd(3, PW3_TEST1, PW3_TEST0)
        assert r

    def test_verify_pw3_2(self, card):
        v = card.verify(3, PW3_TEST0)
        assert v

