"""
card_test_public_key_operations_alt.py - test the sign/dec/auth

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
from pubkey_crypto import get_PK_Crypto, get_key, get_test_vector
from card_const import *
from constants_for_test import *

class Test_Card_PK_OPs(object):
    def test_sign_0(self, card):
        test_vector = get_test_vector(card)
        key = get_key(card)
        PK_Crypto = get_PK_Crypto(card)
        digestinfo = PK_Crypto.compute_digestinfo(test_vector['sign_0'])
        r = card.cmd_pso(0x9e, 0x9a, digestinfo)
        sig_bytes = key[0].compute_signature(digestinfo)
        assert r == sig_bytes

    # Since forcesig setting, failed
    def test_sign_1(self, card):
        test_vector = get_test_vector(card)
        PK_Crypto = get_PK_Crypto(card)
        digestinfo = PK_Crypto.compute_digestinfo(test_vector['sign_1'])
        try:
            r = card.cmd_pso(0x9e, 0x9a, digestinfo)
        except ValueError as e:
            r = e.args[0]
        assert r == "6982"

    def test_decrypt_0(self, card):
        test_vector = get_test_vector(card)
        key = get_key(card)
        encrypted_data = key[1].encrypt(test_vector['decrypt_0'])
        PK_Crypto = get_PK_Crypto(card)
        r = card.cmd_pso(0x80, 0x86, PK_Crypto.enc_data(encrypted_data))
        assert PK_Crypto.enc_check(encrypted_data, r)

    def test_decrypt_1(self, card):
        test_vector = get_test_vector(card)
        key = get_key(card)
        PK_Crypto = get_PK_Crypto(card)
        encrypted_data = key[1].encrypt(test_vector['decrypt_1'])
        r = card.cmd_pso(0x80, 0x86, PK_Crypto.enc_data(encrypted_data))
        assert PK_Crypto.enc_check(encrypted_data, r)

    def test_auth_0(self, card):
        test_vector = get_test_vector(card)
        key = get_key(card)
        PK_Crypto = get_PK_Crypto(card)
        digestinfo = PK_Crypto.compute_digestinfo(test_vector['auth_0'])
        r = card.cmd_internal_authenticate(digestinfo)
        sig_bytes = key[2].compute_signature(digestinfo)
        assert r == sig_bytes

    def test_auth_1(self, card):
        test_vector = get_test_vector(card)
        key = get_key(card)
        PK_Crypto = get_PK_Crypto(card)
        digestinfo = PK_Crypto.compute_digestinfo(test_vector['auth_1'])
        r = card.cmd_internal_authenticate(digestinfo)
        sig_bytes = key[2].compute_signature(digestinfo)
        assert r == sig_bytes
