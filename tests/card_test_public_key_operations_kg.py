"""
card_test_public_key_operations_kg.py - test the sign/dec/auth

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
from pubkey_crypto import get_PK_Crypto, get_test_vector
from card_const import *
from constants_for_test import *

class Test_Card_PK_OPs_KG(object):
    def test_verify_pw3_0(self, card):
        v = card.verify(3, FACTORY_PASSPHRASE_PW3)
        assert v

    def test_signature_sigkey(self, card):
        test_vector = get_test_vector(card)
        PK_Crypto = get_PK_Crypto(card)
        pk_info = card.cmd_get_public_key(1)
        k = PK_Crypto(0, pk_info=pk_info)
        digestinfo = PK_Crypto.compute_digestinfo(test_vector['sign_0'])
        sig_bytes = card.cmd_pso(0x9e, 0x9a, digestinfo)
        r = k.verify_signature(digestinfo, sig_bytes)
        assert r

    def test_decryption(self, card):
        test_vector = get_test_vector(card)
        PK_Crypto = get_PK_Crypto(card)
        pk_info = card.cmd_get_public_key(2)
        k = PK_Crypto(1, pk_info=pk_info)
        encrypted_data = k.encrypt(test_vector['encrypt_0'])
        r = card.cmd_pso(0x80, 0x86, PK_Crypto.enc_data(encrypted_data))
        assert PK_Crypto.enc_check(encrypted_data, r)

    def test_signature_authkey(self, card):
        test_vector = get_test_vector(card)
        PK_Crypto = get_PK_Crypto(card)
        pk_info = card.cmd_get_public_key(3)
        k = PK_Crypto(2, pk_info=pk_info)
        digestinfo = PK_Crypto.compute_digestinfo(test_vector['sign_0'])
        sig_bytes = card.cmd_internal_authenticate(digestinfo)
        r = k.verify_signature(digestinfo, sig_bytes)
        assert r
