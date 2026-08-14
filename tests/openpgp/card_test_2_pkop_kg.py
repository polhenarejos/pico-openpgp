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
from card_const import *
from constants_for_test import *

class Test_Card_PK_OPs_KG(object):
    def test_signature_sigkey(self, card, pk):
        pk_info = card.cmd_get_public_key(1)
        k = pk.PK_Crypto(keyno=0, pk_info=pk_info)
        digestinfo = pk.compute_digestinfo(pk.test_vector['sign_0'])
        sig_bytes = card.cmd_pso(0x9e, 0x9a, digestinfo)
        r = k.verify_signature(digestinfo, sig_bytes)
        assert r

    def test_decryption(self, card, pk):
        pk_info = card.cmd_get_public_key(2)
        k = pk.PK_Crypto(keyno=1, pk_info=pk_info)
        encrypted_data = k.encrypt(pk.test_vector['encrypt_0'])
        r = card.cmd_pso(0x80, 0x86, pk.enc_data(encrypted_data))
        assert pk.enc_check(encrypted_data, r)

    def test_signature_authkey(self, card, pk):
        pk_info = card.cmd_get_public_key(3)
        k = pk.PK_Crypto(2, pk_info=pk_info)
        digestinfo = pk.compute_digestinfo(pk.test_vector['sign_0'])
        sig_bytes = card.cmd_internal_authenticate(digestinfo)
        r = k.verify_signature(digestinfo, sig_bytes)
        assert r
