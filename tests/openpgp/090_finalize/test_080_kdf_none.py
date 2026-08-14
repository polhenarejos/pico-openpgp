"""
test_025_kdf_none.py - test KDF data object

Copyright (C) 2018  g10 Code GmbH
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

from skip_if_no_kdf_support import *

from card_const import *
from constants_for_test import *

def test_verify_pw3(card):
    v = card.verify(3, FACTORY_PASSPHRASE_PW3)
    assert v

def test_kdf_put_none(card):
    if card.is_yubikey:
        KDF_SETUP_NONE=b"\x81\x01\x00"
    else:
        KDF_SETUP_NONE=b""
    r = card.configure_kdf(KDF_SETUP_NONE)
    assert r

def test_verify_pw3_1(card):
    v = card.verify(3, FACTORY_PASSPHRASE_PW3)
    assert v
