"""
card_test_kdf_full.py - test KDF data object

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

import pytest

from card_const import *
from constants_for_test import *

class Test_Card_KDF_full(object):

    def test_verify_pw3(self, card):
        v = card.verify(3, FACTORY_PASSPHRASE_PW3)
        assert v

    def test_kdf_put_full(self, card):
        r = card.configure_kdf(KDF_FULL)
        assert r

    def test_kdf_rekeys_pin_references(self, card):
        assert card.cmd_verify(1, KDF_FULL_HASH_PW1)
        assert card.cmd_verify(3, KDF_FULL_HASH_PW3)

    def test_kdf_changes_pw3(self, card):
        assert card.change_passwd(3, FACTORY_PASSPHRASE_PW3, PW3_TEST0)
        assert card.verify(3, PW3_TEST0)
        assert card.change_passwd(3, PW3_TEST0, FACTORY_PASSPHRASE_PW3)
        assert card.verify(3, FACTORY_PASSPHRASE_PW3)

    def test_kdf_disable_does_not_reset_custom_pin(self, card):
        assert card.change_passwd(3, FACTORY_PASSPHRASE_PW3, PW3_TEST0)
        with pytest.raises(ValueError, match="^6985$"):
            card.cmd_put_data(0x00, 0xF9, b"\x81\x01\x00")
        assert card.change_passwd(3, PW3_TEST0, FACTORY_PASSPHRASE_PW3)
