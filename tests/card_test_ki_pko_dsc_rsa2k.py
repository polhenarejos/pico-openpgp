"""
card_test_ki_pko_dsc.py - test personalizing card

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

import pytest
from card_const import KEY_ATTRIBUTES_RSA2K, KEY_ATTRIBUTES_RSA2K_ALT
from rsa_keys import rsa_pk

@pytest.fixture(scope="module",autouse=True)
def check_rsa2k(card):
    if not (KEY_ATTRIBUTES_RSA2K in card.supported_key_attrlist[0]
            or KEY_ATTRIBUTES_RSA2K_ALT in card.supported_key_attrlist[0]):
        pytest.skip("Test for RSA-2048", allow_module_level=True)

@pytest.fixture(scope="module")
def pk(card):
    print("Select RSA-2048 for testing key import")
    return rsa_pk

from card_test_0_set_attr import *
from card_test_1_import_keys import *
from card_test_2_pkop import *
from card_test_3_ds_counter2 import *
