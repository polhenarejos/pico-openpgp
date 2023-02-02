"""
card_test_check_card.py - test configuration of card

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

from binascii import hexlify
from util import *
from card_const import *
import pytest

def print_key_attr(keyno, p):
    algo = p[0]
    if algo == 0x01 and len(p) >= 6:
        # RSA
        nbits = (p[1] << 8) | p[2]
        ebits = (p[3] << 8) | p[4]
        flags = p[5]
        print(keyno)
        print("RSA")
        print(nbits)
        print(ebits)
        print(flags)
    elif len(p) >= 2 and (algo == 0x12 or algo == 0x13 or algo == 0x16):
        # ECC
        if p[-1] == 0x00 or p[-1] == 0x00:
            flag = True # Pubkey required
            curve = p[1:-1]
        else:
            flag = False # Pubkey is not required
            curve = p[1:]
        print(keyno)
        print("ECDSA" if algo == 0x13 else "ECDH" if algo == 0x12 else "EDDSA")
        print(curve)
        print(flag)
    else:
        print("Unknown algo attr")


def parse_list_of_key_attributes(card, p, printout=False):
    while True:
        if len(p) < 2:
            break
        tag = p[0]
        length = p[1]
        if tag < 0xc1:
            p = p[2:]
            continue
        if tag == 0xda:
            keyno = 0x81
        else:
            keyno = tag - 0xc1 + 1
        if len(p) - 2 < length:
            break
        attr = p[2:2+length]
        if printout:
            print_key_attr(keyno, attr)
        p = p[2+length:]
        if keyno >= 1 and keyno <= 3:
            card.add_to_key_attrlist(keyno - 1, attr)

def test_list_of_key_attributes(card):
    a = get_data_object(card, 0xfa)
    parse_list_of_key_attributes(card, a, True)
