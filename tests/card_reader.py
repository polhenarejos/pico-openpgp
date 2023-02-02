"""
card_reader.py - a library for smartcard reader

Copyright (C) 2016, 2017, 2019  Free Software Initiative of Japan
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
from binascii import hexlify
import sys

try:
    from smartcard.CardType import AnyCardType
    from smartcard.CardRequest import CardRequest
    from smartcard.Exceptions import CardRequestTimeoutException, CardConnectionException
except ModuleNotFoundError:
    print('ERROR: smarctard module not found! Install pyscard package.\nTry with `pip install pyscard`')
    sys.exit(-1)

class CardReader(object):
    def __init__(self):
        """
        __init__() -> None
        Initialize the reader
        device: usb.core.Device object.
        """

        cardtype = AnyCardType()
        try:
            # request card insertion
            cardrequest = CardRequest(timeout=10, cardType=cardtype)
            self.__card = cardrequest.waitforcard()

            # connect to the card and perform a few transmits
            self.__card.connection.connect()

        except CardRequestTimeoutException:
            raise Exception('time-out: no card inserted during last 10s')

    def reset_device(self):
        self.__card.connection.reconnect()

    def send_cmd(self, cmd):
        response, sw1, sw2 = self.__card.connection.transmit(list(bytearray(cmd)))
        return bytes(response + [sw1,sw2])

    def ccid_power_off(self):
        self.__card.connection.disconnect()

def get_ccid_device():
    return CardReader()

