/*
 * This file is part of the Pico OpenPGP distribution (https://github.com/polhenarejos/pico-openpgp).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "openpgp.h"

int cmd_mse() {
    if (P1(apdu) != 0x41 || (P2(apdu) != 0xA4 && P2(apdu) != 0xB8)) {
        return SW_WRONG_P1P2();
    }
    if (apdu.data[0] != 0x83 || apdu.data[1] != 0x1 ||
        (apdu.data[2] != 0x2 && apdu.data[2] != 0x3)) {
        return SW_WRONG_DATA();
    }
    if (P2(apdu) == 0xA4) {
        if (apdu.data[2] == 0x2) {
            algo_dec = EF_ALGO_PRIV2;
            pk_dec = EF_PK_DEC;
        }
        else if (apdu.data[2] == 0x3) {
            algo_dec = EF_ALGO_PRIV3;
            pk_dec = EF_PK_AUT;
        }
    }
    else if (P2(apdu) == 0xB8) {
        if (apdu.data[2] == 0x2) {
            algo_aut = EF_ALGO_PRIV2;
            pk_aut = EF_PK_DEC;
        }
        else if (apdu.data[2] == 0x3) {
            algo_aut = EF_ALGO_PRIV3;
            pk_aut = EF_PK_AUT;
        }
    }
    return SW_OK();
}
