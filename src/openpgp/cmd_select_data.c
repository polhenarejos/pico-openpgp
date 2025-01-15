/*
 * This file is part of the Pico OpenPGP distribution (https://github.com/polhenarejos/pico-openpgp).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "openpgp.h"

int cmd_select_data() {
    file_t *ef = NULL;
    uint16_t fid = 0x0;
    if (P2(apdu) != 0x4) {
        return SW_WRONG_P1P2();
    }
    if (apdu.data[0] != 0x60) {
        return SW_WRONG_DATA();
    }
    if (apdu.nc != apdu.data[1] + 2 || apdu.nc < 5) {
        return SW_WRONG_LENGTH();
    }
    if (apdu.data[2] != 0x5C) {
        return SW_WRONG_DATA();
    }
    if (apdu.data[3] == 2) {
        fid = (apdu.data[4] << 8) | apdu.data[5];
    }
    else {
        fid = apdu.data[4];
    }
    if (!(ef = search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!authenticate_action(ef, ACL_OP_UPDATE_ERASE)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    fid &= ~0x6000; //Now get private DO
    fid += P1(apdu);
    if (!(ef = search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    select_file(ef);
    return SW_OK();
}
