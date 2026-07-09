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

int cmd_select_data(void) {
    file_t *ef = NULL;
    uint16_t fid = 0x0;
    if (P2(apdu) != 0x4) {
        return SW_WRONG_P1P2();
    }
    if (apdu.nc < 5u) {
        return SW_WRONG_LENGTH();
    }
    if (apdu.data[0] != 0x60) {
        return SW_WRONG_DATA();
    }
    if (apdu.nc != (uint32_t) apdu.data[1] + 2u) {
        return SW_WRONG_LENGTH();
    }
    if (apdu.data[2] != 0x5C) {
        return SW_WRONG_DATA();
    }
    if (apdu.data[3] == 2) {
        if (apdu.nc < 6u) {
            return SW_WRONG_LENGTH();
        }
        fid = (apdu.data[4] << 8) | apdu.data[5];
    }
    else if (apdu.data[3] == 1) {
        fid = apdu.data[4];
    }
    else {
        return SW_WRONG_DATA();
    }
    if (fid != EF_CH_CERT || P1(apdu) >= 3) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!(ef = file_search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!file_authenticate_action(ef, ACL_OP_UPDATE_ERASE)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    fid = EF_CH_1 + P1(apdu);
    if (!(ef = file_search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    select_file(ef);
    return SW_OK();
}
