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

int cmd_verify() {
    uint8_t p1 = P1(apdu);
    uint8_t p2 = P2(apdu);

    if (p1 == 0xFF) {
        if (apdu.nc != 0) {
            return SW_WRONG_DATA();
        }
        if (p2 == 0x81) {
            has_pw1 = false;
        }
        else if (p2 == 0x82) {
            has_pw2 = false;
        }
        else if (p2 == 0x83) {
            has_pw3 = false;
        }
        return SW_OK();
    }
    else if (p1 != 0x0 || (p2 & 0x60) != 0x0) {
        return SW_WRONG_P1P2();
    }
    uint16_t fid = 0x1000 | p2;
    if (fid == EF_RC && apdu.nc > 0) {
        fid = EF_PW1;
    }
    file_t *pw, *pw_status;
    if (!(pw = search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!(pw_status = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (file_get_data(pw)[0] == 0) { //not initialized
        return SW_REFERENCE_NOT_FOUND();
    }
    if (apdu.nc > 0) {
        return check_pin(pw, apdu.data, apdu.nc);
    }
    uint8_t retries = *(file_get_data(pw_status) + 3 + (fid & 0xf));
    if (retries == 0) {
        return SW_PIN_BLOCKED();
    }
    if ((p2 == 0x81 && has_pw1) || (p2 == 0x82 && has_pw2) || (p2 == 0x83 && has_pw3)) {
        return SW_OK();
    }
    return set_res_sw(0x63, 0xc0 | retries);
}
