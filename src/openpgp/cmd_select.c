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

int cmd_select() {
    uint8_t p1 = P1(apdu);
    uint8_t p2 = P2(apdu);
    file_t *pe = NULL;
    uint16_t fid = 0x0;

    if (apdu.nc >= 2) {
        fid = get_uint16_t_be(apdu.data);
    }

    if (!pe) {
        if (p1 == 0x0) { //Select MF, DF or EF - File identifier or absent
            if (apdu.nc == 0) {
                pe = (file_t *) MF;
                //ac_fini();
            }
            else if (apdu.nc == 2) {
                if (!(pe = search_by_fid(fid, NULL, SPECIFY_ANY))) {
                    return SW_REFERENCE_NOT_FOUND();
                }
            }
        }
        else if (p1 == 0x01) { //Select child DF - DF identifier
            if (!(pe = search_by_fid(fid, currentDF, SPECIFY_DF))) {
                return SW_REFERENCE_NOT_FOUND();
            }
        }
        else if (p1 == 0x02) { //Select EF under the current DF - EF identifier
            if (!(pe = search_by_fid(fid, currentDF, SPECIFY_EF))) {
                return SW_REFERENCE_NOT_FOUND();
            }
        }
        else if (p1 == 0x03) { //Select parent DF of the current DF - Absent
            if (apdu.nc != 0) {
                return SW_REFERENCE_NOT_FOUND();
            }
        }
        else if (p1 == 0x04) { //Select by DF name - e.g., [truncated] application identifier
            if (!(pe = search_by_name(apdu.data, apdu.nc))) {
                return SW_REFERENCE_NOT_FOUND();
            }
            if (card_terminated) {
                return set_res_sw(0x62, 0x85);
            }
        }
        else if (p1 == 0x08) { //Select from the MF - Path without the MF identifier
            if (!(pe = search_by_path(apdu.data, apdu.nc, MF))) {
                return SW_REFERENCE_NOT_FOUND();
            }
        }
        else if (p1 == 0x09) { //Select from the current DF - Path without the current DF identifier
            if (!(pe = search_by_path(apdu.data, apdu.nc, currentDF))) {
                return SW_REFERENCE_NOT_FOUND();
            }
        }
    }
    if ((p2 & 0xfc) == 0x00 || (p2 & 0xfc) == 0x04) {
        if ((p2 & 0xfc) == 0x04) {
            process_fci(pe, 0);
        }
    }
    else {
        return SW_INCORRECT_P1P2();
    }
    select_file(pe);
    return SW_OK();
}
