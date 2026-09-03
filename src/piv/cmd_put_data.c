/*
 * This file is part of the Pico OpenPGP distribution (https://github.com/polhenarejos/pico-openpgp).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "piv.h"


int cmd_piv_put_data(void) {
    if (P1(apdu) != 0x3F || P2(apdu) != 0xFF) {
        return SW_INCORRECT_P1P2();
    }
    if (!has_mgm) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (apdu.nc == 0) {
        return SW_WRONG_LENGTH();
    }
    tlv_ctx_t ctxi, a5c = {0}, a53 = {0};
    tlv_ctx_init(BYTE_ARRAY(apdu.data, apdu.nc), &ctxi);
    if (apdu.data[0] != 0x7E && apdu.data[0] != 0x7F && (!tlv_find_tag(&ctxi, 0x5C, &a5c) || !tlv_find_tag(&ctxi, 0x53, &a53))) {
        return SW_WRONG_DATA();
    }
    if (a5c.data && a53.data) {
        if (a5c.len != 3 || a5c.data[0] != 0x5F || a5c.data[1] != 0xC1) {
            return SW_WRONG_DATA();
        }
        uint16_t fid = (a5c.data[1] << 8 | a5c.data[2]);
        file_t *ef = file_search_by_fid(fid, NULL, SPECIFY_EF);
        if (!ef) {
            return SW_MEMORY_FAILURE();
        }
        if (fid == EF_PIV_CHUID && file_has_data(ef)) {
            return SW_FUNC_NOT_SUPPORTED();
        }
        if (a53.len > OPENPGP_MAX_OBJECT_SIZE) {
            return SW_WRONG_LENGTH();
        }
        if (fid == EF_PIV_AUTHENTICATION && !piv_validate_certificate_object(a53.data, a53.len)) {
            return SW_WRONG_DATA();
        }
        if (a53.len > 0) {
            file_put_data(ef, CONST_BYTE_ARRAY(a53.data, a53.len));
        }
        else {
            if (flash_clear_file(ef) != PICOKEYS_OK) {
                return SW_MEMORY_FAILURE();
            }
        }
        flash_commit();
    }
    return SW_OK();
}
