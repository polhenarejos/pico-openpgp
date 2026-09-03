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


int cmd_piv_verify(void) {
    uint8_t key_ref = P2(apdu);
    if (P1(apdu) != 0x00 && P1(apdu) != 0xFF) {
        return SW_INCORRECT_PARAMS();
    }
    if (key_ref != 0x80) {
        return SW_INCORRECT_PARAMS();
    }
    file_t *pw, *pw_status;
    uint16_t fid = EF_PIV_PIN;
    if (!(pw = file_search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!(pw_status = file_search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (file_get_data(pw)[0] == 0) { //not initialized
        return SW_REFERENCE_NOT_FOUND();
    }
    if (P1(apdu) == 0xFF) {
        if (apdu.nc != 0) {
            return SW_INCORRECT_PARAMS();
        }
        has_pwpiv = false;
        mbedtls_platform_zeroize(session_pwpiv, sizeof(session_pwpiv));
        return SW_OK();
    }
    if (apdu.nc > 0 && apdu.nc != PIV_PIN_WIRE_SIZE) {
        has_pwpiv = false;
        mbedtls_platform_zeroize(session_pwpiv, sizeof(session_pwpiv));
        return SW_INCORRECT_PARAMS();
    }
    if (apdu.nc > 0) {
        has_pwpiv = false;
        uint16_t ret = pin_check_verifier(pw, apdu.data, apdu.nc, 2, NULL);
        if (ret == 0x9000) {
            has_pwpiv = true;
            pin_derive_session(CONST_BYTE_ARRAY(apdu.data, apdu.nc), session_pwpiv);
        }
        return ret; //SW already set
    }
    uint8_t retries = *(file_get_data(pw_status) + 3 + (fid & 0xf));
    if (retries == 0) {
        return SW_PIN_BLOCKED();
    }
    if ((key_ref == 0x80 && has_pwpiv)) {
        return SW_OK();
    }
    return set_res_sw(0x63, 0xc0 | retries);
}
