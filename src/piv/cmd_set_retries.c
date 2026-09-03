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


int cmd_set_retries(void) {
    if (!has_mgm || !has_pwpiv) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (P1(apdu) > PIV_MAX_RETRIES || P2(apdu) > PIV_MAX_RETRIES) {
        return SW_INCORRECT_PARAMS();
    }
    file_t *ef = file_search_by_fid(EF_PW_RETRIES, NULL, SPECIFY_ANY);
    if (!ef) {
        return SW_MEMORY_FAILURE();
    }
    uint16_t retries_len = file_get_size(ef);
    if (retries_len < 6) {
        return SW_WRONG_DATA();
    }
    uint8_t *tmp = (uint8_t *)calloc(1, retries_len);
    if (!tmp) {
        return SW_MEMORY_FAILURE();
    }
    memcpy(tmp, file_get_data(ef), retries_len);
    tmp[4] = P1(apdu);
    tmp[5] = P2(apdu);
    file_put_data(ef, CONST_BYTE_ARRAY(tmp, retries_len));
    free(tmp);

    ef = file_search_by_fid(EF_PIV_PIN, NULL, SPECIFY_ANY);
    const uint8_t def_pin[8] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF };

    uint8_t dhash[34];
    dhash[0] = sizeof(def_pin);
    dhash[1] = 0x1; // Format
    pin_derive_verifier(CONST_BYTE_ARRAY(def_pin, sizeof(def_pin)), dhash + 2);
    file_put_data(ef, CONST_BYTE_ARRAY(dhash, sizeof(dhash)));
    pin_reset_retries(ef, true);

    ef = file_search_by_fid(EF_PIV_PUK, NULL, SPECIFY_ANY);
    const uint8_t def_puk[8] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
    dhash[0] = sizeof(def_puk);
    dhash[1] = 0x1; // Format
    pin_derive_verifier(CONST_BYTE_ARRAY(def_puk, sizeof(def_puk)), dhash + 2);
    file_put_data(ef, CONST_BYTE_ARRAY(dhash, sizeof(dhash)));
    pin_reset_retries(ef, true);

    flash_commit();
    return SW_OK();
}
