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


int cmd_set_mgmkey(void) {
    if (P1(apdu) != 0xFF) {
        return SW_INCORRECT_P1P2();
    }
    if (apdu.nc < 5) {
        return SW_WRONG_LENGTH();
    }
    if (!has_mgm) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    uint8_t touch = P2(apdu);
    if (touch != 0xFF && touch != 0xFE) {
        return SW_INCORRECT_P1P2();
    }
    if (touch == 0xFF) {
        touch = TOUCHPOLICY_NEVER;
    }
    else if (touch == 0xFE) {
        touch = TOUCHPOLICY_ALWAYS;
    }
    uint8_t algo = apdu.data[0], key_ref = apdu.data[1], pinlen = apdu.data[2];
    if ((key_ref != EF_PIV_KEY_CARDMGM) || (!(algo == PIV_ALGO_AES128 && pinlen == 16) && !(algo == PIV_ALGO_AES192 && pinlen == 24) && !(algo == PIV_ALGO_AES256 && pinlen == 32) && !(algo == PIV_ALGO_3DES && pinlen == 24))) {
        return SW_WRONG_DATA();
    }
    if (apdu.nc != (uint32_t)pinlen + 3u) {
        return SW_WRONG_LENGTH();
    }
    if (openpgp_key_container_store(key_ref, apdu.data + 3, pinlen, NULL, 0, true) != PICOKEYS_OK) {
        return SW_MEMORY_FAILURE();
    }
    byte_array_t metadata = meta_find(key_ref);
    uint8_t *meta = metadata.data;
    uint8_t new_meta[4];
    if (!meta) {
        return SW_REFERENCE_NOT_FOUND();
    }
    memcpy(new_meta, meta, 4);
    new_meta[0] = algo;
    new_meta[1] = MGM_PIN_POLICY;
    new_meta[2] = touch;
    if (meta_add(key_ref, CONST_BYTE_ARRAY(new_meta, sizeof(new_meta))) != PICOKEYS_OK || !flash_commit_sync(PIV_FLASH_COMMIT_TIMEOUT_MS)) {
        return SW_MEMORY_FAILURE();
    }
    return SW_OK();
}
