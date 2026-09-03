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


int cmd_move_key(void) {
    if (!has_mgm) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    uint8_t to = P1(apdu), from = P2(apdu);
    if ((!IS_KEY(to) && to != 0xFF) || !IS_KEY(from)) {
        return SW_INCORRECT_P1P2();
    }
    if (to == from) {
        return SW_INCORRECT_P1P2();
    }
    if (from == 0x93) {
        from = EF_PIV_KEY_RETIRED18;
    }
    if (to == 0x93) {
        to = EF_PIV_KEY_RETIRED18;
    }
    file_t *efs, *efd;
    if (!(efs = file_search_by_fid(from, NULL, SPECIFY_EF)) || (!(efd = file_search_by_fid(to, NULL, SPECIFY_EF)) && to != 0xFF)) {
        return SW_FILE_NOT_FOUND();
    }
    uint16_t cert_from_fid = 0;
    uint16_t cert_to_fid = 0;
    if (from == EF_PIV_KEY_AUTHENTICATION) {
        cert_from_fid = EF_PIV_AUTHENTICATION;
    }
    else if (from == EF_PIV_KEY_SIGNATURE) {
        cert_from_fid = EF_PIV_SIGNATURE;
    }
    else if (from == EF_PIV_KEY_KEYMGM) {
        cert_from_fid = EF_PIV_KEY_MANAGEMENT;
    }
    else if (from == EF_PIV_KEY_CARDAUTH) {
        cert_from_fid = EF_PIV_CARD_AUTH;
    }
    else if (from == EF_PIV_KEY_RETIRED18) {
        cert_from_fid = EF_PIV_RETIRED18;
    }
    else {
        cert_from_fid = from + 0xC08B;
    }
    if (to != 0xFF) {
        if (to == EF_PIV_KEY_AUTHENTICATION) {
            cert_to_fid = EF_PIV_AUTHENTICATION;
        }
        else if (to == EF_PIV_KEY_SIGNATURE) {
            cert_to_fid = EF_PIV_SIGNATURE;
        }
        else if (to == EF_PIV_KEY_KEYMGM) {
            cert_to_fid = EF_PIV_KEY_MANAGEMENT;
        }
        else if (to == EF_PIV_KEY_CARDAUTH) {
            cert_to_fid = EF_PIV_CARD_AUTH;
        }
        else if (to == EF_PIV_KEY_RETIRED18) {
            cert_to_fid = EF_PIV_RETIRED18;
        }
        else {
            cert_to_fid = to + 0xC08B;
        }
    }

    if (to != 0xFF) {
        if (meta_delete(to) != PICOKEYS_OK) {
            return SW_MEMORY_FAILURE();
        }
        uint8_t key_data[4096 / 8] = { 0 };
        byte_buffer_t key = BYTE_BUFFER(key_data, sizeof(key_data));
        int r = PICOKEYS_OK;
        if (openpgp_key_container_is_marker(efs)) {
            r = openpgp_key_container_read_private(from, FILE_OBJECT_OPERATION_USE, true, &key);
        }
        else if (file_has_data(efs) && file_get_size(efs) <= sizeof(key_data)) {
            key.len = file_get_size(efs);
            memcpy(key_data, file_get_data(efs), key.len);
        }
        else {
            r = PICOKEYS_WRONG_DATA;
        }
        if (r == PICOKEYS_OK) {
            r = openpgp_key_container_store(to, key_data, key.len, NULL, 0, true);
        }
        mbedtls_platform_zeroize(key_data, sizeof(key_data));
        if (r != PICOKEYS_OK) {
            return SW_EXEC_ERROR();
        }
    }

    file_t *ef_cert_from = file_search_by_fid(cert_from_fid, NULL, SPECIFY_EF);
    if (to != 0xFF) {
        file_t *ef_cert_to = file_search_by_fid(cert_to_fid, NULL, SPECIFY_EF);
        if (!ef_cert_to) {
            return SW_FILE_NOT_FOUND();
        }
        if (file_has_data(ef_cert_from)) {
            uint16_t cert_len = MIN(file_get_size(ef_cert_from), OPENPGP_MAX_OBJECT_SIZE);
            file_put_data(ef_cert_to, CONST_BYTE_ARRAY(file_get_data(ef_cert_from), cert_len));
        }
        else {
            flash_clear_file(ef_cert_to);
        }
    }
    if (ef_cert_from) {
        flash_clear_file(ef_cert_from);
    }

    byte_array_t metadata = meta_find(from);
    uint8_t *meta_src = metadata.data;
    size_t meta_len = metadata.len;
    if (to != 0xFF) {
        if (meta_len > 0 && meta_src != NULL) {
            uint8_t *meta_copy = (uint8_t *)calloc(1, (size_t)meta_len);
            if (!meta_copy) {
                return SW_MEMORY_FAILURE();
            }
            memcpy(meta_copy, meta_src, (size_t)meta_len);
            if (meta_add(to, CONST_BYTE_ARRAY(meta_copy, meta_len)) != PICOKEYS_OK) {
                free(meta_copy);
                return SW_MEMORY_FAILURE();
            }
            free(meta_copy);
        }
        else {
            meta_delete(to);
        }
    }
    meta_delete(from);
    if (openpgp_key_container_is_marker(efs)) {
        if (openpgp_key_container_delete(from, true) != PICOKEYS_OK) {
            return SW_EXEC_ERROR();
        }
    }
    else {
        flash_clear_file(efs);
    }
    flash_commit();
    return SW_OK();
}
