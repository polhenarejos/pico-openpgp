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


int cmd_piv_authenticate(void) {
    uint8_t algo = P1(apdu), key_ref = P2(apdu);
    if (apdu.nc == 0 || apdu.data[0] != 0x7C) {
        return SW_INCORRECT_PARAMS();
    }
    file_t *ef_mgm = NULL;
    if (key_ref == EF_PIV_KEY_CARDMGM) {
        ef_mgm = file_search_by_fid(key_ref, NULL, SPECIFY_EF);
        if (!file_has_data(ef_mgm)) {
            return SW_MEMORY_FAILURE();
        }
    }
    byte_array_t metadata = meta_find(key_ref);
    uint8_t *meta = metadata.data;
    if (metadata.len < 3) {
        return SW_REFERENCE_NOT_FOUND();
    }
    bool pending_mgm_challenge = key_ref == EF_PIV_KEY_CARDMGM && mgm_challenge_kind != MGM_CHALLENGE_NONE;
    if (key_ref == EF_PIV_KEY_CARDMGM) {
        if (algo != PIV_ALGO_AES128 && algo != PIV_ALGO_AES192 && algo != PIV_ALGO_AES256 && algo != PIV_ALGO_3DES) {
            return SW_INCORRECT_PARAMS();
        }
        uint8_t management_key[32] = { 0 };
        byte_buffer_t management_key_data = BYTE_BUFFER(management_key, sizeof(management_key));
        int r = openpgp_key_container_is_marker(ef_mgm) ? openpgp_key_container_read_private(EF_PIV_KEY_CARDMGM, FILE_OBJECT_OPERATION_USE, true, &management_key_data) : PICOKEYS_OK;
        size_t mgm_len = management_key_data.len;
        if (!openpgp_key_container_is_marker(ef_mgm)) {
            mgm_len = MIN(file_get_size(ef_mgm), sizeof(management_key));
        }
        mbedtls_platform_zeroize(management_key, sizeof(management_key));
        if (r != PICOKEYS_OK) {
            return SW_MEMORY_FAILURE();
        }
        if ((algo == PIV_ALGO_AES128 && mgm_len != 16) || (algo == PIV_ALGO_AES192 && mgm_len != 24) || (algo == PIV_ALGO_AES256 && mgm_len != 32) || (algo == PIV_ALGO_3DES && mgm_len != 24)) {
            return SW_INCORRECT_PARAMS();
        }
    }
    uint8_t pin_policy = meta[1];
    if (pin_policy == PINPOLICY_DEFAULT) {
        pin_policy = piv_default_pin_policy(key_ref);
    }
    if (pin_policy != PINPOLICY_NEVER && !has_pwpiv && (key_ref == EF_PIV_KEY_AUTHENTICATION || key_ref == EF_PIV_KEY_SIGNATURE || key_ref == EF_PIV_KEY_KEYMGM || key_ref == EF_PIV_KEY_CARDAUTH || IS_RETIRED(key_ref))) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    uint8_t chal_len = algo == PIV_ALGO_3DES ? sizeof(mgm_challenge) / 2 : sizeof(mgm_challenge);
    tlv_ctx_t ctxi, a7c = { 0 };
    tlv_ctx_init(BYTE_ARRAY(apdu.data, apdu.nc), &ctxi);
    if (!tlv_find_tag(&ctxi, 0x7C, &a7c) || tlv_len(&a7c) == 0) {
        return SW_INCORRECT_PARAMS();
    }
    uint16_t operation_tag = 0;
    tlv_ctx_t operation = { 0 };
    if (!piv_first_auth_operation(&a7c, &operation_tag, &operation)) {
        return SW_INCORRECT_PARAMS();
    }
    bool challenge_response = (operation_tag == 0x80 || operation_tag == 0x82) && operation.len > 0;
#ifndef ENABLE_EMULATION
    if (meta[2] != TOUCHPOLICY_NEVER && (!pending_mgm_challenge || !challenge_response) && piv_button_wait()) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
#endif
    if (key_ref == EF_PIV_KEY_CARDMGM && meta[0] != algo && !(pending_mgm_challenge && challenge_response)) {
        return SW_INCORRECT_PARAMS();
    }
    size_t slot_rsa_modulus_size = piv_rsa_modulus_size(meta[0]);
    bool rsa_family_match = slot_rsa_modulus_size > 0 && piv_rsa_modulus_size(algo) > 0 && operation_tag == 0x81 && operation.len == slot_rsa_modulus_size;
    if (algo != meta[0] && !rsa_family_match && !(pending_mgm_challenge && challenge_response)) {
        return SW_WRONG_DATA();
    }
    if (key_ref == EF_PIV_KEY_CARDMGM) {
        tlv_ctx_t empty = { 0 };
        if (operation_tag == 0x80) {
            tlv_ctx_t host_challenge = { 0 };
            tlv_find_tag(&a7c, 0x81, &host_challenge);
            return authenticate_mgm(algo, ef_mgm, chal_len, &operation, &host_challenge, &empty);
        }
        if (operation_tag == 0x81 && operation.len == 0) {
            return authenticate_mgm(algo, ef_mgm, chal_len, &empty, &operation, &empty);
        }
        if (operation_tag == 0x82) {
            return authenticate_mgm(algo, ef_mgm, chal_len, &empty, &empty, &operation);
        }
        return SW_INCORRECT_PARAMS();
    }
    bool key_management_ecc = (key_ref == EF_PIV_KEY_KEYMGM || IS_RETIRED(key_ref)) && (algo == PIV_ALGO_ECCP256 || algo == PIV_ALGO_ECCP384);
    bool ecdh = key_management_ecc && operation_tag == 0x85 && operation.len > 0;
    if (key_management_ecc && !ecdh) {
        return SW_INCORRECT_PARAMS();
    }
    if (!key_management_ecc && operation_tag != 0x81) {
        return SW_INCORRECT_PARAMS();
    }
    if (algo != PIV_ALGO_RSA1024 && algo != PIV_ALGO_RSA2048 && algo != PIV_ALGO_RSA3072 && algo != PIV_ALGO_RSA4096 && algo != PIV_ALGO_ECCP256 && algo != PIV_ALGO_ECCP384) {
        return SW_INCORRECT_PARAMS();
    }

    file_t *ef_key = file_search_by_fid(key_ref == 0x93 ? EF_PIV_KEY_RETIRED18 : key_ref, NULL, SPECIFY_EF);
    if (!file_has_data(ef_key)) {
        return SW_MEMORY_FAILURE();
    }
    if (ecdh) {
        int r = piv_ecdh(ef_key, algo, &operation);
        if (r != 0x9000) {
            return r;
        }
    }
    else if (algo == PIV_ALGO_RSA1024 || algo == PIV_ALGO_RSA2048 || algo == PIV_ALGO_RSA3072 || algo == PIV_ALGO_RSA4096) {
        mbedtls_rsa_context ctx;
        mbedtls_rsa_init(&ctx);
        int r = load_private_key_rsa(&ctx, ef_key, false);
        if (r != PICOKEYS_OK) {
            mbedtls_rsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        size_t olen = mbedtls_rsa_get_len(&ctx);
        if (olen < 256) {
            memcpy(res_APDU, "\x7C\x81\x00\x82\x81\x00", 6);
            res_APDU_size = 6;
        }
        else {
            memcpy(res_APDU, "\x7C\x82\x00\x00\x82\x82\x00\x00", 8);
            res_APDU_size = 8;
        }
        r = mbedtls_rsa_private(&ctx, random_fill_iterator, NULL, operation.data, res_APDU + res_APDU_size);
        mbedtls_rsa_free(&ctx);
        if (olen < 256) {
            res_APDU[res_APDU_size - 1] = olen;
            res_APDU[res_APDU_size - 4] = olen + 3;
        }
        else {
            res_APDU[res_APDU_size - 2] = olen >> 8;
            res_APDU[res_APDU_size - 1] = olen & 0xFF;
            res_APDU[res_APDU_size - 6] = (olen + 4) >> 8;
            res_APDU[res_APDU_size - 5] = (olen + 4) & 0xFF;
        }
        res_APDU_size += olen;
        if (r != 0) {
            return SW_EXEC_ERROR();
        }
    }
    else if (algo == PIV_ALGO_ECCP256 || algo == PIV_ALGO_ECCP384) {
        mbedtls_ecdsa_context ctx;
        mbedtls_ecdsa_init(&ctx);
        int r = load_private_key_ecdsa(&ctx, ef_key, false);
        if (r != PICOKEYS_OK) {
            mbedtls_ecdsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        size_t olen = 0;
        memcpy(res_APDU, "\x7C\x00\x82\x00", 4);
        res_APDU_size = 4;
        r = mbedtls_ecdsa_write_signature(&ctx, algo == PIV_ALGO_ECCP256 ? MBEDTLS_MD_SHA256 : MBEDTLS_MD_SHA384, operation.data, operation.len, res_APDU + res_APDU_size, MBEDTLS_ECDSA_MAX_LEN, &olen, random_fill_iterator, NULL);
        mbedtls_ecdsa_free(&ctx);
        res_APDU[res_APDU_size - 1] = olen;
        res_APDU[res_APDU_size - 3] = olen + 2;
        res_APDU_size += olen;
        if (r != 0) {
            return SW_EXEC_ERROR();
        }
    }
    else {
        return SW_INCORRECT_PARAMS();
    }
    if (meta[1] == PINPOLICY_ALWAYS) {
        has_pwpiv = false;
    }
    return SW_OK();
}
