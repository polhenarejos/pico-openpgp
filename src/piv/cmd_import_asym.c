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


int cmd_import_asym(void) {
    if (!has_mgm) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    uint8_t algo = P1(apdu), key_ref = P2(apdu);
    if (key_ref != EF_PIV_KEY_AUTHENTICATION && key_ref != EF_PIV_KEY_SIGNATURE && key_ref != EF_PIV_KEY_KEYMGM && key_ref != EF_PIV_KEY_CARDAUTH && !(key_ref >= EF_PIV_KEY_RETIRED1 && key_ref <= EF_PIV_KEY_RETIRED20)) {
        return SW_INCORRECT_P1P2();
    }
    tlv_ctx_t ctxi, aaa = {0}, aab = {0};
    tlv_ctx_init(BYTE_ARRAY(apdu.data, apdu.nc), &ctxi);
    bool has_aaa = tlv_find_tag(&ctxi, 0xAA, &aaa);
    bool has_aab = tlv_find_tag(&ctxi, 0xAB, &aab);
    uint8_t pin_policy, touch_policy;
    if (!piv_resolve_policies(key_ref, has_aaa, &aaa, has_aab, &aab, &pin_policy, &touch_policy)) {
        return SW_INCORRECT_PARAMS();
    }
    if (algo == PIV_ALGO_RSA1024 || algo == PIV_ALGO_RSA2048 || algo == PIV_ALGO_RSA3072 || algo == PIV_ALGO_RSA4096) {
        tlv_ctx_t a1 = { 0 }, a2 = { 0 };
        tlv_find_tag(&ctxi, 0x01, &a1);
        tlv_find_tag(&ctxi, 0x02, &a2);
        if (tlv_len(&a1) <= 0 || tlv_len(&a2) <= 0) {
            return SW_WRONG_DATA();
        }
        mbedtls_rsa_context rsa;
        mbedtls_rsa_init(&rsa);
        int r = mbedtls_mpi_read_binary(&rsa.P, a1.data, a1.len);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_WRONG_DATA();
        }
        r = mbedtls_mpi_read_binary(&rsa.Q, a2.data, a2.len);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_WRONG_DATA();
        }
        int exponent = 65537;
        mbedtls_mpi_lset(&rsa.E, exponent);
        r = mbedtls_rsa_import(&rsa, NULL, &rsa.P, &rsa.Q, NULL, &rsa.E);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_EXEC_ERROR();
        }
        r = mbedtls_rsa_complete(&rsa);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_EXEC_ERROR();
        }
        r = mbedtls_rsa_check_privkey(&rsa);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_EXEC_ERROR();
        }
        if (meta_delete(key_ref) != PICOKEYS_OK) {
            mbedtls_rsa_free(&rsa);
            return SW_MEMORY_FAILURE();
        }
        r = store_keys(&rsa, ALGO_RSA, key_ref == 0x93 ? EF_PIV_KEY_RETIRED18 : key_ref, false);
        mbedtls_rsa_free(&rsa);
        if (r != 0) {
            return SW_EXEC_ERROR();
        }
    }
    else if (algo == PIV_ALGO_ECCP256 || algo == PIV_ALGO_ECCP384) {
        tlv_ctx_t a6 = {0};
        tlv_find_tag(&ctxi, 0x06, &a6);
        size_t scalar_size = algo == PIV_ALGO_ECCP256 ? 32 : 48;
        if (tlv_len(&a6) != scalar_size) {
            return SW_DATA_INVALID();
        }
        mbedtls_ecp_group_id gid = algo == PIV_ALGO_ECCP256 ? MBEDTLS_ECP_DP_SECP256R1 : MBEDTLS_ECP_DP_SECP384R1;
        mbedtls_ecdsa_context ecdsa;
        mbedtls_ecdsa_init(&ecdsa);
        int r = mbedtls_ecp_read_key(gid, &ecdsa, a6.data, a6.len);
        if (r != 0) {
            mbedtls_ecdsa_free(&ecdsa);
            return SW_EXEC_ERROR();
        }
        r = mbedtls_ecp_keypair_calc_public(&ecdsa, random_fill_iterator, NULL);
        if (r != 0) {
            mbedtls_ecdsa_free(&ecdsa);
            return SW_EXEC_ERROR();
        }
        r = mbedtls_ecp_check_pub_priv(&ecdsa, &ecdsa, random_fill_iterator, NULL);
        if (r != 0) {
            mbedtls_ecdsa_free(&ecdsa);
            return SW_EXEC_ERROR();
        }
        if (meta_delete(key_ref) != PICOKEYS_OK) {
            mbedtls_ecdsa_free(&ecdsa);
            return SW_MEMORY_FAILURE();
        }
        r = store_keys(&ecdsa, ALGO_ECDSA, key_ref == 0x93 ? EF_PIV_KEY_RETIRED18 : key_ref, false);
        mbedtls_ecdsa_free(&ecdsa);
        if (r != 0) {
            return SW_EXEC_ERROR();
        }
    }
    else {
        return SW_WRONG_DATA();
    }
    uint8_t meta[] = { algo, pin_policy, touch_policy, ORIGIN_IMPORTED };
    if (meta_add(key_ref, CONST_BYTE_ARRAY(meta, sizeof(meta))) != PICOKEYS_OK || !flash_commit_sync(PIV_FLASH_COMMIT_TIMEOUT_MS)) {
        return SW_MEMORY_FAILURE();
    }
    return SW_OK();
}
