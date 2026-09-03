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


int cmd_asym_keygen(void) {
    uint8_t key_ref = P2(apdu);
    if (!has_mgm) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (apdu.nc == 0 || apdu.data[0] != 0xAC) {
        return SW_INCORRECT_PARAMS();
    }
    if (P1(apdu) != 0x0) {
        return SW_INCORRECT_P1P2();
    }
    if (key_ref != EF_PIV_KEY_AUTHENTICATION && key_ref != EF_PIV_KEY_SIGNATURE && key_ref != EF_PIV_KEY_KEYMGM && key_ref != EF_PIV_KEY_CARDAUTH && !(key_ref >= EF_PIV_KEY_RETIRED1 && key_ref <= EF_PIV_KEY_RETIRED20)) {
        return SW_INCORRECT_P1P2();
    }
    tlv_ctx_t ctxi, aac = {0};
    tlv_ctx_init(BYTE_ARRAY(apdu.data, apdu.nc), &ctxi);
    if (!tlv_find_tag(&ctxi, 0xAC, &aac) || tlv_len(&aac) == 0) {
        return SW_WRONG_DATA();
    }
    tlv_ctx_t a80 = {0}, aaa = {0}, aab = {0};
    tlv_find_tag(&aac, 0x80, &a80);
    bool has_aaa = tlv_find_tag(&aac, 0xAA, &aaa);
    bool has_aab = tlv_find_tag(&aac, 0xAB, &aab);
    if (tlv_len(&a80) == 0) {
        return SW_WRONG_DATA();
    }
    uint8_t pin_policy, touch_policy;
    if (!piv_resolve_policies(key_ref, has_aaa, &aaa, has_aab, &aab, &pin_policy, &touch_policy)) {
        return SW_INCORRECT_PARAMS();
    }
    uint16_t key_cert = 0;
    if (key_ref == EF_PIV_KEY_AUTHENTICATION) {
        key_cert = EF_PIV_AUTHENTICATION;
    }
    else if (key_ref == EF_PIV_KEY_SIGNATURE) {
        key_cert = EF_PIV_SIGNATURE;
    }
    else if (key_ref == EF_PIV_KEY_KEYMGM) {
        key_cert = EF_PIV_KEY_MANAGEMENT;
    }
    else if (key_ref == EF_PIV_KEY_CARDAUTH) {
        key_cert = EF_PIV_CARD_AUTH;
    }
    else {
        key_cert = key_ref + 0xC08B;
    }
    if (a80.data[0] == PIV_ALGO_RSA1024 || a80.data[0] == PIV_ALGO_RSA2048 || a80.data[0] == PIV_ALGO_RSA3072) {
        printf("KEYPAIR RSA\r\n");
        tlv_ctx_t a81 = {0};
        tlv_find_tag(&aac, 0x81, &a81);
        if (tlv_len(&a81) && tlv_get_uint(&a81) != 65537u) {
            return SW_DATA_INVALID();
        }
        mbedtls_rsa_context rsa;
        mbedtls_rsa_init(&rsa);
        int exponent = 65537, nlen = a80.data[0] == PIV_ALGO_RSA1024 ? 1024 : a80.data[0] == PIV_ALGO_RSA2048 ? 2048 : 3072;
        if (tlv_len(&a81)) {
            exponent = (int)tlv_get_uint(&a81);
        }
        int r = mbedtls_rsa_gen_key(&rsa, random_fill_iterator, NULL, nlen, exponent);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_EXEC_ERROR();
        }
        make_rsa_response(&rsa);
        uint8_t cert[2048];
        r = x509_create_cert(&rsa, a80.data[0], key_ref, false, cert, sizeof(cert));
        if (r <= 0) {
            mbedtls_rsa_free(&rsa);
            return SW_EXEC_ERROR();
        }
        uint16_t cert_len = (uint16_t)r;
        uint16_t object_len = tlv_len_tag(0x70, cert_len) + 3;
        if (object_len > sizeof(cert)) {
            mbedtls_rsa_free(&rsa);
            return SW_EXEC_ERROR();
        }
        r = piv_format_certificate_object(cert + sizeof(cert) - cert_len, cert_len, cert + sizeof(cert) - object_len, sizeof(cert));
        if (r <= 0) {
            mbedtls_rsa_free(&rsa);
            return SW_EXEC_ERROR();
        }
        file_t *ef = file_search_by_fid(key_cert, NULL, SPECIFY_ANY);
        if (!ef || file_put_data(ef, CONST_BYTE_ARRAY(cert + sizeof(cert) - object_len, r)) != PICOKEYS_OK) {
            mbedtls_rsa_free(&rsa);
            return SW_EXEC_ERROR();
        }
        r = store_keys(&rsa, ALGO_RSA, key_ref == 0x93 ? EF_PIV_KEY_RETIRED18 : key_ref, false);
        mbedtls_rsa_free(&rsa);
        if (r != PICOKEYS_OK) {
            return r == PICOKEYS_ERR_NO_MEMORY ? SW_FILE_FULL() : SW_EXEC_ERROR();
        }
    }
    else if (a80.data[0] == PIV_ALGO_ECCP256 || a80.data[0] == PIV_ALGO_ECCP384) {
        printf("KEYPAIR ECDSA\r\n");
        mbedtls_ecp_group_id gid = a80.data[0] == PIV_ALGO_ECCP256 ? MBEDTLS_ECP_DP_SECP256R1 : MBEDTLS_ECP_DP_SECP384R1;
        mbedtls_ecdsa_context ecdsa;
        mbedtls_ecdsa_init(&ecdsa);
        int r = mbedtls_ecdsa_genkey(&ecdsa, gid, random_fill_iterator, NULL);
        if (r != 0) {
            mbedtls_ecdsa_free(&ecdsa);
            return SW_EXEC_ERROR();
        }
        make_ecdsa_response(&ecdsa);
        uint8_t cert[2048];
        r = x509_create_cert(&ecdsa, a80.data[0], key_ref, false, cert, sizeof(cert));
        if (r <= 0) {
            mbedtls_ecdsa_free(&ecdsa);
            return SW_EXEC_ERROR();
        }
        uint16_t cert_len = (uint16_t)r;
        uint16_t object_len = tlv_len_tag(0x70, cert_len) + 3;
        if (object_len > sizeof(cert)) {
            mbedtls_ecdsa_free(&ecdsa);
            return SW_EXEC_ERROR();
        }
        r = piv_format_certificate_object(cert + sizeof(cert) - cert_len, cert_len, cert + sizeof(cert) - object_len, sizeof(cert));
        if (r <= 0) {
            mbedtls_ecdsa_free(&ecdsa);
            return SW_EXEC_ERROR();
        }
        file_t *ef = file_search_by_fid(key_cert, NULL, SPECIFY_ANY);
        if (!ef || file_put_data(ef, CONST_BYTE_ARRAY(cert + sizeof(cert) - object_len, r)) != PICOKEYS_OK) {
            mbedtls_ecdsa_free(&ecdsa);
            return SW_EXEC_ERROR();
        }
        r = store_keys(&ecdsa, ALGO_ECDSA, key_ref == 0x93 ? EF_PIV_KEY_RETIRED18 : key_ref, false);
        mbedtls_ecdsa_free(&ecdsa);
        if (r != PICOKEYS_OK) {
            return r == PICOKEYS_ERR_NO_MEMORY ? SW_FILE_FULL() : SW_EXEC_ERROR();
        }
    }
    else {
        return SW_DATA_INVALID();
    }
    uint8_t meta[] = {a80.data[0], pin_policy, touch_policy, ORIGIN_GENERATED};
    if (meta_add(key_ref, CONST_BYTE_ARRAY(meta, sizeof(meta))) != PICOKEYS_OK || !flash_commit_sync(PIV_FLASH_COMMIT_TIMEOUT_MS)) {
        return SW_MEMORY_FAILURE();
    }
    return SW_OK();
}
