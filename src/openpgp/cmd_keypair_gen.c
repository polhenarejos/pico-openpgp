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

#include <stdio.h>
#include "openpgp.h"
#include "do.h"
#include "key_container.h"
#include "random.h"

int cmd_keypair_gen(void) {
    if (P2(apdu) != 0x0) {
        return SW_INCORRECT_P1P2();
    }
    if (apdu.nc != 2 && apdu.nc != 5) {
        return SW_WRONG_LENGTH();
    }
    if (!has_pw3 && P1(apdu) == 0x80) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }

    uint16_t fid = 0x0;
    int r = PICOKEYS_OK;
    if (apdu.data[0] == 0xB6) {
        fid = EF_PK_SIG;
    }
    else if (apdu.data[0] == 0xB8) {
        fid = EF_PK_DEC;
    }
    else if (apdu.data[0] == 0xA4) {
        fid = EF_PK_AUT;
    }
    else {
        return SW_WRONG_DATA();
    }

    file_t *algo_ef = file_search_by_fid(fid - 0x0010, NULL, SPECIFY_EF);
    if (!algo_ef) {
        return SW_REFERENCE_NOT_FOUND();
    }
    const uint8_t *algo = algorithm_attr_rsa2k + 1;
    uint16_t algo_len = algorithm_attr_rsa2k[0];
    if (algo_ef && algo_ef->data) {
        algo = file_get_data(algo_ef);
        algo_len = file_get_size(algo_ef);
    }
    if (algo_len == 0 || algo_len > OPENPGP_MAX_ALGORITHM_ATTR_SIZE) {
        return SW_WRONG_DATA();
    }
    if (P1(apdu) == 0x80) { //generate
        if (algo[0] == ALGO_RSA) {
            if (algo_len < 3) {
                return SW_WRONG_DATA();
            }
            int exponent = 65537, nlen = (algo[1] << 8) | algo[2];
            printf("KEYPAIR RSA %d\r\n", nlen);
            //if (nlen != 2048 && nlen != 4096)
            //    return SW_FUNC_NOT_SUPPORTED();
            mbedtls_rsa_context rsa;
            mbedtls_rsa_init(&rsa);
            r = mbedtls_rsa_gen_key(&rsa, random_fill_iterator, NULL, nlen, exponent);
            if (r != 0) {
                mbedtls_rsa_free(&rsa);
                return SW_EXEC_ERROR();
            }
            make_rsa_response(&rsa);
            r = store_keypair(&rsa, ALGO_RSA, fid, res_APDU, res_APDU_size);
            mbedtls_rsa_free(&rsa);
            if (r != PICOKEYS_OK) {
                return SW_EXEC_ERROR();
            }
        }
        else if (algo[0] == ALGO_ECDH || algo[0] == ALGO_ECDSA || algo[0] == ALGO_EDDSA) {
            printf("KEYPAIR ECDSA\r\n");
            mbedtls_ecp_group_id gid = get_ec_group_id_from_attr(algo + 1, algo_len - 1);
            if (gid == MBEDTLS_ECP_DP_NONE) {
                return SW_FUNC_NOT_SUPPORTED();
            }
            mbedtls_ecp_keypair ecdsa;
            mbedtls_ecp_keypair_init(&ecdsa);
            r = mbedtls_ecdsa_genkey(&ecdsa, gid, random_fill_iterator, NULL);
            if (r != 0) {
                mbedtls_ecp_keypair_free(&ecdsa);
                return SW_EXEC_ERROR();
            }
            make_ecdsa_response(&ecdsa);
            r = store_keypair(&ecdsa, algo[0], fid, res_APDU, res_APDU_size);
            mbedtls_ecp_keypair_free(&ecdsa);
            if (r != PICOKEYS_OK) {
                return SW_EXEC_ERROR();
            }
        }
        else {
            return SW_FUNC_NOT_SUPPORTED();
        }
        if (fid == EF_PK_SIG) {
            reset_sig_count();
        }
        else if (fid == EF_PK_DEC) {
            // OpenPGP does not allow generating AES keys. So, we generate a new one when gen for DEC is called.
            // It is a 256 AES key by default.
            uint8_t aes_key[32]; //maximum AES key size
            uint8_t key_size = 32;
            memcpy(aes_key, random_bytes_get(key_size), key_size);
            r = store_keys(aes_key, ALGO_AES_256, EF_AES_KEY, true);
            mbedtls_platform_zeroize(aes_key, sizeof(aes_key));
            if (r != PICOKEYS_OK) {
                return SW_EXEC_ERROR();
            }
        }
        flash_commit();
        return SW_OK();
    }
    else if (P1(apdu) == 0x81) { //read
        file_t *private_ef = file_search_by_fid(fid, NULL, SPECIFY_EF);
        if (openpgp_key_container_is_marker(private_ef)) {
            uint32_t public_size = 0;
            if (openpgp_key_container_public_size(fid, &public_size) != PICOKEYS_OK || public_size > OPENPGP_MAX_RESPONSE_SIZE) {
                return SW_REFERENCE_NOT_FOUND();
            }
            size_t written = 0;
            if (openpgp_key_container_read_public(fid, res_APDU, public_size, &written) != PICOKEYS_OK || written != public_size) {
                return SW_EXEC_ERROR();
            }
            res_APDU_size = (uint16_t)written;
            return SW_OK();
        }
        file_t *ef = file_search_by_fid(fid + 3, NULL, SPECIFY_EF);
        if (!file_has_data(ef)) {
            return SW_REFERENCE_NOT_FOUND();
        }
        res_APDU_size = MIN(file_get_size(ef), OPENPGP_MAX_RESPONSE_SIZE);
        memcpy(res_APDU, file_get_data(ef), res_APDU_size);
        return SW_OK();
    }
    return SW_INCORRECT_P1P2();
}
