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

#include "openpgp.h"
#include "do.h"
#include "random.h"

int cmd_keypair_gen() {
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
    int r = PICOKEY_OK;
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

    file_t *algo_ef = search_by_fid(fid - 0x0010, NULL, SPECIFY_EF);
    if (!algo_ef) {
        return SW_REFERENCE_NOT_FOUND();
    }
    const uint8_t *algo = algorithm_attr_rsa2k + 1;
    uint16_t algo_len = algorithm_attr_rsa2k[0];
    if (algo_ef && algo_ef->data) {
        algo = file_get_data(algo_ef);
        algo_len = file_get_size(algo_ef);
    }
    if (P1(apdu) == 0x80) { //generate
        if (algo[0] == ALGO_RSA) {
            int exponent = 65537, nlen = (algo[1] << 8) | algo[2];
            printf("KEYPAIR RSA %d\r\n", nlen);
            //if (nlen != 2048 && nlen != 4096)
            //    return SW_FUNC_NOT_SUPPORTED();
            mbedtls_rsa_context rsa;
            mbedtls_rsa_init(&rsa);
            uint8_t index = 0;
            r = mbedtls_rsa_gen_key(&rsa, random_gen, &index, nlen, exponent);
            if (r != 0) {
                mbedtls_rsa_free(&rsa);
                return SW_EXEC_ERROR();
            }
            r = store_keys(&rsa, ALGO_RSA, fid, true);
            make_rsa_response(&rsa);
            mbedtls_rsa_free(&rsa);
            if (r != PICOKEY_OK) {
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
            uint8_t index = 0;
            r = mbedtls_ecdsa_genkey(&ecdsa, gid, random_gen, &index);
            if (r != 0) {
                mbedtls_ecp_keypair_free(&ecdsa);
                return SW_EXEC_ERROR();
            }
            r = store_keys(&ecdsa, algo[0], fid, true);
            make_ecdsa_response(&ecdsa);
            mbedtls_ecp_keypair_free(&ecdsa);
            if (r != PICOKEY_OK) {
                return SW_EXEC_ERROR();
            }
        }
        else {
            return SW_FUNC_NOT_SUPPORTED();
        }
        file_t *pbef = search_by_fid(fid + 3, NULL, SPECIFY_EF);
        if (!pbef) {
            return SW_REFERENCE_NOT_FOUND();
        }
        r = file_put_data(pbef, res_APDU, res_APDU_size);
        if (r != PICOKEY_OK) {
            return SW_EXEC_ERROR();
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
            /* if storing the key fails, we silently continue */
            //if (r != PICOKEY_OK)
            //    return SW_EXEC_ERROR();
        }
        low_flash_available();
        return SW_OK();
    }
    else if (P1(apdu) == 0x81) { //read
        file_t *ef = search_by_fid(fid + 3, NULL, SPECIFY_EF);
        if (!file_has_data(ef)) {
            return SW_REFERENCE_NOT_FOUND();
        }
        res_APDU_size = file_get_size(ef);
        memcpy(res_APDU, file_get_data(ef), res_APDU_size);
        return SW_OK();
    }
    return SW_INCORRECT_P1P2();
}
