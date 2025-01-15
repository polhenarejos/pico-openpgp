/*
 * This file is part of the Pico OpenPGP distribution (https://github.com/polhenarejos/pico-openpgp).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef ESP_PLATFORM
#include "esp_compat.h"
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#else
#include "common.h"
#endif
#include "openpgp.h"
#include "do.h"
#include "random.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/asn1.h"

int cmd_pso() {
    uint16_t algo_fid = 0x0, pk_fid = 0x0;
    bool is_aes = false;
    if (P1(apdu) == 0x9E && P2(apdu) == 0x9A) {
        if (!has_pw3 && !has_pw1) {
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
        algo_fid = EF_ALGO_PRIV1;
        pk_fid = EF_PK_SIG;
    }
    else if (P1(apdu) == 0x80 && P2(apdu) == 0x86) {
        if (!has_pw3 && !has_pw2) {
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
        algo_fid = algo_dec;
        pk_fid = pk_dec;
    }
    else {
        return SW_INCORRECT_P1P2();
    }
    file_t *algo_ef = search_by_fid(algo_fid, NULL, SPECIFY_EF);
    if (!algo_ef) {
        return SW_REFERENCE_NOT_FOUND();
    }
    const uint8_t *algo = algorithm_attr_rsa2k + 1;
    if (algo_ef && algo_ef->data) {
        algo = file_get_data(algo_ef);
    }
    if (apdu.data[0] == 0x2) { //AES PSO?
        if (((apdu.nc - 1) % 16 == 0 && P1(apdu) == 0x80 && P2(apdu) == 0x86) ||
            (apdu.nc % 16 == 0 && P1(apdu) == 0x86 && P2(apdu) == 0x80)) {
            pk_fid = EF_AES_KEY;
            is_aes = true;
        }
    }
    file_t *ef = search_by_fid(pk_fid, NULL, SPECIFY_EF);
    if (!ef) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (wait_button_pressed(pk_fid == EF_PK_SIG ? EF_UIF_SIG : EF_UIF_DEC) == true) {
        return SW_SECURE_MESSAGE_EXEC_ERROR();
    }
    int r = PICOKEY_OK;
    int key_size = file_get_size(ef);
    if (is_aes) {
        uint8_t aes_key[32];
        r = load_aes_key(aes_key, ef);
        if (r != PICOKEY_OK) {
            memset(aes_key, 0, sizeof(aes_key));
            return SW_EXEC_ERROR();
        }
        if (P1(apdu) == 0x80 && P2(apdu) == 0x86) { //decipher
            r = aes_decrypt(aes_key, NULL, key_size, PICO_KEYS_AES_MODE_CBC, apdu.data + 1, apdu.nc - 1);
            memset(aes_key, 0, sizeof(aes_key));
            if (r != PICOKEY_OK) {
                return SW_EXEC_ERROR();
            }
            memcpy(res_APDU, apdu.data + 1, apdu.nc - 1);
            res_APDU_size = apdu.nc - 1;
        }
        else if (P1(apdu) == 0x86 && P2(apdu) == 0x80) { //encipher
            r = aes_encrypt(aes_key, NULL, key_size, PICO_KEYS_AES_MODE_CBC, apdu.data, apdu.nc);
            memset(aes_key, 0, sizeof(aes_key));
            if (r != PICOKEY_OK) {
                return SW_EXEC_ERROR();
            }
            res_APDU[0] = 0x2;
            memcpy(res_APDU + 1, apdu.data, apdu.nc);
            res_APDU_size = apdu.nc + 1;
        }
        return SW_OK();
    }
    if (algo[0] == ALGO_RSA) {
        mbedtls_rsa_context ctx;
        mbedtls_rsa_init(&ctx);
        r = load_private_key_rsa(&ctx, ef, true);
        if (r != PICOKEY_OK) {
            mbedtls_rsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        if (P1(apdu) == 0x9E && P2(apdu) == 0x9A) {
            size_t olen = 0;
            r = rsa_sign(&ctx, apdu.data, apdu.nc, res_APDU, &olen);
            mbedtls_rsa_free(&ctx);
            if (r != 0) {
                return SW_EXEC_ERROR();
            }
            res_APDU_size = olen;
            //apdu.ne = key_size;
            inc_sig_count();
        }
        else if (P1(apdu) == 0x80 && P2(apdu) == 0x86) {
            if (apdu.nc < key_size) { //needs padding
                memset(apdu.data + apdu.nc, 0, key_size - apdu.nc);
            }
            size_t olen = 0;
            r = mbedtls_rsa_pkcs1_decrypt(&ctx,
                                          random_gen,
                                          NULL,
                                          &olen,
                                          apdu.data + 1,
                                          res_APDU,
                                          key_size);
            mbedtls_rsa_free(&ctx);
            if (r != 0) {
                return SW_EXEC_ERROR();
            }
            res_APDU_size = olen;
        }
    }
    else if (algo[0] == ALGO_ECDH || algo[0] == ALGO_ECDSA || algo[0] == ALGO_EDDSA) {
        if (P1(apdu) == 0x9E && P2(apdu) == 0x9A) {
            mbedtls_ecp_keypair ctx;
            mbedtls_ecp_keypair_init(&ctx);
            r = load_private_key_ecdsa(&ctx, ef, true);
            if (r != PICOKEY_OK) {
                mbedtls_ecp_keypair_free(&ctx);
                return SW_EXEC_ERROR();
            }
            size_t olen = 0;
            r = ecdsa_sign(&ctx, apdu.data, apdu.nc, res_APDU, &olen);
            mbedtls_ecp_keypair_free(&ctx);
            if (r != 0) {
                return SW_EXEC_ERROR();
            }
            res_APDU_size = olen;
            inc_sig_count();
        }
        else if (P1(apdu) == 0x80 && P2(apdu) == 0x86) {
            mbedtls_ecdh_context ctx;
            uint8_t kdata[67];
            uint8_t *data = apdu.data, *end = data + apdu.nc;
            size_t len = 0;
            if (mbedtls_asn1_get_tag(&data, end, &len, 0xA6) != 0) {
                return SW_WRONG_DATA();
            }
            if (*data++ != 0x7f) {
                return SW_WRONG_DATA();
            }
            if (mbedtls_asn1_get_tag(&data, end, &len,
                                     0x49) != 0 ||
                mbedtls_asn1_get_tag(&data, end, &len, 0x86) != 0) {
                return SW_WRONG_DATA();
            }
            //if (len != 2*key_size-1)
            //    return SW_WRONG_LENGTH();
            memcpy(kdata, file_get_data(ef), key_size);
            if (dek_decrypt(kdata, key_size) != 0) {
                return SW_EXEC_ERROR();
            }
            mbedtls_ecdh_init(&ctx);
            mbedtls_ecp_group_id gid = kdata[0];
            r = mbedtls_ecdh_setup(&ctx, gid);
            if (r != 0) {
                mbedtls_ecdh_free(&ctx);
                return SW_DATA_INVALID();
            }
            r = mbedtls_ecp_read_key(gid, (mbedtls_ecdsa_context *)&ctx.ctx.mbed_ecdh, kdata + 1, key_size - 1);
            if (r != 0) {
                mbedtls_ecdh_free(&ctx);
                return SW_DATA_INVALID();
            }
            r = mbedtls_ecdh_read_public(&ctx, data - 1, len + 1);
            if (r != 0) {
                mbedtls_ecdh_free(&ctx);
                return SW_DATA_INVALID();
            }
            size_t olen = 0;
            r = mbedtls_ecdh_calc_secret(&ctx,
                                         &olen,
                                         res_APDU,
                                         MBEDTLS_ECP_MAX_BYTES,
                                         random_gen,
                                         NULL);
            if (r != 0) {
                mbedtls_ecdh_free(&ctx);
                return SW_EXEC_ERROR();
            }
            res_APDU_size = olen;
            mbedtls_ecdh_free(&ctx);
        }
    }
    return SW_OK();
}
