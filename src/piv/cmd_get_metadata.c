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


int cmd_get_metadata(void) {
    if (P1(apdu) != 0x00) {
        return SW_INCORRECT_P1P2();
    }
    uint16_t key_ref = P2(apdu);
    if (key_ref == 0x80) {
        key_ref = EF_PIV_PIN;
    }
    else if (key_ref == 0x81) {
        key_ref = EF_PIV_PUK;
    }
    else if (key_ref == 0xF9) {
        key_ref = EF_PIV_KEY_ATTESTATION;
    }
    uint16_t key_fid = key_ref == 0x93 ? EF_PIV_KEY_RETIRED18 : key_ref;
    byte_array_t metadata = meta_find(key_ref);
    uint8_t *meta = metadata.data;
    file_t *ef_key = file_search_by_fid(key_fid, NULL, SPECIFY_EF);
    if (!file_has_data(ef_key)) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (key_ref != EF_PIV_PIN && key_ref != EF_PIV_PUK) {
        uint8_t attestation_meta[] = {PIV_ALGO_ECCP384, PINPOLICY_ONCE, TOUCHPOLICY_NEVER, ORIGIN_GENERATED};
        if (!meta && key_ref == EF_PIV_KEY_ATTESTATION) {
            meta = attestation_meta;
        }
        if (!meta) {
            return SW_REFERENCE_NOT_FOUND();
        }
        res_APDU[res_APDU_size++] = 0x1;
        res_APDU[res_APDU_size++] = 1;
        res_APDU[res_APDU_size++] = meta[0];
        res_APDU[res_APDU_size++] = 0x2;
        res_APDU[res_APDU_size++] = 2;
        res_APDU[res_APDU_size++] = meta[1];
        res_APDU[res_APDU_size++] = meta[2];
        if (key_ref != EF_PIV_KEY_CARDMGM) {
            res_APDU[res_APDU_size++] = 0x3;
            res_APDU[res_APDU_size++] = 1;
            res_APDU[res_APDU_size++] = meta[3];
            if (meta[0] == PIV_ALGO_RSA1024 || meta[0] == PIV_ALGO_RSA2048 || meta[0] == PIV_ALGO_RSA3072 || meta[0] == PIV_ALGO_RSA4096 || meta[0] == PIV_ALGO_ECCP256 || meta[0] == PIV_ALGO_ECCP384) {
                res_APDU[res_APDU_size++] = 0x4;
                res_APDU[res_APDU_size++] = 0; // Filled later
                uint8_t *pk = &res_APDU[res_APDU_size];
                if (meta[0] == PIV_ALGO_RSA1024 || meta[0] == PIV_ALGO_RSA2048 || meta[0] == PIV_ALGO_RSA3072 || meta[0] == PIV_ALGO_RSA4096) {
                    mbedtls_rsa_context ctx;
                    mbedtls_rsa_init(&ctx);
                    int r = load_private_key_rsa(&ctx, ef_key, false);
                    if (r != PICOKEYS_OK) {
                        mbedtls_rsa_free(&ctx);
                        return SW_EXEC_ERROR();
                    }
                    res_APDU[res_APDU_size++] = 0x81;
                    res_APDU[res_APDU_size++] = 0x82;
                    put_uint16_be(mbedtls_mpi_size(&ctx.N), res_APDU + res_APDU_size); res_APDU_size += 2;
                    mbedtls_mpi_write_binary(&ctx.N, res_APDU + res_APDU_size, mbedtls_mpi_size(&ctx.N));
                    res_APDU_size += mbedtls_mpi_size(&ctx.N);
                    res_APDU[res_APDU_size++] = 0x82;
                    res_APDU[res_APDU_size++] = mbedtls_mpi_size(&ctx.E) & 0xff;
                    mbedtls_mpi_write_binary(&ctx.E, res_APDU + res_APDU_size, mbedtls_mpi_size(&ctx.E));
                    res_APDU_size += mbedtls_mpi_size(&ctx.E);
                    mbedtls_rsa_free(&ctx);
                }
                else {
                    mbedtls_ecdsa_context ctx;
                    mbedtls_ecdsa_init(&ctx);
                    int r = load_private_key_ecdsa(&ctx, ef_key, false);
                    if (r != PICOKEYS_OK) {
                        mbedtls_ecdsa_free(&ctx);
                        return SW_EXEC_ERROR();
                    }
                    uint8_t pt[MBEDTLS_ECP_MAX_PT_LEN];
                    size_t plen = 0;
                    mbedtls_ecp_point_write_binary(&ctx.grp, &ctx.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &plen, pt, sizeof(pt));
                    mbedtls_ecdsa_free(&ctx);
                    res_APDU[res_APDU_size++] = 0x86;
                    if (plen >= 128) {
                        res_APDU[res_APDU_size++] = 0x81;
                    }
                    res_APDU[res_APDU_size++] = plen;
                    memcpy(res_APDU + res_APDU_size, pt, plen);
                    res_APDU_size += plen;
                }
                uint16_t pk_len = res_APDU_size - (pk - res_APDU);
                if (pk_len > 255) {
                    memmove(pk + 2, pk, pk_len);
                    pk[-1] = 0x82;
                    pk[0] = pk_len >> 8;
                    pk[1] = pk_len & 0xff;
                    res_APDU_size += 2;
                }
                else if (pk_len > 127) {
                    memmove(pk + 1, pk, pk_len);
                    pk[-1] = 0x81;
                    pk[0] = pk_len;
                    res_APDU_size += 1;
                }
                else {
                    pk[-1] = pk_len;
                }
            }
        }
    }
    if (key_ref == EF_PIV_PIN || key_ref == EF_PIV_PUK || key_ref == EF_PIV_KEY_CARDMGM) {
        uint8_t dhash[32];
        int32_t eq = 0;
        bool is_default;
        if (key_ref == EF_PIV_PIN) {
            pin_derive_verifier(CONST_BYTE_ARRAY((const uint8_t *)"\x31\x32\x33\x34\x35\x36\xFF\xFF", 8), dhash);
            eq = file_get_size(ef_key) == 34u && file_get_data(ef_key)[1] == 1u ? mbedtls_ct_memcmp(dhash, file_get_data(ef_key) + 2, sizeof(dhash)) : -1;
        }
        else if (key_ref == EF_PIV_PUK) {
            pin_derive_verifier(CONST_BYTE_ARRAY((const uint8_t *)"\x31\x32\x33\x34\x35\x36\x37\x38", 8), dhash);
            eq = file_get_size(ef_key) == 34u && file_get_data(ef_key)[1] == 1u ? mbedtls_ct_memcmp(dhash, file_get_data(ef_key) + 2, sizeof(dhash)) : -1;
        }
        else if (key_ref == EF_PIV_KEY_CARDMGM) {
            uint8_t management_key[32] = { 0 };
            byte_buffer_t management_key_data = BYTE_BUFFER(management_key, sizeof(management_key));
            int r = openpgp_key_container_is_marker(ef_key) ? openpgp_key_container_read_private(EF_PIV_KEY_CARDMGM, FILE_OBJECT_OPERATION_USE, true, &management_key_data) : PICOKEYS_OK;
            size_t management_key_size = management_key_data.len;
            if (!openpgp_key_container_is_marker(ef_key)) {
                management_key_size = MIN(file_get_size(ef_key), sizeof(management_key));
                memcpy(management_key, file_get_data(ef_key), management_key_size);
            }
            eq = r == PICOKEYS_OK && management_key_size == sizeof(piv_management_key_default) ? mbedtls_ct_memcmp(piv_management_key_default, management_key, management_key_size) : -1;
            mbedtls_platform_zeroize(management_key, sizeof(management_key));
        }
        is_default = eq == 0;
        if (key_ref == EF_PIV_KEY_CARDMGM) {
            is_default = is_default & (meta[2] == TOUCHPOLICY_NEVER);
        }
        if (key_ref == EF_PIV_PIN || key_ref == EF_PIV_PUK) {
            res_APDU[res_APDU_size++] = 0x1;
            res_APDU[res_APDU_size++] = 0x1;
            res_APDU[res_APDU_size++] = PIV_ALGO_PIN;
        }
        res_APDU[res_APDU_size++] = 0x5;
        res_APDU[res_APDU_size++] = 1;
        res_APDU[res_APDU_size++] = is_default;
        if (key_ref == EF_PIV_PIN || key_ref == EF_PIV_PUK) {
            file_t *pw_status;
            if (!(pw_status = file_search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF))) {
                return SW_REFERENCE_NOT_FOUND();
            }
            uint8_t retries = *(file_get_data(pw_status) + 3 + (key_ref & 0xf));
            if (!(pw_status = file_search_by_fid(EF_PW_RETRIES, NULL, SPECIFY_EF))) {
                return SW_REFERENCE_NOT_FOUND();
            }
            uint8_t total = *(file_get_data(pw_status) + (key_ref & 0xf));
            res_APDU[res_APDU_size++] = 0x6;
            res_APDU[res_APDU_size++] = 2;
            res_APDU[res_APDU_size++] = total;
            res_APDU[res_APDU_size++] = retries;
        }
    }
    return SW_OK();
}
