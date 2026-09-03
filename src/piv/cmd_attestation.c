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


int cmd_attestation(void) {
    uint8_t key_ref = P1(apdu);
    if (P2(apdu) != 0x00) {
        return SW_INCORRECT_P1P2();
    }
    if (!IS_KEY(key_ref)) {
        return SW_REFERENCE_NOT_FOUND();
    }
    file_t *ef_key = NULL;
    byte_array_t metadata = meta_find(key_ref);
    uint8_t *meta = metadata.data;
    if (!(ef_key = file_search_by_fid(key_ref == 0x93 ? EF_PIV_KEY_RETIRED18 : key_ref, NULL, SPECIFY_EF)) || !file_has_data(ef_key)) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!meta) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (meta[3] != ORIGIN_GENERATED) {
        return SW_INCORRECT_PARAMS();
    }
    int r = 0;
    uint8_t abuf[2048];
    if (meta[0] == PIV_ALGO_RSA1024 || meta[0] == PIV_ALGO_RSA2048) {
        mbedtls_rsa_context ctx;
        mbedtls_rsa_init(&ctx);
        r = load_private_key_rsa(&ctx, ef_key, false);
        if (r != PICOKEYS_OK) {
            mbedtls_rsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        r = x509_create_cert(&ctx, meta[0], key_ref, true, abuf, sizeof(abuf));
        mbedtls_rsa_free(&ctx);
    }
    else if (meta[0] == PIV_ALGO_ECCP256 || meta[0] == PIV_ALGO_ECCP384) {
        mbedtls_ecdsa_context ctx;
        mbedtls_ecdsa_init(&ctx);
        r = load_private_key_ecdsa(&ctx, ef_key, false);
        if (r != PICOKEYS_OK) {
            mbedtls_ecdsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        r = x509_create_cert(&ctx, meta[0], key_ref, true, abuf, sizeof(abuf));
        mbedtls_ecdsa_free(&ctx);
    }
    else {
        return SW_WRONG_DATA();
    }
    if (r <= 0) {
        return SW_EXEC_ERROR();
    }
    memcpy(res_APDU, abuf + sizeof(abuf) - r, r);
    res_APDU_size = r;
    return SW_OK();
}
