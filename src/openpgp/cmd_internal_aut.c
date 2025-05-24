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

#include "openpgp.h"
#include "do.h"

int cmd_internal_aut() {
    if (P1(apdu) != 0x00 || P2(apdu) != 0x00) {
        return SW_WRONG_P1P2();
    }
    if (!has_pw3 && !has_pw2) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    file_t *algo_ef = search_by_fid(algo_aut, NULL, SPECIFY_EF);
    if (!algo_ef) {
        return SW_REFERENCE_NOT_FOUND();
    }
    const uint8_t *algo = algorithm_attr_rsa2k + 1;
    if (algo_ef && algo_ef->data) {
        algo = file_get_data(algo_ef);
    }
    file_t *ef = search_by_fid(pk_aut, NULL, SPECIFY_EF);
    if (!ef) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (wait_button_pressed_fid(EF_UIF_AUT) == true) {
        return SW_SECURE_MESSAGE_EXEC_ERROR();
    }
    int r = PICOKEY_OK;
    if (algo[0] == ALGO_RSA) {
        mbedtls_rsa_context ctx;
        mbedtls_rsa_init(&ctx);
        r = load_private_key_rsa(&ctx, ef, true);
        if (r != PICOKEY_OK) {
            mbedtls_rsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        size_t olen = 0;
        r = rsa_sign(&ctx, apdu.data, apdu.nc, res_APDU, &olen);
        mbedtls_rsa_free(&ctx);
        if (r != 0) {
            return SW_EXEC_ERROR();
        }
        res_APDU_size = olen;
    }
    else if (algo[0] == ALGO_ECDH || algo[0] == ALGO_ECDSA || algo[0] == ALGO_EDDSA) {
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
    }
    return SW_OK();
}
