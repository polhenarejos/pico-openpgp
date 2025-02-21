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
#include "random.h"
#include "do.h"

uint16_t tag_len(uint8_t **data) {
    size_t len = *(*data)++;
    if (len == 0x82) {
        len = *(*data)++ << 8;
        len |= *(*data)++;
    }
    else if (len == 0x81) {
        len = *(*data)++;
    }
    return len;
}

int cmd_import_data() {
    file_t *ef = NULL;
    uint16_t fid = 0x0;
    if (P1(apdu) != 0x3F || P2(apdu) != 0xFF) {
        return SW_WRONG_P1P2();
    }
    if (apdu.nc < 5) {
        return SW_WRONG_LENGTH();
    }
    uint8_t *start = apdu.data;
    if (*start++ != 0x4D) {
        return SW_WRONG_DATA();
    }
    uint16_t tgl = tag_len(&start);
    if (*start != 0xB6 && *start != 0xB8 && *start != 0xA4) {
        return SW_WRONG_DATA();
    }
    if (*start == 0xB6) {
        fid = EF_PK_SIG;
    }
    else if (*start == 0xB8) {
        fid = EF_PK_DEC;
    }
    else if (*start == 0xA4) {
        fid = EF_PK_AUT;
    }
    else {
        return SW_WRONG_DATA();
    }
    start++;
    if (!(ef = search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!authenticate_action(ef, ACL_OP_UPDATE_ERASE)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    start += (*start + 1);
    if (*start++ != 0x7F || *start++ != 0x48) {
        return SW_WRONG_DATA();
    }
    tgl = tag_len(&start);
    uint8_t *end = start + tgl, *p[9] = { 0 };
    uint16_t len[9] = { 0 };
    while (start < end) {
        uint8_t tag = *start++;
        if ((tag >= 0x91 && tag <= 0x97) || tag == 0x99) {
            len[tag - 0x91] = tag_len(&start);
        }
        else {
            return SW_WRONG_DATA();
        }
    }
    if (*start++ != 0x5F || *start++ != 0x48) {
        return SW_WRONG_DATA();
    }
    tgl = tag_len(&start);
    end = start + tgl;
    for (int t = 0; start < end && t < 9; t++) {
        if (len[t] > 0) {
            p[t] = start;
            start += len[t];
        }
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
    int r = 0;
    if (algo[0] == ALGO_RSA) {
        mbedtls_rsa_context rsa;
        if (p[0] == NULL || len[0] == 0 || p[1] == NULL || len[1] == 0 || p[2] == NULL ||
            len[2] == 0) {
            return SW_WRONG_DATA();
        }
        mbedtls_rsa_init(&rsa);
        r = mbedtls_mpi_read_binary(&rsa.E, p[0], len[0]);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_EXEC_ERROR();
        }
        r = mbedtls_mpi_read_binary(&rsa.P, p[1], len[1]);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_EXEC_ERROR();
        }
        r = mbedtls_mpi_read_binary(&rsa.Q, p[2], len[2]);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_EXEC_ERROR();
        }
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
        r = store_keys(&rsa, ALGO_RSA, fid, true);
        make_rsa_response(&rsa);
        mbedtls_rsa_free(&rsa);
        if (r != PICOKEY_OK) {
            return SW_EXEC_ERROR();
        }
    }
    else if (algo[0] == ALGO_ECDSA || algo[0] == ALGO_ECDH || algo[0] == ALGO_EDDSA) {
        mbedtls_ecp_keypair ecdsa;
        if (p[1] == NULL || len[1] == 0) {
            return SW_WRONG_DATA();
        }
        mbedtls_ecp_group_id gid = get_ec_group_id_from_attr(algo + 1, algo_len - 1);
        if (gid == MBEDTLS_ECP_DP_NONE) {
            return SW_FUNC_NOT_SUPPORTED();
        }
        mbedtls_ecp_keypair_init(&ecdsa);
        if (gid == MBEDTLS_ECP_DP_CURVE25519) {
            mbedtls_ecp_group_load(&ecdsa.grp, gid);
            r = mbedtls_mpi_read_binary(&ecdsa.d, p[1], len[1]);
        }
        else {
            r = mbedtls_ecp_read_key(gid, &ecdsa, p[1], len[1]);
        }
        if (r != 0) {
            mbedtls_ecp_keypair_free(&ecdsa);
            return SW_EXEC_ERROR();
        }
#ifdef MBEDTLS_EDDSA_C
        if (ecdsa.grp.id == MBEDTLS_ECP_DP_ED25519) {
            r = mbedtls_ecp_point_edwards(&ecdsa.grp, &ecdsa.Q, &ecdsa.d, random_gen, NULL);
        }
        else
#endif
        {
            r = mbedtls_ecp_mul(&ecdsa.grp, &ecdsa.Q, &ecdsa.d, &ecdsa.grp.G, random_gen, NULL);
        }
        if (r != 0) {
            mbedtls_ecp_keypair_free(&ecdsa);
            return SW_EXEC_ERROR();
        }
        r = store_keys(&ecdsa, ALGO_ECDSA, fid, true);
        make_ecdsa_response(&ecdsa);
        mbedtls_ecp_keypair_free(&ecdsa);
        if (r != PICOKEY_OK) {
            return SW_EXEC_ERROR();
        }
    }
    else {
        return SW_FUNC_NOT_SUPPORTED();
    }
    if (fid == EF_PK_SIG) {
        reset_sig_count();
    }
    file_t *pbef = search_by_fid(fid + 3, NULL, SPECIFY_EF);
    if (!pbef) {
        return SW_REFERENCE_NOT_FOUND();
    }
    r = file_put_data(pbef, res_APDU, res_APDU_size);
    if (r != PICOKEY_OK) {
        return SW_EXEC_ERROR();
    }
    res_APDU_size = 0; //make_*_response sets a response. we need to overwrite
    return SW_OK();
}
