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

#ifdef ESP_PLATFORM
#include "esp_compat.h"
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#endif
#include "openpgp.h"
#include "random.h"
#include "do.h"

static bool tag_len(uint8_t **data, const uint8_t *end, uint16_t *len_out) {
    if (*data >= end) {
        return false;
    }
    size_t len = *(*data)++;
    if (len == 0x82) {
        if ((size_t)(end - *data) < 2) {
            return false;
        }
        len = *(*data)++ << 8;
        len |= *(*data)++;
    }
    else if (len == 0x81) {
        if (*data >= end) {
            return false;
        }
        len = *(*data)++;
    }
    *len_out = (uint16_t) len;
    return true;
}

int cmd_import_data(void) {
    uint16_t fid = 0x0;
    if (P1(apdu) != 0x3F || P2(apdu) != 0xFF) {
        return SW_WRONG_P1P2();
    }
    if (apdu.nc < 5) {
        return SW_WRONG_LENGTH();
    }
    if (!has_pw3) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    uint8_t *start = apdu.data;
    uint8_t *apdu_end = apdu.data + apdu.nc;
    if (*start++ != 0x4D) {
        return SW_WRONG_DATA();
    }
    uint16_t tgl = 0;
    if (!tag_len(&start, apdu_end, &tgl) || (size_t)(apdu_end - start) < tgl) {
        return SW_WRONG_DATA();
    }
    uint8_t *outer_end = start + tgl;
    if (start >= outer_end) {
        return SW_WRONG_DATA();
    }
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
    if (start >= outer_end || (size_t)(outer_end - start) < (size_t)*start + 1u) {
        return SW_WRONG_DATA();
    }
    start += (*start + 1);
    if ((size_t)(outer_end - start) < 2 || *start++ != 0x7F || *start++ != 0x48) {
        return SW_WRONG_DATA();
    }
    if (!tag_len(&start, outer_end, &tgl) || (size_t)(outer_end - start) < tgl) {
        return SW_WRONG_DATA();
    }
    uint8_t *end = start + tgl, *p[9] = { 0 };
    uint16_t len[9] = { 0 };
    while (start < end) {
        uint8_t tag = *start++;
        if ((tag >= 0x91 && tag <= 0x97) || tag == 0x99) {
            if (!tag_len(&start, end, &len[tag - 0x91])) {
                return SW_WRONG_DATA();
            }
        }
        else {
            return SW_WRONG_DATA();
        }
    }
    if ((size_t)(outer_end - start) < 2 || *start++ != 0x5F || *start++ != 0x48) {
        return SW_WRONG_DATA();
    }
    if (!tag_len(&start, outer_end, &tgl) || (size_t)(outer_end - start) < tgl) {
        return SW_WRONG_DATA();
    }
    end = start + tgl;
    for (int t = 0; start < end && t < 9; t++) {
        if (len[t] > 0) {
            if ((size_t)(end - start) < len[t]) {
                return SW_WRONG_DATA();
            }
            p[t] = start;
            start += len[t];
        }
    }
    if (start != end) {
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
    int r = 0;
    if (algo[0] == ALGO_RSA) {
        if (algo_len < 3) {
            return SW_WRONG_DATA();
        }
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
        if ((size_t)mbedtls_rsa_get_len(&rsa) * 8u != (size_t)((algo[1] << 8) | algo[2])) {
            mbedtls_rsa_free(&rsa);
            return SW_WRONG_DATA();
        }
        make_rsa_response(&rsa);
        r = store_keypair(&rsa, ALGO_RSA, fid, res_APDU, res_APDU_size);
        mbedtls_rsa_free(&rsa);
        if (r != PICOKEYS_OK) {
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
        r = mbedtls_ecp_keypair_calc_public(&ecdsa, random_fill_iterator, NULL);
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
    res_APDU_size = 0; //make_*_response sets a response. we need to overwrite
    return SW_OK();
}
