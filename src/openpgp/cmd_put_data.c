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

static bool put_data_authorized(uint16_t fid) {
    if (fid == EF_PRIV_DO_1 || fid == EF_PRIV_DO_3) {
        return has_pw2;
    }
    return has_pw3;
}

static uint16_t fixed_do_max_size(uint16_t fid) {
    switch (fid) {
    case EF_FP_SIG:
    case EF_FP_DEC:
    case EF_FP_AUT:
    case EF_FP_CA1:
    case EF_FP_CA2:
    case EF_FP_CA3:
        return OPENPGP_FINGERPRINT_SIZE;
    case EF_TS_SIG:
    case EF_TS_DEC:
    case EF_TS_AUT:
        return OPENPGP_TIMESTAMP_SIZE;
    default:
        return 0;
    }
}

int cmd_put_data(void) {
    uint16_t fid = (P1(apdu) << 8) | P2(apdu);
    uint16_t requested_fid = fid;
    bool is_algorithm_attr = fid == EF_ALGO_SIG || fid == EF_ALGO_DEC || fid == EF_ALGO_AUT;
    file_t *ef;

    if (!put_data_authorized(requested_fid)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }

    uint16_t max_size = fixed_do_max_size(requested_fid);
    if (max_size != 0 && apdu.nc > max_size) {
        return SW_WRONG_DATA();
    }

    if (fid == EF_RESET_CODE) {
        fid = EF_RC;
    }
    else if (is_algorithm_attr) {
        fid |= 0x1000;
    }
    if (is_algorithm_attr && apdu.nc > 0 &&
        (apdu.nc > OPENPGP_MAX_ALGORITHM_ATTR_SIZE ||
         (apdu.data[0] == ALGO_RSA && apdu.nc < 3))) {
        return SW_WRONG_DATA();
    }
    if (fid == EF_CH_NAME && apdu.nc > 39u) {
        return SW_WRONG_DATA();
    }
    if (fid == EF_LANG_PREF && apdu.nc > 8u) {
        return SW_WRONG_DATA();
    }
    if (fid == EF_SEX && (apdu.nc > 1u || (apdu.nc > 0u && memchr("0129", apdu.data[0], 4) == NULL))) {
        return SW_WRONG_DATA();
    }
    if (!(ef = file_search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_WRONG_P1P2();
    }
    if (!file_authenticate_action(ef, ACL_OP_UPDATE_ERASE)) {
        return SW_WRONG_P1P2();
    }
    if (fid == EF_PW_STATUS) {
        if (apdu.nc != 1 || apdu.data[0] > 1) {
            return SW_WRONG_DATA();
        }
        fid = EF_PW_PRIV;
        if (!(ef = file_search_by_fid(fid, NULL, SPECIFY_EF))) {
            return SW_REFERENCE_NOT_FOUND();
        }
    }
    if (requested_fid == EF_CH_CERT) {
        if (currentEF && currentEF->fid >= EF_CH_1 && currentEF->fid <= EF_CH_3) {
            ef = currentEF;
        }
        else if (!(ef = file_search_by_fid(EF_CH_1, NULL, SPECIFY_EF))) {
            return SW_REFERENCE_NOT_FOUND();
        }
        fid = ef->fid;
    }
    else if (currentEF && currentEF->fid == fid) { // previously selected same EF
        ef = currentEF;
    }
    if (file_get_type(ef) & FILE_DATA_FLASH) {
        int r = 0;
        if (apdu.nc > 0) {
            if (requested_fid == EF_PW_STATUS) {
                uint8_t pw_status[7] = { 0x1, 127, 127, 127, 3, 0, 3 };
                if (file_has_data(ef)) {
                    memset(pw_status, 0, sizeof(pw_status));
                    uint16_t status_len = MIN(file_get_size(ef), sizeof(pw_status));
                    memcpy(pw_status, file_get_data(ef), status_len);
                }
                pw_status[0] = apdu.data[0];
                r = file_put_data(ef, CONST_BYTE_ARRAY(pw_status, sizeof(pw_status)));
            }
            else if (fid == EF_RC) {
                if (check_pin_len(EF_RC, apdu.nc) != 0x9000) {
                    return SW_WRONG_DATA();
                }
                has_rc = false;
                if ((r = load_dek()) != PICOKEYS_OK) {
                    return SW_EXEC_ERROR();
                }
                uint8_t dhash[34];
                dhash[0] = apdu.nc;
                dhash[1] = 0x1; // Format
                pin_derive_verifier(CONST_BYTE_ARRAY(apdu.data, apdu.nc), dhash + 2);
                if ((r = file_put_data(ef, CONST_BYTE_ARRAY(dhash, sizeof(dhash)))) != PICOKEYS_OK) {
                    return SW_MEMORY_FAILURE();
                }

                file_t *tf = file_search_by_fid(EF_DEK_RC, NULL, SPECIFY_EF);
                if (!tf) {
                    return SW_REFERENCE_NOT_FOUND();
                }

                uint8_t def[DEK_FILE_SIZE];
                def[0] = 0x3;
                pin_derive_session(CONST_BYTE_ARRAY(apdu.data, apdu.nc), session_rc);
                if ((r = encrypt_with_aad(session_rc, CONST_BYTE_ARRAY(dek, DEK_SIZE), PIN_KDF_DEFAULT_VERSION, def + 1)) != PICOKEYS_OK) {
                    return SW_EXEC_ERROR();
                }
                r = file_put_data(tf, CONST_BYTE_ARRAY(def, sizeof(def)));
                if (r == PICOKEYS_OK) {
                    r = pin_reset_retries(ef, true);
                }
            }
            else {
                r = file_put_data(ef, CONST_BYTE_ARRAY(apdu.data, apdu.nc));
            }
            if (r != PICOKEYS_OK) {
                return SW_MEMORY_FAILURE();
            }
#ifdef ENABLE_ADMINLESS_MODE
            if (requested_fid == EF_KDF && apdu.nc > 0 && !(apdu.nc == 3 && memcmp(apdu.data, "\x81\x01\x00", 3) == 0)) {
                if ((r = openpgp_adminless_begin_kdf_migration()) != PICOKEYS_OK) {
                    return SW_MEMORY_FAILURE();
                }
            }
#endif
            flash_commit();
        }
        else {
            r = fid == EF_RC ? openpgp_reset_code_deactivate() : flash_clear_file(ef);
            if (r != PICOKEYS_OK) {
                return SW_MEMORY_FAILURE();
            }
            flash_commit();
        }
    }
    return SW_OK();
}
