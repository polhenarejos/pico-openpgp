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

int cmd_put_data(void) {
    uint16_t fid = (P1(apdu) << 8) | P2(apdu);
    uint16_t requested_fid = fid;
    bool is_algorithm_attr = fid == EF_ALGO_SIG || fid == EF_ALGO_DEC || fid == EF_ALGO_AUT;
    file_t *ef;
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
    if (!(ef = file_search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!file_authenticate_action(ef, ACL_OP_UPDATE_ERASE)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if ((fid == EF_PRIV_DO_1 || fid == EF_PRIV_DO_3) && (!has_pw2 && !has_pw3)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (!(fid == EF_PRIV_DO_1 || fid == EF_PRIV_DO_3) && !has_pw3) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (fid == EF_PW_STATUS) {
        fid = EF_PW_PRIV;
        if (apdu.nc == 0) {
            return SW_WRONG_LENGTH();
        }
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
    if (ef->type & FILE_DATA_FLASH) {
        int r = 0;
        if (apdu.nc > 0) {
            if (requested_fid == EF_PW_STATUS) {
                uint8_t pw_status[7] = { 0x1, 127, 127, 127, 3, 3, 3 };
                if (file_has_data(ef)) {
                    memset(pw_status, 0, sizeof(pw_status));
                    uint16_t status_len = MIN(file_get_size(ef), sizeof(pw_status));
                    memcpy(pw_status, file_get_data(ef), status_len);
                }
                memcpy(pw_status, apdu.data, MIN(apdu.nc, 4u));
                r = file_put_data(ef, pw_status, sizeof(pw_status));
            }
            else if (fid == EF_RC) {
                has_rc = false;
                if ((r = load_dek()) != PICOKEYS_OK) {
                    return SW_EXEC_ERROR();
                }
                uint8_t dhash[34];
                dhash[0] = apdu.nc;
                dhash[1] = 0x1; // Format
                pin_derive_verifier(apdu.data, apdu.nc, dhash + 2);
                file_put_data(ef, dhash, sizeof(dhash));

                file_t *tf = file_search_by_fid(EF_DEK_RC, NULL, SPECIFY_EF);
                if (!tf) {
                    return SW_REFERENCE_NOT_FOUND();
                }

                uint8_t def[DEK_FILE_SIZE];
                def[0] = 0x3;
                pin_derive_session(apdu.data, apdu.nc, session_rc);
                encrypt_with_aad(session_rc, dek, DEK_SIZE, PIN_KDF_DEFAULT_VERSION, def + 1);
                r = file_put_data(tf, def, sizeof(def));
            }
            else {
                r = file_put_data(ef, apdu.data, apdu.nc);
            }
            if (r != PICOKEYS_OK) {
                return SW_MEMORY_FAILURE();
            }
            flash_commit();
        }
        else {
            if (flash_clear_file(ef) != PICOKEYS_OK) {
                return SW_MEMORY_FAILURE();
            }
            flash_commit();
        }
    }
    return SW_OK();
}
