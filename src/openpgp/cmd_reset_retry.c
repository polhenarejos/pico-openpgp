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
#include "otp.h"

int cmd_reset_retry() {
    if (P2(apdu) != 0x81) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (P1(apdu) == 0x0 || P1(apdu) == 0x2) {
        int newpin_len = 0;
        file_t *pw = NULL;
        has_pw1 = false;
        if (!(pw = search_by_fid(EF_PW1, NULL, SPECIFY_EF))) {
            return SW_REFERENCE_NOT_FOUND();
        }
        if (P1(apdu) == 0x0) {
            file_t *rc;
            if (!(rc = search_by_fid(EF_RC, NULL, SPECIFY_EF))) {
                return SW_REFERENCE_NOT_FOUND();
            }
            uint8_t pin_len = file_get_data(rc)[0];
            if (apdu.nc <= pin_len) {
                return SW_WRONG_LENGTH();
            }
            uint16_t r = check_pin(rc, apdu.data, pin_len);
            if (r != 0x9000) {
                return r;
            }
            newpin_len = apdu.nc - pin_len;
            has_rc = true;
            hash_multi(apdu.data, pin_len, session_rc);
            has_pw1 = has_pw3 = false;
            isUserAuthenticated = false;
        }
        else if (P1(apdu) == 0x2) {
            if (!has_pw3) {
                return SW_CONDITIONS_NOT_SATISFIED();
            }
            newpin_len = apdu.nc;
        }
        int r = 0;
        if ((r = load_dek()) != PICOKEY_OK) {
            return SW_EXEC_ERROR();
        }
        file_t *tf = search_by_fid(EF_DEK, NULL, SPECIFY_EF);
        if (!tf) {
            return SW_REFERENCE_NOT_FOUND();
        }
        if (otp_key_1) {
            for (int i = 0; i < 32; i++) {
                dek[IV_SIZE + i] ^= otp_key_1[i];
            }
        }
        uint8_t def[IV_SIZE + 32 + 32 + 32 + 32];
        memcpy(def, file_get_data(tf), file_get_size(tf));
        hash_multi(apdu.data + (apdu.nc - newpin_len), newpin_len, session_pw1);
        memcpy(def + IV_SIZE, dek + IV_SIZE, 32);
        aes_encrypt_cfb_256(session_pw1, def, def + IV_SIZE, 32);
        r = file_put_data(tf, def, sizeof(def));

        uint8_t dhash[33];
        dhash[0] = newpin_len;
        double_hash_pin(apdu.data + (apdu.nc - newpin_len), newpin_len, dhash + 1);
        file_put_data(pw, dhash, sizeof(dhash));
        if (pin_reset_retries(pw, true) != PICOKEY_OK) {
            return SW_MEMORY_FAILURE();
        }
        low_flash_available();
        if ((r = load_dek()) != PICOKEY_OK) {
            return SW_EXEC_ERROR();
        }
        return SW_OK();
    }
    return SW_INCORRECT_P1P2();
}
