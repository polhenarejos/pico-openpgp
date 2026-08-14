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
#include "otp.h"

int cmd_reset_retry(void) {
    if (P2(apdu) != 0x81) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (P1(apdu) == 0x0 || P1(apdu) == 0x2) {
        int newpin_len = 0;
        file_t *pw = NULL;
#ifdef ENABLE_ADMINLESS_MODE
        bool sync_adminless_pw3 = openpgp_adminless_is_active();
#endif
        has_pw1 = false;
        uint16_t r = 0;
        if (!(pw = file_search_by_fid(EF_PW1, NULL, SPECIFY_EF))) {
            return SW_REFERENCE_NOT_FOUND();
        }
        if (P1(apdu) == 0x0) {
            file_t *rc;
            if (!(rc = file_search_by_fid(EF_RC, NULL, SPECIFY_EF))) {
                return SW_REFERENCE_NOT_FOUND();
            }
            if (!file_has_data(rc) || file_get_data(rc)[0] == 0) {
                return SW_REFERENCE_NOT_FOUND();
            }
            uint8_t pin_len = file_get_data(rc)[0];
            if (apdu.nc <= pin_len) {
                return SW_WRONG_LENGTH();
            }
            r = check_pin(rc, apdu.data, pin_len);
            if (r != 0x9000) {
                return r;
            }
            newpin_len = apdu.nc - pin_len;
            if ((r = check_pin_len(EF_PW1, newpin_len)) != 0x9000) {
                return r;
            }
            has_rc = true;
            pin_derive_session(CONST_BYTE_ARRAY(apdu.data, pin_len), session_rc);
            has_pw1 = has_pw3 = false;
            isUserAuthenticated = false;
        }
        else if (P1(apdu) == 0x2) {
            if (!has_pw3) {
                return SW_CONDITIONS_NOT_SATISFIED();
            }
            newpin_len = apdu.nc;
            if ((r = check_pin_len(EF_PW1, newpin_len)) != 0x9000) {
                return r;
            }
        }
        if ((r = load_dek()) != PICOKEYS_OK) {
            return SW_EXEC_ERROR();
        }
        file_t *tf = file_search_by_fid(EF_DEK_PW1, NULL, SPECIFY_EF);
        if (!tf) {
            return SW_REFERENCE_NOT_FOUND();
        }
        uint8_t def[DEK_FILE_SIZE];
        def[0] = 0x03;
        pin_derive_session(CONST_BYTE_ARRAY(apdu.data + (apdu.nc - newpin_len), newpin_len), session_pw1);
        encrypt_with_aad(session_pw1, CONST_BYTE_ARRAY(dek, DEK_SIZE), PIN_KDF_DEFAULT_VERSION, def + 1);
        r = file_put_data(tf, CONST_BYTE_ARRAY(def, sizeof(def)));

        uint8_t dhash[34];
        dhash[0] = newpin_len;
        dhash[1] = 0x1; // Format
        pin_derive_verifier(CONST_BYTE_ARRAY(apdu.data + (apdu.nc - newpin_len), newpin_len), dhash + 2);
        if ((r = file_put_data(pw, CONST_BYTE_ARRAY(dhash, sizeof(dhash)))) != PICOKEYS_OK) {
            return SW_MEMORY_FAILURE();
        }
#ifdef ENABLE_ADMINLESS_MODE
        if (sync_adminless_pw3 && (r = openpgp_adminless_sync_pw3(apdu.data + (apdu.nc - newpin_len), newpin_len, dhash)) != PICOKEYS_OK) {
            return SW_MEMORY_FAILURE();
        }
#endif
        if (pin_reset_retries(pw, true) != PICOKEYS_OK) {
            return SW_MEMORY_FAILURE();
        }
        flash_commit();
        if ((r = load_dek()) != PICOKEYS_OK) {
            return SW_EXEC_ERROR();
        }
        return SW_OK();
    }
    return SW_INCORRECT_P1P2();
}
