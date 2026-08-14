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

#ifdef ENABLE_ADMINLESS_MODE
#include "mbedtls/constant_time.h"

static bool pw3_matches_nonfactory_pw1(const uint8_t *pin, size_t pin_len) {
    file_t *pw1 = file_search_by_fid(EF_PW1, NULL, SPECIFY_EF);
    uint8_t verifier[34];

    if (!pw1 || !file_has_data(pw1) || file_get_data(pw1)[0] < 8) {
        return false;
    }
    if (file_get_size(pw1) == 33) {
        verifier[0] = pin_len;
        double_hash_pin(CONST_BYTE_ARRAY(pin, pin_len), verifier + 1);
        return mbedtls_ct_memcmp(file_get_data(pw1), verifier, 33) == 0;
    }
    if (file_get_size(pw1) == 34) {
        verifier[0] = pin_len;
        verifier[1] = 0x1;
        pin_derive_verifier(CONST_BYTE_ARRAY(pin, pin_len), verifier + 2);
        return mbedtls_ct_memcmp(file_get_data(pw1), verifier, sizeof(verifier)) == 0;
    }
    return false;
}
#endif

int cmd_change_pin(void) {
    if (P1(apdu) != 0x0) {
        return SW_WRONG_P1P2();
    }
    if (P2(apdu) != 0x81 && P2(apdu) != 0x83) {
        return SW_REFERENCE_NOT_FOUND();
    }
    uint16_t fid = 0x1000 | P2(apdu);
    file_t *pw;
    if (!(pw = file_search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    uint8_t pin_len = file_get_data(pw)[0];
    if (apdu.nc < pin_len) {
        return SW_WRONG_LENGTH();
    }
    uint16_t r = 0;
    r = check_pin(pw, apdu.data, pin_len);
    if (r != 0x9000) {
        return r;
    }
    if ((r = load_dek()) != PICOKEYS_OK) {
        return SW_EXEC_ERROR();
    }

    const uint8_t *new_pin = apdu.data + pin_len;
    size_t new_pin_len = apdu.nc - pin_len;
    bool allow_empty_new_pin = false;
#ifdef ENABLE_ADMINLESS_MODE
    /* Empty PW3 is Gnuk's "PW3 not configured" transition. Keep its
     * current verifier so KDF-backed host flows can still verify it. */
    bool clear_pw3 = P2(apdu) == 0x83 && new_pin_len == 0;
    if (clear_pw3) {
        new_pin = apdu.data;
        new_pin_len = pin_len;
    }
    allow_empty_new_pin = clear_pw3;
    bool sync_adminless_pw3 = P2(apdu) == 0x81 && (openpgp_adminless_is_active() || (openpgp_adminless_is_pending() && new_pin_len >= 8));
    bool disable_pending_adminless = P2(apdu) == 0x81 && openpgp_adminless_is_pending() && new_pin_len < 8;
    bool enable_adminless = P2(apdu) == 0x83 && !clear_pw3 && pw3_matches_nonfactory_pw1(new_pin, new_pin_len);
#endif
    if (!allow_empty_new_pin && (r = check_pin_len(fid, new_pin_len)) != 0x9000) {
        return r;
    }

    uint8_t dhash[34];
    dhash[0] = new_pin_len;
    dhash[1] = 0x1; // Format
    pin_derive_verifier(CONST_BYTE_ARRAY(new_pin, new_pin_len), dhash + 2);
    if ((r = file_put_data(pw, CONST_BYTE_ARRAY(dhash, sizeof(dhash)))) != PICOKEYS_OK) {
        return SW_MEMORY_FAILURE();
    }

    if (P2(apdu) == 0x81) {
        file_t *tf = file_search_by_fid(EF_DEK_PW1, NULL, SPECIFY_EF);
        if (!tf) {
            return SW_REFERENCE_NOT_FOUND();
        }
        uint8_t def[DEK_FILE_SIZE];
        def[0] = 0x3;
        pin_derive_session(CONST_BYTE_ARRAY(new_pin, new_pin_len), session_pw1);
        if ((r = encrypt_with_aad(session_pw1, CONST_BYTE_ARRAY(dek, DEK_SIZE), PIN_KDF_DEFAULT_VERSION, def + 1)) != PICOKEYS_OK) {
            return SW_EXEC_ERROR();
        }
        r = file_put_data(tf, CONST_BYTE_ARRAY(def, sizeof(def)));
#ifdef ENABLE_ADMINLESS_MODE
        if (r == PICOKEYS_OK && sync_adminless_pw3) {
            r = openpgp_adminless_sync_pw3(new_pin, new_pin_len, dhash);
            if (r == PICOKEYS_OK && openpgp_adminless_is_pending()) {
                r = openpgp_adminless_enable();
            }
        }
        else if (r == PICOKEYS_OK && disable_pending_adminless) {
            r = openpgp_adminless_disable();
        }
#endif
    }
    else if (P2(apdu) == 0x83) {
        file_t *tf = file_search_by_fid(EF_DEK_PW3, NULL, SPECIFY_EF);
        if (!tf) {
            return SW_REFERENCE_NOT_FOUND();
        }
        uint8_t def[DEK_FILE_SIZE];
        def[0] = 0x3;
        pin_derive_session(CONST_BYTE_ARRAY(new_pin, new_pin_len), session_pw3);
        if ((r = encrypt_with_aad(session_pw3, CONST_BYTE_ARRAY(dek, DEK_SIZE), PIN_KDF_DEFAULT_VERSION, def + 1)) != PICOKEYS_OK) {
            return SW_EXEC_ERROR();
        }
        r = file_put_data(tf, CONST_BYTE_ARRAY(def, sizeof(def)));
#ifdef ENABLE_ADMINLESS_MODE
        if (r == PICOKEYS_OK) {
            r = enable_adminless ? openpgp_adminless_enable() : clear_pw3 ? openpgp_adminless_reset() : openpgp_adminless_disable();
        }
#endif
    }
    if (r != PICOKEYS_OK) {
        return SW_MEMORY_FAILURE();
    }
    flash_commit();
    return SW_OK();
}
