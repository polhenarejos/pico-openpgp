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

int cmd_change_pin() {
    if (P1(apdu) != 0x0) {
        return SW_WRONG_P1P2();
    }
    uint16_t fid = 0x1000 | P2(apdu);
    file_t *pw;
    if (!(pw = search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    uint8_t pin_len = file_get_data(pw)[0];
    uint16_t r = 0;
    if ((r = load_dek()) != PICOKEY_OK) {
        return SW_EXEC_ERROR();
    }

    if (otp_key_1) {
        for (int i = 0; i < 32; i++) {
            dek[IV_SIZE + i] ^= otp_key_1[i];
        }
    }
    r = check_pin(pw, apdu.data, pin_len);
    if (r != 0x9000) {
        return r;
    }
    uint8_t dhash[33];
    dhash[0] = apdu.nc - pin_len;
    double_hash_pin(apdu.data + pin_len, apdu.nc - pin_len, dhash + 1);
    file_put_data(pw, dhash, sizeof(dhash));

    file_t *tf = search_by_fid(EF_DEK, NULL, SPECIFY_EF);
    if (!tf) {
        return SW_REFERENCE_NOT_FOUND();
    }
    uint8_t def[IV_SIZE + 32 + 32 + 32 + 32] = {0};
    memcpy(def, file_get_data(tf), file_get_size(tf));
    if (P2(apdu) == 0x81) {
        hash_multi(apdu.data + pin_len, apdu.nc - pin_len, session_pw1);
        memcpy(def + IV_SIZE, dek + IV_SIZE, 32);
        aes_encrypt_cfb_256(session_pw1, def, def + IV_SIZE, 32);
    }
    else if (P2(apdu) == 0x83) {
        hash_multi(apdu.data + pin_len, apdu.nc - pin_len, session_pw3);
        memcpy(def + IV_SIZE + 32 + 32, dek + IV_SIZE, 32);
        aes_encrypt_cfb_256(session_pw3, def, def + IV_SIZE + 32 + 32, 32);
    }
    file_put_data(tf, def, sizeof(def));
    low_flash_available();
    return SW_OK();
}
