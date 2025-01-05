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
#include "version.h"
#include "files.h"
#include "random.h"
#include "eac.h"
#include "crypto_utils.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/asn1.h"
#include "asn1.h"
#include "usb.h"
#include "ccid/ccid.h"
#include "otp.h"
#include "mbedtls/eddsa.h"

uint8_t PICO_PRODUCT = 3;

bool has_pw1 = false;
bool has_pw2 = false;
bool has_pw3 = false;
bool has_rc = false;
uint8_t session_pw1[32];
uint8_t session_rc[32];
uint8_t session_pw3[32];
static uint8_t dek[IV_SIZE + 32];
static uint16_t algo_dec = EF_ALGO_PRIV2, algo_aut = EF_ALGO_PRIV3, pk_dec = EF_PK_DEC,
                pk_aut = EF_PK_AUT;

uint8_t openpgp_aid[] = {
    6,
    0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
};

uint8_t openpgp_aid_full[] = {
    16, 00,
    0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
    OPGP_VERSION_MAJOR, OPGP_VERSION_MINOR, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00
};

char atr_openpgp[] = {
    21,
    0x3b, 0xda, 0x18, 0xff, 0x81, 0xb1, 0xfe, 0x75, 0x1f, 0x03, 0x00, 0x31, 0xf5, 0x73, 0xc0, 0x01,
    0x60, 0x00, 0x90, 0x00, 0x1c
};

int openpgp_process_apdu();

extern uint32_t board_button_read(void);

static bool wait_button_pressed(uint16_t fid) {
    uint32_t val = EV_PRESS_BUTTON;
#ifndef ENABLE_EMULATION
    file_t *ef = search_by_fid(fid, NULL, SPECIFY_ANY);
    if (ef && ef->data && file_get_data(ef)[0] > 0) {
        queue_try_add(&card_to_usb_q, &val);
        do {
            queue_remove_blocking(&usb_to_card_q, &val);
        }while (val != EV_BUTTON_PRESSED && val != EV_BUTTON_TIMEOUT);
    }
#endif
    return val == EV_BUTTON_TIMEOUT;
}

void select_file(file_t *pe) {
    if (!pe) {
        currentDF = (file_t *) MF;
        currentEF = NULL;
    }
    else if (pe->type & FILE_TYPE_INTERNAL_EF) {
        currentEF = pe;
        currentDF = &file_entries[pe->parent];
    }
    else {
        currentDF = pe;
    }
    if (currentEF == file_openpgp) {
        selected_applet = currentEF;
        //sc_hsm_unload(); //reset auth status
    }
}

static int cmd_select() {
    uint8_t p1 = P1(apdu);
    uint8_t p2 = P2(apdu);
    file_t *pe = NULL;
    uint16_t fid = 0x0;

    if (apdu.nc >= 2) {
        fid = get_uint16_t_be(apdu.data);
    }

    if (!pe) {
        if (p1 == 0x0) { //Select MF, DF or EF - File identifier or absent
            if (apdu.nc == 0) {
                pe = (file_t *) MF;
                //ac_fini();
            }
            else if (apdu.nc == 2) {
                if (!(pe = search_by_fid(fid, NULL, SPECIFY_ANY))) {
                    return SW_REFERENCE_NOT_FOUND();
                }
            }
        }
        else if (p1 == 0x01) { //Select child DF - DF identifier
            if (!(pe = search_by_fid(fid, currentDF, SPECIFY_DF))) {
                return SW_REFERENCE_NOT_FOUND();
            }
        }
        else if (p1 == 0x02) { //Select EF under the current DF - EF identifier
            if (!(pe = search_by_fid(fid, currentDF, SPECIFY_EF))) {
                return SW_REFERENCE_NOT_FOUND();
            }
        }
        else if (p1 == 0x03) { //Select parent DF of the current DF - Absent
            if (apdu.nc != 0) {
                return SW_REFERENCE_NOT_FOUND();
            }
        }
        else if (p1 == 0x04) { //Select by DF name - e.g., [truncated] application identifier
            if (!(pe = search_by_name(apdu.data, apdu.nc))) {
                return SW_REFERENCE_NOT_FOUND();
            }
            if (card_terminated) {
                return set_res_sw(0x62, 0x85);
            }
        }
        else if (p1 == 0x08) { //Select from the MF - Path without the MF identifier
            if (!(pe = search_by_path(apdu.data, apdu.nc, MF))) {
                return SW_REFERENCE_NOT_FOUND();
            }
        }
        else if (p1 == 0x09) { //Select from the current DF - Path without the current DF identifier
            if (!(pe = search_by_path(apdu.data, apdu.nc, currentDF))) {
                return SW_REFERENCE_NOT_FOUND();
            }
        }
    }
    if ((p2 & 0xfc) == 0x00 || (p2 & 0xfc) == 0x04) {
        if ((p2 & 0xfc) == 0x04) {
            process_fci(pe, 0);
        }
    }
    else {
        return SW_INCORRECT_P1P2();
    }
    select_file(pe);
    return SW_OK();
}

void scan_files() {
    scan_flash();
    file_t *ef;
    if ((ef = search_by_fid(EF_FULL_AID, NULL, SPECIFY_ANY))) {
        ef->data = openpgp_aid_full;
        memcpy(ef->data + 12, pico_serial.id, 4);
    }
    bool reset_dek = false;
    if ((ef = search_by_fid(EF_DEK, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("DEK is empty\r\n");
            const uint8_t def1[6] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36 };
            const uint8_t def3[8] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };

            uint8_t def[IV_SIZE + 32 + 32 + 32];
            const uint8_t *dek = random_bytes_get(IV_SIZE + 32);
            memcpy(def, dek, IV_SIZE + 32);
            memcpy(def + IV_SIZE + 32, dek + IV_SIZE, 32);
            memcpy(def + IV_SIZE + 32 + 32, dek + IV_SIZE, 32);
            hash_multi(def1, sizeof(def1), session_pw1);
            aes_encrypt_cfb_256(session_pw1, def, def + IV_SIZE, 32);
            memset(session_pw1, 0, sizeof(session_pw1));

            hash_multi(def3, sizeof(def3), session_pw3);
            aes_encrypt_cfb_256(session_pw3, def, def + IV_SIZE + 32, 32);
            aes_encrypt_cfb_256(session_pw3, def, def + IV_SIZE + 32 + 32, 32);
            memset(session_pw3, 0, sizeof(session_pw3));
            file_put_data(ef, def, sizeof(def));
            reset_dek = true;
        }
    }
    if ((ef = search_by_fid(EF_PW1, NULL, SPECIFY_ANY))) {
        if (!ef->data || reset_dek) {
            printf("PW1 is empty. Initializing with default password\r\n");
            const uint8_t def[6] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36 };
            uint8_t dhash[33];
            dhash[0] = sizeof(def);
            double_hash_pin(def, sizeof(def), dhash + 1);
            file_put_data(ef, dhash, sizeof(dhash));
        }
    }
    if ((ef = search_by_fid(EF_RC, NULL, SPECIFY_ANY))) {
        if (!ef->data || reset_dek) {
            printf("RC is empty. Initializing with default password\r\n");

            const uint8_t def[8] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
            uint8_t dhash[33];
            dhash[0] = sizeof(def);
            double_hash_pin(def, sizeof(def), dhash + 1);
            file_put_data(ef, dhash, sizeof(dhash));
        }
    }
    if ((ef = search_by_fid(EF_PW3, NULL, SPECIFY_ANY))) {
        if (!ef->data || reset_dek) {
            printf("PW3 is empty. Initializing with default password\r\n");

            const uint8_t def[8] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
            uint8_t dhash[33];
            dhash[0] = sizeof(def);
            double_hash_pin(def, sizeof(def), dhash + 1);
            file_put_data(ef, dhash, sizeof(dhash));
        }
    }
    if ((ef = search_by_fid(EF_SIG_COUNT, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("SigCount is empty. Initializing to zero\r\n");
            const uint8_t def[3] = { 0 };
            file_put_data(ef, def, sizeof(def));
        }
    }
    if ((ef = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("PW status is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x1, 127, 127, 127, 3, 3, 3 };
            file_put_data(ef, def, sizeof(def));
        }
    }
    if ((ef = search_by_fid(EF_UIF_SIG, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("UIF SIG is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x0, 0x20 };
            file_put_data(ef, def, sizeof(def));
        }
    }
    if ((ef = search_by_fid(EF_UIF_DEC, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("UIF DEC is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x0, 0x20 };
            file_put_data(ef, def, sizeof(def));
        }
    }
    if ((ef = search_by_fid(EF_UIF_AUT, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("UIF AUT is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x0, 0x20 };
            file_put_data(ef, def, sizeof(def));
        }
    }
    if ((ef = search_by_fid(EF_KDF, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("KDF is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x81, 0x1, 0x0 };
            file_put_data(ef, def, sizeof(def));
        }
    }
    if ((ef = search_by_fid(EF_SEX, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("Sex is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x30 };
            file_put_data(ef, def, sizeof(def));
        }
    }
    if ((ef = search_by_fid(EF_PW_RETRIES, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("PW retries is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x1, 3, 3, 3 };
            file_put_data(ef, def, sizeof(def));
        }
    }
    low_flash_available();
}

extern bool has_pwpiv;
extern uint8_t session_pwpiv[32];
int load_dek() {
    if (!has_pw1 && !has_pw2 && !has_pw3 && !has_pwpiv) {
        return PICOKEY_NO_LOGIN;
    }
    file_t *tf = search_by_fid(EF_DEK, NULL, SPECIFY_EF);
    if (!tf) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    int r = PICOKEY_OK;
    if (has_pw1 || has_pw2) {
        memcpy(dek, file_get_data(tf), IV_SIZE + 32);
        r = aes_decrypt_cfb_256(session_pw1, dek, dek + IV_SIZE, 32);
    }
    else if (has_pw3) {
        memcpy(dek, file_get_data(tf), IV_SIZE);
        memcpy(dek + IV_SIZE, file_get_data(tf) + IV_SIZE + 32 + 32, 32);
        r = aes_decrypt_cfb_256(session_pw3, dek, dek + IV_SIZE, 32);
    }
    else if (has_pwpiv) {
        memcpy(dek, file_get_data(tf), IV_SIZE);
        memcpy(dek + IV_SIZE, file_get_data(tf) + IV_SIZE + 32 + 32 + 32, 32);
        r = aes_decrypt_cfb_256(session_pwpiv, dek, dek + IV_SIZE, 32);
    }
    if (r != 0) {
        return PICOKEY_EXEC_ERROR;
    }
    if (otp_key_1) {
        for (int i = 0; i < 32; i++) {
            dek[IV_SIZE + i] ^= otp_key_1[i];
        }
    }
    return PICOKEY_OK;
}

void release_dek() {
    memset(dek, 0, sizeof(dek));
}

int dek_encrypt(uint8_t *data, size_t len) {
    int r;
    if ((r = load_dek()) != PICOKEY_OK) {
        return r;
    }
    r = aes_encrypt_cfb_256(dek + IV_SIZE, dek, data, len);
    release_dek();
    return r;
}

int dek_decrypt(uint8_t *data, size_t len) {
    int r;
    if ((r = load_dek()) != PICOKEY_OK) {
        return r;
    }
    r = aes_decrypt_cfb_256(dek + IV_SIZE, dek, data, len);
    release_dek();
    return r;
}

void init_openpgp() {
    isUserAuthenticated = false;
    has_pw1 = has_pw3 = false;
    algo_dec = EF_ALGO_PRIV2;
    algo_aut = EF_ALGO_PRIV3;
    pk_dec = EF_PK_DEC;
    pk_aut = EF_PK_AUT;
    scan_files();
    //cmd_select();
}

int openpgp_unload() {
    isUserAuthenticated = false;
    has_pw1 = has_pw3 = false;
    algo_dec = EF_ALGO_PRIV2;
    algo_aut = EF_ALGO_PRIV3;
    pk_dec = EF_PK_DEC;
    pk_aut = EF_PK_AUT;
    return PICOKEY_OK;
}

extern char __StackLimit;
int heapLeft() {
#if !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
    char *p = malloc(256);   // try to avoid undue fragmentation
    int left = &__StackLimit - p;
    free(p);
#else
    int left = 1024 * 1024;
#endif
    return left;
}

int openpgp_select_aid(app_t *a, uint8_t force) {
    (void) force;
    a->process_apdu = openpgp_process_apdu;
    a->unload = openpgp_unload;
    init_openpgp();
    process_fci(file_openpgp, 1);
    memcpy(res_APDU + res_APDU_size, "\x64\x06\x53\x04", 4);
    res_APDU_size += 4;
    int heap_left = heapLeft();
    res_APDU[res_APDU_size++] = ((heap_left >> 24) & 0xff);
    res_APDU[res_APDU_size++] = ((heap_left >> 16) & 0xff);
    res_APDU[res_APDU_size++] = ((heap_left >> 8) & 0xff);
    res_APDU[res_APDU_size++] = ((heap_left >> 0) & 0xff);
    res_APDU[1] += 8;
    apdu.ne = res_APDU_size;
    return PICOKEY_OK;
}

INITIALIZER( openpgp_ctor ) {
    ccid_atr = (uint8_t *) atr_openpgp;
    register_app(openpgp_select_aid, openpgp_aid);
}

int parse_do(uint16_t *fids, int mode) {
    int len = 0;
    file_t *ef;
    for (int i = 0; i < fids[0]; i++) {
        if ((ef = search_by_fid(fids[i + 1], NULL, SPECIFY_EF))) {
            uint16_t data_len;
            if ((ef->type & FILE_DATA_FUNC) == FILE_DATA_FUNC) {
                data_len = ((int (*)(const file_t *, int))(ef->data))((const file_t *) ef, mode);
            }
            else {
                if (ef->data) {
                    data_len = file_get_size(ef);
                }
                else {
                    data_len = 0;
                }
                if (mode == 1) {
                    if (fids[0] > 1 && res_APDU_size > 0) {
                        if (fids[i + 1] < 0x0100) {
                            res_APDU[res_APDU_size++] = fids[i + 1] & 0xff;
                        }
                        else {
                            res_APDU[res_APDU_size++] = fids[i + 1] >> 8;
                            res_APDU[res_APDU_size++] = fids[i + 1] & 0xff;
                        }
                        res_APDU_size += format_tlv_len(data_len, res_APDU + res_APDU_size);
                    }
                    if (ef->data) {
                        memcpy(res_APDU + res_APDU_size, file_get_data(ef), data_len);
                    }
                    res_APDU_size += data_len;
                }
            }
            len += data_len;
        }
    }
    return len;
}

int parse_trium(uint16_t fid, uint8_t num, size_t size) {
    for (uint8_t i = 0; i < num; i++) {
        file_t *ef;
        if ((ef = search_by_fid(fid + i, NULL, SPECIFY_EF)) && ef->data) {
            uint16_t data_len = file_get_size(ef);
            memcpy(res_APDU + res_APDU_size, file_get_data(ef), data_len);
            res_APDU_size += data_len;
        }
        else {
            memset(res_APDU + res_APDU_size, 0, size);
            res_APDU_size += size;
        }
    }
    return num * size;
}

int parse_ch_data(const file_t *f, int mode) {
    uint16_t fids[] = {
        3,
        EF_CH_NAME, EF_LANG_PREF, EF_SEX,
    };
    res_APDU[res_APDU_size++] = EF_CH_DATA & 0xff;
    res_APDU[res_APDU_size++] = 0x82;
    uint8_t *lp = res_APDU + res_APDU_size;
    res_APDU_size += 2;
    parse_do(fids, mode);
    uint16_t lpdif = res_APDU + res_APDU_size - lp - 2;
    *lp++ = lpdif >> 8;
    *lp++ = lpdif & 0xff;
    return lpdif + 4;
}

int inc_sig_count() {
    file_t *pw_status;
    if (!(pw_status = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF)) || !pw_status->data) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (file_get_data(pw_status)[0] == 0) {
        has_pw1 = false;
    }
    file_t *ef = search_by_fid(EF_SIG_COUNT, NULL, SPECIFY_ANY);
    if (!ef || !ef->data) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    uint8_t *p = file_get_data(ef);
    uint32_t counter = (p[0] << 16) | (p[1] << 8) | p[2];
    counter++;
    uint8_t q[3] = { (counter >> 16) & 0xff, (counter >> 8) & 0xff, counter & 0xff };
    int r = file_put_data(ef, q, sizeof(q));
    if (r != PICOKEY_OK) {
        return PICOKEY_EXEC_ERROR;
    }
    low_flash_available();
    return PICOKEY_OK;
}

int reset_sig_count() {
    file_t *ef = search_by_fid(EF_SIG_COUNT, NULL, SPECIFY_ANY);
    if (!ef || !ef->data) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    uint8_t q[3] = { 0 };
    int r = file_put_data(ef, q, sizeof(q));
    if (r != PICOKEY_OK) {
        return PICOKEY_EXEC_ERROR;
    }
    low_flash_available();
    return PICOKEY_OK;
}

int parse_sec_tpl(const file_t *f, int mode) {
    res_APDU[res_APDU_size++] = EF_SEC_TPL & 0xff;
    res_APDU[res_APDU_size++] = 5;
    file_t *ef = search_by_fid(EF_SIG_COUNT, NULL, SPECIFY_ANY);
    if (ef && ef->data) {
        res_APDU[res_APDU_size++] = EF_SIG_COUNT & 0xff;
        res_APDU[res_APDU_size++] = 3;
        memcpy(res_APDU + res_APDU_size, file_get_data(ef), 3);
        res_APDU_size += 3;
    }
    return 5 + 2;
}

int parse_ch_cert(const file_t *f, int mode) {
    return 0;
}

int parse_fp(const file_t *f, int mode) {
    res_APDU[res_APDU_size++] = EF_FP & 0xff;
    res_APDU[res_APDU_size++] = 60;
    return parse_trium(EF_FP_SIG, 3, 20) + 2;
}

int parse_cafp(const file_t *f, int mode) {
    res_APDU[res_APDU_size++] = EF_CA_FP & 0xff;
    res_APDU[res_APDU_size++] = 60;
    return parse_trium(EF_FP_CA1, 3, 20) + 2;
}

int parse_ts(const file_t *f, int mode) {
    res_APDU[res_APDU_size++] = EF_TS_ALL & 0xff;
    res_APDU[res_APDU_size++] = 12;
    return parse_trium(EF_TS_SIG, 3, 4) + 2;
}

int parse_keyinfo(const file_t *f, int mode) {
    int init_len = res_APDU_size;
    if (res_APDU_size > 0) {
        res_APDU[res_APDU_size++] = EF_KEY_INFO & 0xff;
        res_APDU[res_APDU_size++] = 6;
    }
    file_t *ef = search_by_fid(EF_PK_SIG, NULL, SPECIFY_ANY);
    res_APDU[res_APDU_size++] = 0x00;
    if (ef && ef->data) {
        res_APDU[res_APDU_size++] = 0x01;
    }
    else {
        res_APDU[res_APDU_size++] = 0x00;
    }

    ef = search_by_fid(EF_PK_DEC, NULL, SPECIFY_ANY);
    res_APDU[res_APDU_size++] = 0x01;
    if (ef && ef->data) {
        res_APDU[res_APDU_size++] = 0x01;
    }
    else {
        res_APDU[res_APDU_size++] = 0x00;
    }

    ef = search_by_fid(EF_PK_AUT, NULL, SPECIFY_ANY);
    res_APDU[res_APDU_size++] = 0x02;
    if (ef && ef->data) {
        res_APDU[res_APDU_size++] = 0x01;
    }
    else {
        res_APDU[res_APDU_size++] = 0x00;
    }
    return res_APDU_size - init_len;
}

int parse_pw_status(const file_t *f, int mode) {
    file_t *ef;
    int init_len = res_APDU_size;
    if (res_APDU_size > 0) {
        res_APDU[res_APDU_size++] = EF_PW_STATUS & 0xff;
        res_APDU[res_APDU_size++] = 7;
    }
    ef = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_ANY);
    if (ef && ef->data) {
        memcpy(res_APDU + res_APDU_size, file_get_data(ef), 7);
        res_APDU_size += 7;
    }
    return res_APDU_size - init_len;
}

#define ALGO_RSA_1K     0
#define ALGO_RSA_2k     1
#define ALGO_RSA_3K     2
#define ALGO_RSA_4K     3
#define ALGO_X448       4
#define ALGO_P256K1     5
#define ALGO_P256R1     6
#define ALGO_P384R1     7
#define ALGO_P521R1     8
#define ALGO_BP256R1    9
#define ALGO_BP384R1    10
#define ALGO_BP512R1    11
#define ALGO_CV22519    12

static const uint8_t algorithm_attr_x448[] = {
    4,
    ALGO_ECDH,
    /* OID of X448 */
    0x2b, 0x65, 0x6f
};

static const uint8_t algorithm_attr_rsa1k[] = {
    6,
    ALGO_RSA,
    0x04, 0x00,       /* Length modulus (in bit): 1024 */
    0x00, 0x20,       /* Length exponent (in bit): 32  */
    0x00          /* 0: Acceptable format is: P and Q */
};

static const uint8_t algorithm_attr_rsa2k[] = {
    6,
    ALGO_RSA,
    0x08, 0x00,       /* Length modulus (in bit): 2048 */
    0x00, 0x20,       /* Length exponent (in bit): 32  */
    0x00          /* 0: Acceptable format is: P and Q */
};

static const uint8_t algorithm_attr_rsa3k[] = {
    6,
    ALGO_RSA,
    0x0C, 0x00,       /* Length modulus (in bit): 3072 */
    0x00, 0x20,       /* Length exponent (in bit): 32  */
    0x00          /* 0: Acceptable format is: P and Q */
};

static const uint8_t algorithm_attr_rsa4k[] = {
    6,
    ALGO_RSA,
    0x10, 0x00,       /* Length modulus (in bit): 4096 */
    0x00, 0x20,       /* Length exponent (in bit): 32  */
    0x00          /* 0: Acceptable format is: P and Q */
};

static const uint8_t algorithm_attr_p256k1[] = {
    6,
    ALGO_ECDSA,
    0x2b, 0x81, 0x04, 0x00, 0x0a
};

static const uint8_t algorithm_attr_p256r1[] = {
    9,
    ALGO_ECDSA,
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
};

static const uint8_t algorithm_attr_p384r1[] = {
    6,
    ALGO_ECDSA,
    0x2B, 0x81, 0x04, 0x00, 0x22
};

static const uint8_t algorithm_attr_p521r1[] = {
    6,
    ALGO_ECDSA,
    0x2B, 0x81, 0x04, 0x00, 0x23
};

static const uint8_t algorithm_attr_bp256r1[] = {
    10,
    ALGO_ECDSA,
    0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07
};

static const uint8_t algorithm_attr_bp384r1[] = {
    10,
    ALGO_ECDSA,
    0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B
};

static const uint8_t algorithm_attr_bp512r1[] = {
    10,
    ALGO_ECDSA,
    0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D
};

static const uint8_t algorithm_attr_cv25519[] = {
    11,
    ALGO_ECDH,
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01
};

static const uint8_t algorithm_attr_ed25519[] = {
    10,
    ALGO_EDDSA,
    0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01
    };

int parse_algo(const uint8_t *algo, uint16_t tag) {
    res_APDU[res_APDU_size++] = tag & 0xff;
    memcpy(res_APDU + res_APDU_size, algo, algo[0] + 1);
    res_APDU_size += algo[0] + 1;
    return algo[0] + 2;
}

int parse_algoinfo(const file_t *f, int mode) {
    int datalen = 0;
    if (f->fid == EF_ALGO_INFO) {
        res_APDU[res_APDU_size++] = EF_ALGO_INFO & 0xff;
        res_APDU[res_APDU_size++] = 0x82;
        uint8_t *lp = res_APDU + res_APDU_size;
        res_APDU_size += 2;
        datalen += parse_algo(algorithm_attr_rsa1k, EF_ALGO_SIG);
        datalen += parse_algo(algorithm_attr_rsa2k, EF_ALGO_SIG);
        datalen += parse_algo(algorithm_attr_rsa3k, EF_ALGO_SIG);
        datalen += parse_algo(algorithm_attr_rsa4k, EF_ALGO_SIG);
        datalen += parse_algo(algorithm_attr_p256k1, EF_ALGO_SIG);
        datalen += parse_algo(algorithm_attr_p256r1, EF_ALGO_SIG);
        datalen += parse_algo(algorithm_attr_p384r1, EF_ALGO_SIG);
        datalen += parse_algo(algorithm_attr_p521r1, EF_ALGO_SIG);
        datalen += parse_algo(algorithm_attr_bp256r1, EF_ALGO_SIG);
        datalen += parse_algo(algorithm_attr_bp384r1, EF_ALGO_SIG);
        datalen += parse_algo(algorithm_attr_bp512r1, EF_ALGO_SIG);
        datalen += parse_algo(algorithm_attr_ed25519, EF_ALGO_SIG);

        datalen += parse_algo(algorithm_attr_rsa1k, EF_ALGO_DEC);
        datalen += parse_algo(algorithm_attr_rsa2k, EF_ALGO_DEC);
        datalen += parse_algo(algorithm_attr_rsa3k, EF_ALGO_DEC);
        datalen += parse_algo(algorithm_attr_rsa4k, EF_ALGO_DEC);
        datalen += parse_algo(algorithm_attr_p256k1, EF_ALGO_DEC);
        datalen += parse_algo(algorithm_attr_p256r1, EF_ALGO_DEC);
        datalen += parse_algo(algorithm_attr_p384r1, EF_ALGO_DEC);
        datalen += parse_algo(algorithm_attr_p521r1, EF_ALGO_DEC);
        datalen += parse_algo(algorithm_attr_bp256r1, EF_ALGO_DEC);
        datalen += parse_algo(algorithm_attr_bp384r1, EF_ALGO_DEC);
        datalen += parse_algo(algorithm_attr_bp512r1, EF_ALGO_DEC);
        datalen += parse_algo(algorithm_attr_cv25519, EF_ALGO_DEC);
        datalen += parse_algo(algorithm_attr_x448, EF_ALGO_DEC);

        datalen += parse_algo(algorithm_attr_rsa1k, EF_ALGO_AUT);
        datalen += parse_algo(algorithm_attr_rsa2k, EF_ALGO_AUT);
        datalen += parse_algo(algorithm_attr_rsa3k, EF_ALGO_AUT);
        datalen += parse_algo(algorithm_attr_rsa4k, EF_ALGO_AUT);
        datalen += parse_algo(algorithm_attr_p256k1, EF_ALGO_AUT);
        datalen += parse_algo(algorithm_attr_p256r1, EF_ALGO_AUT);
        datalen += parse_algo(algorithm_attr_p384r1, EF_ALGO_AUT);
        datalen += parse_algo(algorithm_attr_p521r1, EF_ALGO_AUT);
        datalen += parse_algo(algorithm_attr_bp256r1, EF_ALGO_AUT);
        datalen += parse_algo(algorithm_attr_bp384r1, EF_ALGO_AUT);
        datalen += parse_algo(algorithm_attr_bp512r1, EF_ALGO_AUT);
        datalen += parse_algo(algorithm_attr_ed25519, EF_ALGO_AUT);
        uint16_t lpdif = res_APDU + res_APDU_size - lp - 2;
        *lp++ = lpdif >> 8;
        *lp++ = lpdif & 0xff;
        datalen = lpdif + 4;
    }
    else if (f->fid == EF_ALGO_SIG || f->fid == EF_ALGO_DEC || f->fid == EF_ALGO_AUT) {
        uint16_t fid = 0x1000 | f->fid;
        file_t *ef;
        if (!(ef = search_by_fid(fid, NULL, SPECIFY_EF)) || !ef->data) {
            datalen += parse_algo(algorithm_attr_rsa2k, f->fid);
        }
        else {
            uint16_t len = file_get_size(ef);
            if (res_APDU_size > 0) {
                res_APDU[res_APDU_size++] = f->fid & 0xff;
                res_APDU[res_APDU_size++] = len & 0xff;
                datalen += 2;
            }
            memcpy(res_APDU + res_APDU_size, file_get_data(ef), len);
            res_APDU_size += len;
            datalen += len;
        }
    }
    return datalen;
}

int parse_app_data(const file_t *f, int mode) {
    uint16_t fids[] = {
        6,
        EF_FULL_AID, EF_HIST_BYTES, EF_EXLEN_INFO, EF_GFM, EF_DISCRETE_DO, EF_KEY_INFO
    };
    res_APDU[res_APDU_size++] = EF_APP_DATA & 0xff;
    res_APDU[res_APDU_size++] = 0x82;
    uint8_t *lp = res_APDU + res_APDU_size;
    res_APDU_size += 2;
    parse_do(fids, mode);
    uint16_t lpdif = res_APDU + res_APDU_size - lp - 2;
    *lp++ = lpdif >> 8;
    *lp++ = lpdif & 0xff;
    return lpdif + 4;
}

int parse_discrete_do(const file_t *f, int mode) {
    uint16_t fids[] = {
        11,
        EF_EXT_CAP, EF_ALGO_SIG, EF_ALGO_DEC, EF_ALGO_AUT, EF_PW_STATUS, EF_FP, EF_CA_FP, EF_TS_ALL,
        EF_UIF_SIG, EF_UIF_DEC, EF_UIF_AUT
    };
    res_APDU[res_APDU_size++] = EF_DISCRETE_DO & 0xff;
    res_APDU[res_APDU_size++] = 0x82;
    uint8_t *lp = res_APDU + res_APDU_size;
    res_APDU_size += 2;
    parse_do(fids, mode);
    uint16_t lpdif = res_APDU + res_APDU_size - lp - 2;
    *lp++ = lpdif >> 8;
    *lp++ = lpdif & 0xff;
    return lpdif + 4;
}

static int cmd_get_data() {
    if (apdu.nc > 0) {
        return SW_WRONG_LENGTH();
    }
    uint16_t fid = (P1(apdu) << 8) | P2(apdu);
    file_t *ef;
    if (!(ef = search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!authenticate_action(ef, ACL_OP_READ_SEARCH)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (currentEF && (currentEF->fid & 0x1FF0) == (fid & 0x1FF0)) { //previously selected
        ef = currentEF;
    }
    else {
        select_file(ef);
    }
    if (ef->data) {
        uint16_t fids[] = { 1, fid };
        uint16_t data_len = parse_do(fids, 1);
        uint8_t *p = NULL;
        uint16_t tg = 0;
        uint16_t tg_len = 0;
        asn1_ctx_t ctxi;
        asn1_ctx_init(res_APDU, data_len, &ctxi);
        if (walk_tlv(&ctxi, &p, &tg, &tg_len, NULL)) {
            uint8_t dec = 2;
            if ((tg & 0x1f) == 0x1f) {
                dec++;
            }
            if ((res_APDU[dec - 1] & 0xF0) == 0x80) {
                dec += (res_APDU[dec - 1] & 0x0F);
            }
            if (tg_len + dec == data_len) {
                memmove(res_APDU, res_APDU + dec, data_len - dec);
                data_len -= dec;
                res_APDU_size -= dec;
            }
        }
        //if (apdu.ne > data_len)
        //    apdu.ne = data_len;
    }
    return SW_OK();
}

int pin_reset_retries(const file_t *pin, bool force) {
    if (!pin) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    file_t *pw_status = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF);
    file_t *pw_retries = search_by_fid(EF_PW_RETRIES, NULL, SPECIFY_EF);
    if (!pw_status || !pw_retries) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    if (3 + (pin->fid & 0xf) >= file_get_size(pw_status) || (pin->fid & 0xf) >= file_get_size(pw_retries)) {
        return PICOKEY_ERR_MEMORY_FATAL;
    }
    uint8_t p[64];
    memcpy(p, file_get_data(pw_status), file_get_size(pw_status));
    uint8_t retries = p[3 + (pin->fid & 0xf)];
    if (retries == 0 && force == false) { //blocked
        return PICOKEY_ERR_BLOCKED;
    }
    uint8_t max_retries = file_get_data(pw_retries)[(pin->fid & 0xf)];
    p[3 + (pin->fid & 0xf)] = max_retries;
    int r = file_put_data(pw_status, p, file_get_size(pw_status));
    low_flash_available();
    return r;
}

int pin_wrong_retry(const file_t *pin) {
    if (!pin) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    file_t *pw_status = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF);
    if (!pw_status) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    uint8_t p[64];
    memcpy(p, file_get_data(pw_status), file_get_size(pw_status));
    if (p[3 + (pin->fid & 0xf)] > 0) {
        p[3 + (pin->fid & 0xf)] -= 1;
        int r = file_put_data(pw_status, p, file_get_size(pw_status));
        if (r != PICOKEY_OK) {
            return r;
        }
        low_flash_available();
        if (p[3 + (pin->fid & 0xf)] == 0) {
            return PICOKEY_ERR_BLOCKED;
        }
        return p[3 + (pin->fid & 0xf)];
    }
    return PICOKEY_ERR_BLOCKED;
}

int check_pin(const file_t *pin, const uint8_t *data, size_t len) {
    if (!pin) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!pin->data) {
        return SW_REFERENCE_NOT_FOUND();
    }
    isUserAuthenticated = false;
    //has_pw1 = has_pw3 = false;

    uint8_t dhash[32];
    double_hash_pin(data, len, dhash);
    if (sizeof(dhash) != file_get_size(pin) - 1) { //1 byte for pin len
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if (memcmp(file_get_data(pin) + 1, dhash, sizeof(dhash)) != 0) {
        int retries;
        if ((retries = pin_wrong_retry(pin)) < PICOKEY_OK) {
            return SW_PIN_BLOCKED();
        }
        return set_res_sw(0x63, 0xc0 | retries);
    }

    int r = pin_reset_retries(pin, false);
    if (r == PICOKEY_ERR_BLOCKED) {
        return SW_PIN_BLOCKED();
    }
    if (r != PICOKEY_OK) {
        return SW_MEMORY_FAILURE();
    }
    isUserAuthenticated = true;
    if (pin->fid == EF_PW1) {
        if (P2(apdu) == 0x81) {
            has_pw1 = true;
        }
        else {
            has_pw2 = true;
        }
        hash_multi(data, len, session_pw1);
    }
    else if (pin->fid == EF_PW3) {
        has_pw3 = true;
        hash_multi(data, len, session_pw3);
    }
    return SW_OK();
}

static int cmd_verify() {
    uint8_t p1 = P1(apdu);
    uint8_t p2 = P2(apdu);

    if (p1 == 0xFF) {
        if (apdu.nc != 0) {
            return SW_WRONG_DATA();
        }
        if (p2 == 0x81) {
            has_pw1 = false;
        }
        else if (p2 == 0x82) {
            has_pw2 = false;
        }
        else if (p2 == 0x83) {
            has_pw3 = false;
        }
        return SW_OK();
    }
    else if (p1 != 0x0 || (p2 & 0x60) != 0x0) {
        return SW_WRONG_P1P2();
    }
    uint16_t fid = 0x1000 | p2;
    if (fid == EF_RC && apdu.nc > 0) {
        fid = EF_PW1;
    }
    file_t *pw, *pw_status;
    if (!(pw = search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!(pw_status = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (file_get_data(pw)[0] == 0) { //not initialized
        return SW_REFERENCE_NOT_FOUND();
    }
    if (apdu.nc > 0) {
        return check_pin(pw, apdu.data, apdu.nc);
    }
    uint8_t retries = *(file_get_data(pw_status) + 3 + (fid & 0xf));
    if (retries == 0) {
        return SW_PIN_BLOCKED();
    }
    if ((p2 == 0x81 && has_pw1) || (p2 == 0x82 && has_pw2) || (p2 == 0x83 && has_pw3)) {
        return SW_OK();
    }
    return set_res_sw(0x63, 0xc0 | retries);
}

static int cmd_put_data() {
    uint16_t fid = (P1(apdu) << 8) | P2(apdu);
    file_t *ef;
    if (fid == EF_RESET_CODE) {
        fid = EF_RC;
    }
    else if (fid == EF_ALGO_SIG || fid == EF_ALGO_DEC || fid == EF_ALGO_AUT) {
        fid |= 0x1000;
    }
    if (!(ef = search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!authenticate_action(ef, ACL_OP_UPDATE_ERASE)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (fid == EF_PW_STATUS) {
        fid = EF_PW_PRIV;
        apdu.nc = 4; //we silently ommit the reset parameters
    }
    if (currentEF && (currentEF->fid & 0x1FF0) == (fid & 0x1FF0)) { //previously selected
        ef = currentEF;
    }
    if (apdu.nc > 0 && (ef->type & FILE_DATA_FLASH)) {
        int r = 0;
        if (fid == EF_RC) {
            has_rc = false;
            if ((r = load_dek()) != PICOKEY_OK) {
                return SW_EXEC_ERROR();
            }
            uint8_t dhash[33];
            dhash[0] = apdu.nc;
            double_hash_pin(apdu.data, apdu.nc, dhash + 1);
            r = file_put_data(ef, dhash, sizeof(dhash));

            file_t *tf = search_by_fid(EF_DEK, NULL, SPECIFY_EF);
            if (!tf) {
                return SW_REFERENCE_NOT_FOUND();
            }
            uint8_t def[IV_SIZE + 32 + 32 + 32 + 32];
            memcpy(def, file_get_data(tf), file_get_size(tf));
            hash_multi(apdu.data, apdu.nc, session_rc);
            memcpy(def + IV_SIZE + 32, dek + IV_SIZE, 32);
            aes_encrypt_cfb_256(session_rc, def, def + IV_SIZE + 32, 32);
            r = file_put_data(tf, def, sizeof(def));
        }
        else {
            r = file_put_data(ef, apdu.data, apdu.nc);
        }
        if (r != PICOKEY_OK) {
            return SW_MEMORY_FAILURE();
        }
        low_flash_available();
    }
    return SW_OK();
}

static int cmd_change_pin() {
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

static int cmd_reset_retry() {
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
        return SW_OK();
    }
    return SW_INCORRECT_P1P2();
}

int store_keys(void *key_ctx, int type, uint16_t key_id, bool use_kek) {
    int r, key_size = 0;
    uint8_t kdata[4096 / 8]; //worst

    //if (!has_pw3)
    //    return PICOKEY_NO_LOGIN;
    //file_t *pw3 = search_by_fid(EF_PW3, NULL, SPECIFY_EF);
    //if (!pw3)
    //    return PICOKEY_ERR_FILE_NOT_FOUND;
    file_t *ef = search_by_fid(key_id, NULL, SPECIFY_EF);
    if (!ef) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    if (type == ALGO_RSA) {
        mbedtls_rsa_context *rsa = (mbedtls_rsa_context *) key_ctx;
        key_size = mbedtls_mpi_size(&rsa->P) + mbedtls_mpi_size(&rsa->Q);
        mbedtls_mpi_write_binary(&rsa->P, kdata, key_size / 2);
        mbedtls_mpi_write_binary(&rsa->Q, kdata + key_size / 2, key_size / 2);
    }
    else if (type == ALGO_ECDSA || type == ALGO_ECDH || type == ALGO_EDDSA) {
        mbedtls_ecp_keypair *ecdsa = (mbedtls_ecp_keypair *) key_ctx;
        size_t olen = 0;
        kdata[0] = ecdsa->grp.id & 0xff;
        mbedtls_ecp_write_key_ext(ecdsa, &olen, kdata + 1, sizeof(kdata) - 1);
        key_size = olen + 1;
    }
    else if (type & ALGO_AES) {
        if (type == ALGO_AES_128) {
            key_size = 16;
        }
        else if (type == ALGO_AES_192) {
            key_size = 24;
        }
        else if (type == ALGO_AES_256) {
            key_size = 32;
        }
        memcpy(kdata, key_ctx, key_size);
    }
    if (use_kek) {
        r = dek_encrypt(kdata, key_size);
        if (r != PICOKEY_OK) {
            return r;
        }
    }
    //r = aes_encrypt_cfb_256(file_read(pw3->data+2), session_pw3, kdata, key_size);
    //if (r != PICOKEY_OK)
    //    return r;
    r = file_put_data(ef, kdata, key_size);
    if (r != PICOKEY_OK) {
        return r;
    }
    low_flash_available();
    return PICOKEY_OK;
}

int load_private_key_rsa(mbedtls_rsa_context *ctx, file_t *fkey, bool use_dek) {
    int key_size = file_get_size(fkey);
    uint8_t kdata[4096 / 8];
    memcpy(kdata, file_get_data(fkey), key_size);
    if (use_dek && dek_decrypt(kdata, key_size) != 0) {
        return PICOKEY_EXEC_ERROR;
    }
    if (mbedtls_mpi_read_binary(&ctx->P, kdata, key_size / 2) != 0) {
        mbedtls_rsa_free(ctx);
        return PICOKEY_WRONG_DATA;
    }
    if (mbedtls_mpi_read_binary(&ctx->Q, kdata + key_size / 2, key_size / 2) != 0) {
        mbedtls_rsa_free(ctx);
        return PICOKEY_WRONG_DATA;
    }
    if (mbedtls_mpi_lset(&ctx->E, 0x10001) != 0) {
        mbedtls_rsa_free(ctx);
        return PICOKEY_EXEC_ERROR;
    }
    if (mbedtls_rsa_import(ctx, NULL, &ctx->P, &ctx->Q, NULL, &ctx->E) != 0) {
        mbedtls_rsa_free(ctx);
        return PICOKEY_WRONG_DATA;
    }
    if (mbedtls_rsa_complete(ctx) != 0) {
        mbedtls_rsa_free(ctx);
        return PICOKEY_WRONG_DATA;
    }
    if (mbedtls_rsa_check_privkey(ctx) != 0) {
        mbedtls_rsa_free(ctx);
        return PICOKEY_WRONG_DATA;
    }
    return PICOKEY_OK;
}

int load_private_key_ecdsa(mbedtls_ecp_keypair *ctx, file_t *fkey, bool use_dek) {
    int key_size = file_get_size(fkey);
    uint8_t kdata[67]; //Worst case, 521 bit + 1byte
    memcpy(kdata, file_get_data(fkey), key_size);
    if (use_dek && dek_decrypt(kdata, key_size) != 0) {
        return PICOKEY_EXEC_ERROR;
    }
    mbedtls_ecp_group_id gid = kdata[0];
    int r = mbedtls_ecp_read_key(gid, ctx, kdata + 1, key_size - 1);
    if (r != 0) {
        mbedtls_ecp_keypair_free(ctx);
        return PICOKEY_EXEC_ERROR;
    }
    mbedtls_platform_zeroize(kdata, sizeof(kdata));
    if (ctx->grp.id == MBEDTLS_ECP_DP_ED25519) {
        r = mbedtls_ecp_point_edwards(&ctx->grp, &ctx->Q, &ctx->d, random_gen, NULL);
    }
    else {
        r = mbedtls_ecp_mul(&ctx->grp, &ctx->Q, &ctx->d, &ctx->grp.G, random_gen, NULL);
    }
    if (r != 0) {
        mbedtls_ecdsa_free(ctx);
        return PICOKEY_EXEC_ERROR;
    }
    return PICOKEY_OK;
}

int load_aes_key(uint8_t *aes_key, file_t *fkey) {
    int key_size = file_get_size(fkey);
    memcpy(aes_key, file_get_data(fkey), key_size);
    if (dek_decrypt(aes_key, key_size) != 0) {
        return PICOKEY_EXEC_ERROR;
    }
    return PICOKEY_OK;
}

mbedtls_ecp_group_id get_ec_group_id_from_attr(const uint8_t *algo, size_t algo_len) {
    if (memcmp(algorithm_attr_p256k1 + 2, algo, algo_len) == 0) {
        return MBEDTLS_ECP_DP_SECP256K1;
    }
    else if (memcmp(algorithm_attr_p256r1 + 2, algo, algo_len) == 0) {
        return MBEDTLS_ECP_DP_SECP256R1;
    }
    else if (memcmp(algorithm_attr_p384r1 + 2, algo, algo_len) == 0) {
        return MBEDTLS_ECP_DP_SECP384R1;
    }
    else if (memcmp(algorithm_attr_p521r1 + 2, algo, algo_len) == 0) {
        return MBEDTLS_ECP_DP_SECP521R1;
    }
    else if (memcmp(algorithm_attr_bp256r1 + 2, algo, algo_len) == 0) {
        return MBEDTLS_ECP_DP_BP256R1;
    }
    else if (memcmp(algorithm_attr_bp384r1 + 2, algo, algo_len) == 0) {
        return MBEDTLS_ECP_DP_BP384R1;
    }
    else if (memcmp(algorithm_attr_bp512r1 + 2, algo, algo_len) == 0) {
        return MBEDTLS_ECP_DP_BP512R1;
    }
    else if (memcmp(algorithm_attr_cv25519 + 2, algo, algo_len) == 0) {
        return MBEDTLS_ECP_DP_CURVE25519;
    }
    else if (memcmp(algorithm_attr_x448 + 2, algo, algo_len) == 0) {
        return MBEDTLS_ECP_DP_CURVE448;
    }
    else if (memcmp(algorithm_attr_ed25519 + 2, algo, algo_len) == 0) {
        return MBEDTLS_ECP_DP_ED25519;
    }
    return MBEDTLS_ECP_DP_NONE;
}

void make_rsa_response(mbedtls_rsa_context *rsa) {
    memcpy(res_APDU, "\x7f\x49\x82\x00\x00", 5);
    res_APDU_size = 5;
    res_APDU[res_APDU_size++] = 0x81;
    res_APDU[res_APDU_size++] = 0x82;
    put_uint16_t_be(mbedtls_mpi_size(&rsa->N), res_APDU + res_APDU_size); res_APDU_size += 2;
    mbedtls_mpi_write_binary(&rsa->N, res_APDU + res_APDU_size, mbedtls_mpi_size(&rsa->N));
    res_APDU_size += mbedtls_mpi_size(&rsa->N);
    res_APDU[res_APDU_size++] = 0x82;
    res_APDU[res_APDU_size++] = mbedtls_mpi_size(&rsa->E) & 0xff;
    mbedtls_mpi_write_binary(&rsa->E, res_APDU + res_APDU_size, mbedtls_mpi_size(&rsa->E));
    res_APDU_size += mbedtls_mpi_size(&rsa->E);
    put_uint16_t_be(res_APDU_size - 5, res_APDU + 3);
}

void make_ecdsa_response(mbedtls_ecp_keypair *ecdsa) {
    uint8_t pt[MBEDTLS_ECP_MAX_PT_LEN];
    size_t plen = 0;
    mbedtls_ecp_point_write_binary(&ecdsa->grp,
                                   &ecdsa->Q,
                                   MBEDTLS_ECP_PF_UNCOMPRESSED,
                                   &plen,
                                   pt,
                                   sizeof(pt));
    res_APDU[res_APDU_size++] = 0x7f;
    res_APDU[res_APDU_size++] = 0x49;
    if (plen >= 128) {
        res_APDU[res_APDU_size++] = 0x81;
    }
    res_APDU[res_APDU_size++] = plen + (plen >= 128 ? 3 : 2);
    res_APDU[res_APDU_size++] = 0x86;
    if (plen >= 128) {
        res_APDU[res_APDU_size++] = 0x81;
    }
    res_APDU[res_APDU_size++] = plen;
    memcpy(res_APDU + res_APDU_size, pt, plen);
    res_APDU_size += plen;
}

static int cmd_keypair_gen() {
    if (P2(apdu) != 0x0) {
        return SW_INCORRECT_P1P2();
    }
    if (apdu.nc != 2 && apdu.nc != 5) {
        return SW_WRONG_LENGTH();
    }
    if (!has_pw3 && P1(apdu) == 0x80) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }

    uint16_t fid = 0x0;
    int r = PICOKEY_OK;
    if (apdu.data[0] == 0xB6) {
        fid = EF_PK_SIG;
    }
    else if (apdu.data[0] == 0xB8) {
        fid = EF_PK_DEC;
    }
    else if (apdu.data[0] == 0xA4) {
        fid = EF_PK_AUT;
    }
    else {
        return SW_WRONG_DATA();
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
    if (P1(apdu) == 0x80) { //generate
        if (algo[0] == ALGO_RSA) {
            int exponent = 65537, nlen = (algo[1] << 8) | algo[2];
            printf("KEYPAIR RSA %d\r\n", nlen);
            //if (nlen != 2048 && nlen != 4096)
            //    return SW_FUNC_NOT_SUPPORTED();
            mbedtls_rsa_context rsa;
            mbedtls_rsa_init(&rsa);
            uint8_t index = 0;
            r = mbedtls_rsa_gen_key(&rsa, random_gen, &index, nlen, exponent);
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
        else if (algo[0] == ALGO_ECDH || algo[0] == ALGO_ECDSA || algo[0] == ALGO_EDDSA) {
            printf("KEYPAIR ECDSA\r\n");
            mbedtls_ecp_group_id gid = get_ec_group_id_from_attr(algo + 1, algo_len - 1);
            if (gid == MBEDTLS_ECP_DP_NONE) {
                return SW_FUNC_NOT_SUPPORTED();
            }
            mbedtls_ecp_keypair ecdsa;
            mbedtls_ecp_keypair_init(&ecdsa);
            uint8_t index = 0;
            r = mbedtls_ecdsa_genkey(&ecdsa, gid, random_gen, &index);
            if (r != 0) {
                mbedtls_ecp_keypair_free(&ecdsa);
                return SW_EXEC_ERROR();
            }
            r = store_keys(&ecdsa, algo[0], fid, true);
            make_ecdsa_response(&ecdsa);
            mbedtls_ecp_keypair_free(&ecdsa);
            if (r != PICOKEY_OK) {
                return SW_EXEC_ERROR();
            }
        }
        else {
            return SW_FUNC_NOT_SUPPORTED();
        }
        file_t *pbef = search_by_fid(fid + 3, NULL, SPECIFY_EF);
        if (!pbef) {
            return SW_REFERENCE_NOT_FOUND();
        }
        r = file_put_data(pbef, res_APDU, res_APDU_size);
        if (r != PICOKEY_OK) {
            return SW_EXEC_ERROR();
        }
        if (fid == EF_PK_SIG) {
            reset_sig_count();
        }
        else if (fid == EF_PK_DEC) {
            // OpenPGP does not allow generating AES keys. So, we generate a new one when gen for DEC is called.
            // It is a 256 AES key by default.
            uint8_t aes_key[32]; //maximum AES key size
            uint8_t key_size = 32;
            memcpy(aes_key, random_bytes_get(key_size), key_size);
            r = store_keys(aes_key, ALGO_AES_256, EF_AES_KEY, true);
            /* if storing the key fails, we silently continue */
            //if (r != PICOKEY_OK)
            //    return SW_EXEC_ERROR();
        }
        low_flash_available();
        return SW_OK();
    }
    else if (P1(apdu) == 0x81) { //read
        file_t *ef = search_by_fid(fid + 3, NULL, SPECIFY_EF);
        if (!ef || !ef->data) {
            return SW_REFERENCE_NOT_FOUND();
        }
        res_APDU_size = file_get_size(ef);
        memcpy(res_APDU, file_get_data(ef), res_APDU_size);
        return SW_OK();
    }
    return SW_INCORRECT_P1P2();
}

int rsa_sign(mbedtls_rsa_context *ctx,
             const uint8_t *data,
             size_t data_len,
             uint8_t *out,
             size_t *out_len) {
    uint8_t *d = (uint8_t *) data, *end = d + data_len, *hsh = NULL;
    size_t seq_len = 0, hash_len = 0;
    int key_size = ctx->len, r = 0;
    mbedtls_md_type_t md = MBEDTLS_MD_NONE;
    if (mbedtls_asn1_get_tag(&d, end, &seq_len,
                             MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) == 0) {
        mbedtls_asn1_buf mdb;
        r = mbedtls_asn1_get_alg_null(&d, end, &mdb);
        if (r == 0) {
            if (mbedtls_asn1_get_tag(&d, end, &hash_len, MBEDTLS_ASN1_OCTET_STRING) == 0) {
                if (memcmp(mdb.p, "\x2B\x0E\x03\x02\x1A", 5) == 0) {
                    md = MBEDTLS_MD_SHA1;
                }
                else if (memcmp(mdb.p, "\x60\x86\x48\x01\x65\x03\x04\x02\x04", 9) == 0) {
                    md = MBEDTLS_MD_SHA224;
                }
                else if (memcmp(mdb.p, "\x60\x86\x48\x01\x65\x03\x04\x02\x01", 9) == 0) {
                    md = MBEDTLS_MD_SHA256;
                }
                else if (memcmp(mdb.p, "\x60\x86\x48\x01\x65\x03\x04\x02\x02", 9) == 0) {
                    md = MBEDTLS_MD_SHA384;
                }
                else if (memcmp(mdb.p, "\x60\x86\x48\x01\x65\x03\x04\x02\x03", 9) == 0) {
                    md = MBEDTLS_MD_SHA512;
                }
                hsh = d;
            }
        }
    }
    if (md == MBEDTLS_MD_NONE) {
        if (data_len == 32) {
            md = MBEDTLS_MD_SHA256;
        }
        else if (data_len == 20) {
            md = MBEDTLS_MD_SHA1;
        }
        else if (data_len == 28) {
            md = MBEDTLS_MD_SHA224;
        }
        else if (data_len == 48) {
            md = MBEDTLS_MD_SHA384;
        }
        else if (data_len == 64) {
            md = MBEDTLS_MD_SHA512;
        }
        hash_len = data_len;
        hsh = (uint8_t *) data;
    }
    if (md == MBEDTLS_MD_NONE) {
        if (data_len < key_size) { //needs padding
            memset((uint8_t *) data + data_len, 0, key_size - data_len);
        }
        r = mbedtls_rsa_private(ctx, random_gen, NULL, data, out);
    }
    else {
        uint8_t *signature = (uint8_t *) calloc(key_size, sizeof(uint8_t));
        r = mbedtls_rsa_pkcs1_sign(ctx, random_gen, NULL, md, hash_len, hsh, signature);
        memcpy(out, signature, key_size);
        free(signature);
    }
    *out_len = key_size;
    return r;
}

int ecdsa_sign(mbedtls_ecp_keypair *ctx,
               const uint8_t *data,
               size_t data_len,
               uint8_t *out,
               size_t *out_len) {

    int r = 0;
    if (ctx->grp.id == MBEDTLS_ECP_DP_ED25519) {
        r = mbedtls_eddsa_write_signature(ctx, data, data_len, out, 64, out_len, MBEDTLS_EDDSA_PURE, NULL, 0, random_gen, NULL);
    }
    else {
        mbedtls_mpi ri, si;
        mbedtls_mpi_init(&ri);
        mbedtls_mpi_init(&si);
        r = mbedtls_ecdsa_sign(&ctx->grp, &ri, &si, &ctx->d, data, data_len, random_gen, NULL);
        if (r == 0) {
            size_t plen = (ctx->grp.nbits + 7) / 8;
            mbedtls_mpi_write_binary(&ri, out, plen);
            mbedtls_mpi_write_binary(&si, out + plen, plen);
            *out_len = 2 * plen;
        }
        mbedtls_mpi_free(&ri);
        mbedtls_mpi_free(&si);
    }
    return r;
}

static int cmd_pso() {
    uint16_t algo_fid = 0x0, pk_fid = 0x0;
    bool is_aes = false;
    if (P1(apdu) == 0x9E && P2(apdu) == 0x9A) {
        if (!has_pw3 && !has_pw1) {
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
        algo_fid = EF_ALGO_PRIV1;
        pk_fid = EF_PK_SIG;
    }
    else if (P1(apdu) == 0x80 && P2(apdu) == 0x86) {
        if (!has_pw3 && !has_pw2) {
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
        algo_fid = algo_dec;
        pk_fid = pk_dec;
    }
    else {
        return SW_INCORRECT_P1P2();
    }
    file_t *algo_ef = search_by_fid(algo_fid, NULL, SPECIFY_EF);
    if (!algo_ef) {
        return SW_REFERENCE_NOT_FOUND();
    }
    const uint8_t *algo = algorithm_attr_rsa2k + 1;
    if (algo_ef && algo_ef->data) {
        algo = file_get_data(algo_ef);
    }
    if (apdu.data[0] == 0x2) { //AES PSO?
        if (((apdu.nc - 1) % 16 == 0 && P1(apdu) == 0x80 && P2(apdu) == 0x86) ||
            (apdu.nc % 16 == 0 && P1(apdu) == 0x86 && P2(apdu) == 0x80)) {
            pk_fid = EF_AES_KEY;
            is_aes = true;
        }
    }
    file_t *ef = search_by_fid(pk_fid, NULL, SPECIFY_EF);
    if (!ef) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (wait_button_pressed(pk_fid == EF_PK_SIG ? EF_UIF_SIG : EF_UIF_DEC) == true) {
        return SW_SECURE_MESSAGE_EXEC_ERROR();
    }
    int r = PICOKEY_OK;
    int key_size = file_get_size(ef);
    if (is_aes) {
        uint8_t aes_key[32];
        r = load_aes_key(aes_key, ef);
        if (r != PICOKEY_OK) {
            memset(aes_key, 0, sizeof(aes_key));
            return SW_EXEC_ERROR();
        }
        if (P1(apdu) == 0x80 && P2(apdu) == 0x86) { //decipher
            r = aes_decrypt(aes_key, NULL, key_size, PICO_KEYS_AES_MODE_CBC, apdu.data + 1, apdu.nc - 1);
            memset(aes_key, 0, sizeof(aes_key));
            if (r != PICOKEY_OK) {
                return SW_EXEC_ERROR();
            }
            memcpy(res_APDU, apdu.data + 1, apdu.nc - 1);
            res_APDU_size = apdu.nc - 1;
        }
        else if (P1(apdu) == 0x86 && P2(apdu) == 0x80) { //encipher
            r = aes_encrypt(aes_key, NULL, key_size, PICO_KEYS_AES_MODE_CBC, apdu.data, apdu.nc);
            memset(aes_key, 0, sizeof(aes_key));
            if (r != PICOKEY_OK) {
                return SW_EXEC_ERROR();
            }
            res_APDU[0] = 0x2;
            memcpy(res_APDU + 1, apdu.data, apdu.nc);
            res_APDU_size = apdu.nc + 1;
        }
        return SW_OK();
    }
    if (algo[0] == ALGO_RSA) {
        mbedtls_rsa_context ctx;
        mbedtls_rsa_init(&ctx);
        r = load_private_key_rsa(&ctx, ef, true);
        if (r != PICOKEY_OK) {
            mbedtls_rsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        if (P1(apdu) == 0x9E && P2(apdu) == 0x9A) {
            size_t olen = 0;
            r = rsa_sign(&ctx, apdu.data, apdu.nc, res_APDU, &olen);
            mbedtls_rsa_free(&ctx);
            if (r != 0) {
                return SW_EXEC_ERROR();
            }
            res_APDU_size = olen;
            //apdu.ne = key_size;
            inc_sig_count();
        }
        else if (P1(apdu) == 0x80 && P2(apdu) == 0x86) {
            if (apdu.nc < key_size) { //needs padding
                memset(apdu.data + apdu.nc, 0, key_size - apdu.nc);
            }
            size_t olen = 0;
            r = mbedtls_rsa_pkcs1_decrypt(&ctx,
                                          random_gen,
                                          NULL,
                                          &olen,
                                          apdu.data + 1,
                                          res_APDU,
                                          key_size);
            mbedtls_rsa_free(&ctx);
            if (r != 0) {
                return SW_EXEC_ERROR();
            }
            res_APDU_size = olen;
        }
    }
    else if (algo[0] == ALGO_ECDH || algo[0] == ALGO_ECDSA || algo[0] == ALGO_EDDSA) {
        if (P1(apdu) == 0x9E && P2(apdu) == 0x9A) {
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
            inc_sig_count();
        }
        else if (P1(apdu) == 0x80 && P2(apdu) == 0x86) {
            mbedtls_ecdh_context ctx;
            uint8_t kdata[67];
            uint8_t *data = apdu.data, *end = data + apdu.nc;
            size_t len = 0;
            if (mbedtls_asn1_get_tag(&data, end, &len, 0xA6) != 0) {
                return SW_WRONG_DATA();
            }
            if (*data++ != 0x7f) {
                return SW_WRONG_DATA();
            }
            if (mbedtls_asn1_get_tag(&data, end, &len,
                                     0x49) != 0 ||
                mbedtls_asn1_get_tag(&data, end, &len, 0x86) != 0) {
                return SW_WRONG_DATA();
            }
            //if (len != 2*key_size-1)
            //    return SW_WRONG_LENGTH();
            memcpy(kdata, file_get_data(ef), key_size);
            if (dek_decrypt(kdata, key_size) != 0) {
                return SW_EXEC_ERROR();
            }
            mbedtls_ecdh_init(&ctx);
            mbedtls_ecp_group_id gid = kdata[0];
            r = mbedtls_ecdh_setup(&ctx, gid);
            if (r != 0) {
                mbedtls_ecdh_free(&ctx);
                return SW_DATA_INVALID();
            }
            r = mbedtls_ecp_read_key(gid, (mbedtls_ecdsa_context *)&ctx.ctx.mbed_ecdh, kdata + 1, key_size - 1);
            if (r != 0) {
                mbedtls_ecdh_free(&ctx);
                return SW_DATA_INVALID();
            }
            r = mbedtls_ecdh_read_public(&ctx, data - 1, len + 1);
            if (r != 0) {
                mbedtls_ecdh_free(&ctx);
                return SW_DATA_INVALID();
            }
            size_t olen = 0;
            r = mbedtls_ecdh_calc_secret(&ctx,
                                         &olen,
                                         res_APDU,
                                         MBEDTLS_ECP_MAX_BYTES,
                                         random_gen,
                                         NULL);
            if (r != 0) {
                mbedtls_ecdh_free(&ctx);
                return SW_EXEC_ERROR();
            }
            res_APDU_size = olen;
            mbedtls_ecdh_free(&ctx);
        }
    }
    return SW_OK();
}

static int cmd_terminate_df() {
    if (P1(apdu) != 0x0 || P2(apdu) != 0x0) {
        return SW_INCORRECT_P1P2();
    }
    file_t *retries;
    if (!(retries = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!has_pw3 && *(file_get_data(retries) + 6) > 0) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (apdu.nc != 0) {
        return SW_WRONG_LENGTH();
    }
    initialize_flash(true);
    scan_files();
    return SW_OK();
}

static int cmd_activate_file() {
    return SW_OK();
}

static int cmd_challenge() {
    uint8_t *rb = (uint8_t *) random_bytes_get(apdu.ne);
    if (!rb) {
        return SW_WRONG_LENGTH();
    }
    memcpy(res_APDU, rb, apdu.ne);
    res_APDU_size = apdu.ne;
    return SW_OK();
}

static int cmd_internal_aut() {
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
    if (wait_button_pressed(EF_UIF_AUT) == true) {
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

static int cmd_mse() {
    if (P1(apdu) != 0x41 || (P2(apdu) != 0xA4 && P2(apdu) != 0xB8)) {
        return SW_WRONG_P1P2();
    }
    if (apdu.data[0] != 0x83 || apdu.data[1] != 0x1 ||
        (apdu.data[2] != 0x2 && apdu.data[2] != 0x3)) {
        return SW_WRONG_DATA();
    }
    if (P2(apdu) == 0xA4) {
        if (apdu.data[2] == 0x2) {
            algo_dec = EF_ALGO_PRIV2;
            pk_dec = EF_PK_DEC;
        }
        else if (apdu.data[2] == 0x3) {
            algo_dec = EF_ALGO_PRIV3;
            pk_dec = EF_PK_AUT;
        }
    }
    else if (P2(apdu) == 0xB8) {
        if (apdu.data[2] == 0x2) {
            algo_aut = EF_ALGO_PRIV2;
            pk_aut = EF_PK_DEC;
        }
        else if (apdu.data[2] == 0x3) {
            algo_aut = EF_ALGO_PRIV3;
            pk_aut = EF_PK_AUT;
        }
    }
    return SW_OK();
}

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

static int cmd_import_data() {
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
        if (ecdsa.grp.id == MBEDTLS_ECP_DP_ED25519) {
            r = mbedtls_ecp_point_edwards(&ecdsa.grp, &ecdsa.Q, &ecdsa.d, random_gen, NULL);
        }
        else {
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

static int cmd_version() {
    res_APDU[res_APDU_size++] = PIPGP_VERSION_MAJOR;
    res_APDU[res_APDU_size++] = PIPGP_VERSION_MINOR;
    res_APDU[res_APDU_size++] = 0x0;
    return SW_OK();
}

static int cmd_select_data() {
    file_t *ef = NULL;
    uint16_t fid = 0x0;
    if (P2(apdu) != 0x4) {
        return SW_WRONG_P1P2();
    }
    if (apdu.data[0] != 0x60) {
        return SW_WRONG_DATA();
    }
    if (apdu.nc != apdu.data[1] + 2 || apdu.nc < 5) {
        return SW_WRONG_LENGTH();
    }
    if (apdu.data[2] != 0x5C) {
        return SW_WRONG_DATA();
    }
    if (apdu.data[3] == 2) {
        fid = (apdu.data[4] << 8) | apdu.data[5];
    }
    else {
        fid = apdu.data[4];
    }
    if (!(ef = search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!authenticate_action(ef, ACL_OP_UPDATE_ERASE)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    fid &= ~0x6000; //Now get private DO
    fid += P1(apdu);
    if (!(ef = search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    select_file(ef);
    return SW_OK();
}

static int cmd_get_next_data() {
    file_t *ef = NULL;
    if (apdu.nc > 0) {
        return SW_WRONG_LENGTH();
    }
    if (!currentEF) {
        return SW_RECORD_NOT_FOUND();
    }
    uint16_t fid = (P1(apdu) << 8) | P2(apdu);
    if (!(ef = search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!authenticate_action(ef, ACL_OP_UPDATE_ERASE)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if ((currentEF->fid & 0x1FF0) != (fid & 0x1FF0)) {
        return SW_WRONG_P1P2();
    }
    fid = currentEF->fid + 1; //curentEF contains private DO. so, we select the next one
    if (!(ef = search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    select_file(ef);
    return cmd_get_data();
}

#define INS_VERIFY          0x20
#define INS_MSE             0x22
#define INS_CHANGE_PIN      0x24
#define INS_PSO             0x2A
#define INS_RESET_RETRY     0x2C
#define INS_ACTIVATE_FILE   0x44
#define INS_KEYPAIR_GEN     0x47
#define INS_CHALLENGE       0x84
#define INS_INTERNAL_AUT    0x88
#define INS_SELECT          0xA4
#define INS_SELECT_DATA     0xA5
#define INS_GET_DATA        0xCA
#define INS_GET_NEXT_DATA   0xCC
#define INS_PUT_DATA        0xDA
#define INS_IMPORT_DATA     0xDB
#define INS_TERMINATE_DF    0xE6
#define INS_VERSION         0xF1

static const cmd_t cmds[] = {
    { INS_GET_DATA, cmd_get_data },
    { INS_SELECT, cmd_select },
    { INS_VERIFY, cmd_verify },
    { INS_PUT_DATA, cmd_put_data },
    { INS_CHANGE_PIN, cmd_change_pin },
    { INS_RESET_RETRY, cmd_reset_retry },
    { INS_KEYPAIR_GEN, cmd_keypair_gen },
    { INS_PSO, cmd_pso },
    { INS_TERMINATE_DF, cmd_terminate_df },
    { INS_ACTIVATE_FILE, cmd_activate_file },
    { INS_CHALLENGE, cmd_challenge },
    { INS_INTERNAL_AUT, cmd_internal_aut },
    { INS_MSE, cmd_mse },
    { INS_IMPORT_DATA, cmd_import_data },
    { INS_VERSION, cmd_version },
    { INS_SELECT_DATA, cmd_select_data },
    { INS_GET_NEXT_DATA, cmd_get_next_data },
    { 0x00, 0x0 }
};

int openpgp_process_apdu() {
    sm_unwrap();
    for (const cmd_t *cmd = cmds; cmd->ins != 0x00; cmd++) {
        if (cmd->ins == INS(apdu)) {
            int r = cmd->cmd_handler();
            sm_wrap();
            return r;
        }
    }
    return SW_INS_NOT_SUPPORTED();
}
