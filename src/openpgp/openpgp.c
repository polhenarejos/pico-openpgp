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

#include <stdio.h>
#ifdef ESP_PLATFORM
#include "esp_compat.h"
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#endif
#include "openpgp.h"
#include "key_container.h"
#include "serial.h"
#include "version.h"
#include "random.h"
#include "eac.h"
#include "mbedtls/asn1.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "usb.h"
#include "ccid/ccid.h"
#include "led/led.h"
#include "otp.h"
#include "do.h"
#ifdef MBEDTLS_EDDSA_C
#include "mbedtls/eddsa.h"
#endif
#include "mbedtls/constant_time.h"

bool has_pw1 = false;
bool has_pw2 = false;
bool has_pw3 = false;
bool has_rc = false;
uint8_t session_pw1[32];
uint8_t session_rc[32];
uint8_t session_pw3[32];
uint8_t dek[DEK_SIZE];
uint16_t algo_dec = EF_ALGO_PRIV2, algo_aut = EF_ALGO_PRIV3, pk_dec = EF_PK_DEC, pk_aut = EF_PK_AUT;
extern bool is_gpg;

#ifdef ENABLE_ADMINLESS_MODE
enum {
    ADMINLESS_MODE_PENDING = 0,
    ADMINLESS_MODE_ENABLED = 1,
    ADMINLESS_MODE_DISABLED = 2,
    ADMINLESS_MODE_KDF_MIGRATION = 3,
};

#define ADMINLESS_MODE_OFFSET (6u)
#define ADMINLESS_RETRIES_SIZE (ADMINLESS_MODE_OFFSET + 1)

static int adminless_set_mode(uint8_t mode) {
    file_t *ef = file_search_by_fid(EF_PW_RETRIES, NULL, SPECIFY_EF);
    if (!ef) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    uint8_t retries[16] = { 0x1, 3, 3, 3, 3, 3, ADMINLESS_MODE_DISABLED };
    uint16_t retries_len = ADMINLESS_RETRIES_SIZE;
    if (file_has_data(ef)) {
        retries_len = MAX(file_get_size(ef), retries_len);
        if (retries_len > sizeof(retries)) {
            return PICOKEYS_ERR_NO_MEMORY;
        }
        memcpy(retries, file_get_data(ef), file_get_size(ef));
    }
    retries[ADMINLESS_MODE_OFFSET] = mode;
    return file_put_data(ef, CONST_BYTE_ARRAY(retries, retries_len));
}

static bool adminless_mode_is(uint8_t mode) {
    file_t *ef = file_search_by_fid(EF_PW_RETRIES, NULL, SPECIFY_EF);
    return ef && file_has_data(ef) && file_get_size(ef) >= ADMINLESS_RETRIES_SIZE && file_get_data(ef)[ADMINLESS_MODE_OFFSET] == mode;
}

static bool pin_is_factory_default(const file_t *pin, const uint8_t *factory_pin, size_t factory_pin_len) {
    uint8_t verifier[34];

    if (!pin || !file_has_data(pin)) {
        return false;
    }
    if (file_get_size(pin) == 33) {
        verifier[0] = factory_pin_len;
        double_hash_pin(CONST_BYTE_ARRAY(factory_pin, factory_pin_len), verifier + 1);
        return mbedtls_ct_memcmp(file_get_data(pin), verifier, 33) == 0;
    }
    if (file_get_size(pin) == 34) {
        verifier[0] = factory_pin_len;
        verifier[1] = 0x1;
        pin_derive_verifier(CONST_BYTE_ARRAY(factory_pin, factory_pin_len), verifier + 2);
        return mbedtls_ct_memcmp(file_get_data(pin), verifier, sizeof(verifier)) == 0;
    }
    return false;
}

static bool pw1_and_pw3_are_factory_default(void) {
    static const uint8_t factory_pw1[] = "123456";
    static const uint8_t factory_pw3[] = "12345678";

    return pin_is_factory_default(file_search_by_fid(EF_PW1, NULL, SPECIFY_EF), factory_pw1, sizeof(factory_pw1) - 1)
        && pin_is_factory_default(file_search_by_fid(EF_PW3, NULL, SPECIFY_EF), factory_pw3, sizeof(factory_pw3) - 1);
}

bool openpgp_adminless_is_pending(void) {
    return adminless_mode_is(ADMINLESS_MODE_PENDING);
}

bool openpgp_adminless_is_active(void) {
    return adminless_mode_is(ADMINLESS_MODE_ENABLED);
}

int openpgp_adminless_begin_kdf_migration(void) {
    if (!openpgp_adminless_is_pending()) {
        return PICOKEYS_OK;
    }
    return adminless_set_mode(ADMINLESS_MODE_KDF_MIGRATION);
}

int openpgp_adminless_sync_pw3(const uint8_t *pin, size_t pin_len, const uint8_t verifier[34]) {
    file_t *pw3 = file_search_by_fid(EF_PW3, NULL, SPECIFY_EF);
    file_t *dek_pw3 = file_search_by_fid(EF_DEK_PW3, NULL, SPECIFY_EF);
    if (!pw3 || !dek_pw3) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    int r = file_put_data(pw3, CONST_BYTE_ARRAY(verifier, 34));
    if (r != PICOKEYS_OK) {
        return r;
    }
    uint8_t encrypted_dek[DEK_FILE_SIZE];
    encrypted_dek[0] = 0x3;
    pin_derive_session(CONST_BYTE_ARRAY(pin, pin_len), session_pw3);
    r = encrypt_with_aad(session_pw3, CONST_BYTE_ARRAY(dek, DEK_SIZE), PIN_KDF_DEFAULT_VERSION, encrypted_dek + 1);
    if (r != PICOKEYS_OK) {
        return r;
    }
    return file_put_data(dek_pw3, CONST_BYTE_ARRAY(encrypted_dek, sizeof(encrypted_dek)));
}

int openpgp_adminless_enable(void) {
    file_t *pw_status = file_search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF);
    if (!pw_status || !file_has_data(pw_status) || file_get_size(pw_status) == 0 || file_get_size(pw_status) > 16) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    uint8_t status[16];
    uint16_t status_len = file_get_size(pw_status);
    memcpy(status, file_get_data(pw_status), status_len);
    status[0] = 0x0; // Require PW1 for every signature in admin-less mode.
    int r = file_put_data(pw_status, CONST_BYTE_ARRAY(status, status_len));
    if (r != PICOKEYS_OK) {
        return r;
    }
    r = adminless_set_mode(ADMINLESS_MODE_ENABLED);
    if (r == PICOKEYS_OK && has_pw1) {
        has_pw3 = true;
    }
    return r;
}

int openpgp_adminless_disable(void) {
    return adminless_set_mode(ADMINLESS_MODE_DISABLED);
}

int openpgp_adminless_reset(void) {
    return adminless_set_mode(ADMINLESS_MODE_PENDING);
}
#endif

static bool pin_record_matches_value(const file_t *pin, const uint8_t *value, size_t value_len) {
    uint8_t verifier[34];

    if (!pin || !file_has_data(pin)) {
        return false;
    }
    if (file_get_size(pin) == 33) {
        verifier[0] = value_len;
        double_hash_pin(CONST_BYTE_ARRAY(value, value_len), verifier + 1);
        return mbedtls_ct_memcmp(file_get_data(pin), verifier, 33) == 0;
    }
    if (file_get_size(pin) == 34) {
        verifier[0] = value_len;
        verifier[1] = 0x1;
        pin_derive_verifier(CONST_BYTE_ARRAY(value, value_len), verifier + 2);
        return mbedtls_ct_memcmp(file_get_data(pin), verifier, sizeof(verifier)) == 0;
    }
    return false;
}

static bool reset_code_is_public_default(const file_t *rc) {
    static const uint8_t default_reset_code[] = "12345678";

    return pin_record_matches_value(rc, default_reset_code, sizeof(default_reset_code) - 1);
}

static int set_reset_code_retries(uint8_t retries) {
    file_t *pw_status = file_search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF);
    if (!pw_status || !file_has_data(pw_status)) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    uint16_t status_len = file_get_size(pw_status);
    if (3 + (EF_RC & 0xf) >= status_len || status_len > 64) {
        return PICOKEYS_ERR_MEMORY_FATAL;
    }

    uint8_t status[64];
    memcpy(status, file_get_data(pw_status), status_len);
    if (status[3 + (EF_RC & 0xf)] == retries) {
        return PICOKEYS_OK;
    }
    status[3 + (EF_RC & 0xf)] = retries;
    return file_put_data(pw_status, CONST_BYTE_ARRAY(status, status_len));
}

int openpgp_reset_code_deactivate(void) {
    int r = PICOKEYS_OK;
    file_t *rc = file_search_by_fid(EF_RC, NULL, SPECIFY_EF);
    file_t *dek_rc = file_search_by_fid(EF_DEK_RC, NULL, SPECIFY_EF);

    if (rc && file_has_data(rc)) {
        r = flash_clear_file(rc);
    }
    if (r == PICOKEYS_OK && dek_rc && file_has_data(dek_rc)) {
        r = flash_clear_file(dek_rc);
    }
    if (r == PICOKEYS_OK) {
        r = set_reset_code_retries(0);
    }
    has_rc = false;
    mbedtls_platform_zeroize(session_rc, sizeof(session_rc));
    return r;
}

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

int openpgp_process_apdu(void);

extern uint32_t board_button_read(void);

bool wait_button_pressed_fid(uint16_t fid) {
    uint32_t val = EV_PRESS_BUTTON;
#ifndef ENABLE_EMULATION
    file_t *ef = file_search_by_fid(fid, NULL, SPECIFY_ANY);
    if (ef && ef->data && file_get_data(ef)[0] > 0) {
        queue_try_add(&card_to_usb_q, &val);
        do {
            queue_remove_blocking(&usb_to_card_q, &val);
        }while (val != EV_BUTTON_PRESSED && val != EV_BUTTON_TIMEOUT);
    }
#else
    (void) fid;
#endif
    return val == EV_BUTTON_TIMEOUT;
}

void signal_private_key_use(uint16_t uif_fid) {
#ifndef ENABLE_EMULATION
    file_t *ef = file_search_by_fid(uif_fid, NULL, SPECIFY_ANY);
    if (ef == NULL || ef->data == NULL || file_get_data(ef)[0] == 0) {
        led_blink_n_times(3, LED_COLOR_GREEN, 100, 100);
    }
#else
    (void)uif_fid;
#endif
}

void select_file(file_t *pe) {
    if (!pe) {
        currentDF = (file_t *) MF;
        currentEF = NULL;
    }
    else if (file_get_type(pe) & FILE_TYPE_INTERNAL_EF) {
        currentEF = pe;
        currentDF = get_parent(pe);
    }
    else {
        currentDF = pe;
    }
    if (currentEF == file_openpgp) {
        selected_applet = currentEF;
        //sc_hsm_unload(); //reset auth status
    }
}

void scan_files_openpgp(void) {
    file_scan_flash();
    file_t *ef;
    if ((ef = file_search_by_fid(EF_FULL_AID, NULL, SPECIFY_ANY))) {
        ef->data = openpgp_aid_full;
        memcpy(ef->data + 12, pico_serial.id, 4);
    }
    bool reset_dek = false;
    bool bootstrap_legacy = false;
    file_t *ef_dek = file_search_by_fid(EF_DEK, NULL, SPECIFY_ANY), *ef_dek_pw1 = file_search_by_fid(EF_DEK_PW1, NULL, SPECIFY_ANY), *ef_dek_rc = file_search_by_fid(EF_DEK_RC, NULL, SPECIFY_ANY), *ef_dek_pw3 = file_search_by_fid(EF_DEK_PW3, NULL, SPECIFY_ANY);
    if (!file_has_data(ef_dek_pw1) && !file_has_data(ef_dek_rc) && !file_has_data(ef_dek_pw3) && !file_has_data(ef_dek)) {
        printf("DEK are empty\r\n");
        const uint8_t *random_dek = random_bytes_get(DEK_SIZE);
        const uint8_t def1[6] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36};
        const uint8_t def3[8] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
#ifdef OPENPGP_TEST_INIT_LEGACY_PIN
        /* Test hook: bootstrap legacy PIN+DEK format to validate runtime migration paths. */

        uint8_t def[IV_SIZE + 32 + 32 + 32];
        memcpy(def, random_dek, IV_SIZE + 32);
        memcpy(def + IV_SIZE + 32, random_dek + IV_SIZE, 32);
        memcpy(def + IV_SIZE + 32 + 32, random_dek + IV_SIZE, 32);
        hash_multi(CONST_BYTE_ARRAY(def1, sizeof(def1)), session_pw1);
        aes_encrypt_cfb_256(session_pw1, def, BYTE_ARRAY(def + IV_SIZE, 32));
        memset(session_pw1, 0, sizeof(session_pw1));

        hash_multi(CONST_BYTE_ARRAY(def3, sizeof(def3)), session_pw3);
        aes_encrypt_cfb_256(session_pw3, def, BYTE_ARRAY(def + IV_SIZE + 32, 32));
        aes_encrypt_cfb_256(session_pw3, def, BYTE_ARRAY(def + IV_SIZE + 32 + 32, 32));
        memset(session_pw3, 0, sizeof(session_pw3));
        file_put_data(ef_dek, CONST_BYTE_ARRAY(def, sizeof(def)));
        bootstrap_legacy = true;
#else
        uint8_t def[DEK_FILE_SIZE];
        def[0] = 0x3; // Format

        pin_derive_session(CONST_BYTE_ARRAY(def1, sizeof(def1)), session_pw1);
        encrypt_with_aad(session_pw1, CONST_BYTE_ARRAY(random_dek, DEK_SIZE), PIN_KDF_DEFAULT_VERSION, def + 1);
        mbedtls_platform_zeroize(session_pw1, sizeof(session_pw1));
        file_put_data(ef_dek_pw1, CONST_BYTE_ARRAY(def, sizeof(def)));

        pin_derive_session(CONST_BYTE_ARRAY(def3, sizeof(def3)), session_pw3);
        encrypt_with_aad(session_pw3, CONST_BYTE_ARRAY(random_dek, DEK_SIZE), PIN_KDF_DEFAULT_VERSION, def + 1);
        mbedtls_platform_zeroize(session_pw3, sizeof(session_pw3));
        file_put_data(ef_dek_pw3, CONST_BYTE_ARRAY(def, sizeof(def)));
#endif

        reset_dek = true;
    }
    if ((ef = file_search_by_fid(EF_PW1, NULL, SPECIFY_ANY))) {
        if (!ef->data || reset_dek) {
            printf("PW1 is empty. Initializing with default password\r\n");
            const uint8_t def[6] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36 };
            uint8_t dhash[34];
            if (bootstrap_legacy) {
                dhash[0] = sizeof(def);
                double_hash_pin(CONST_BYTE_ARRAY(def, sizeof(def)), dhash + 1);
                file_put_data(ef, CONST_BYTE_ARRAY(dhash, 33));
            }
            else {
                dhash[0] = sizeof(def);
                dhash[1] = 0x1; // Format
                pin_derive_verifier(CONST_BYTE_ARRAY(def, sizeof(def)), dhash + 2);
                file_put_data(ef, CONST_BYTE_ARRAY(dhash, sizeof(dhash)));
            }
        }
    }
    if ((ef = file_search_by_fid(EF_PW3, NULL, SPECIFY_ANY))) {
        if (!ef->data || reset_dek) {
            printf("PW3 is empty. Initializing with default password\r\n");

            const uint8_t def[8] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
            uint8_t dhash[34];
            if (bootstrap_legacy) {
                dhash[0] = sizeof(def);
                double_hash_pin(CONST_BYTE_ARRAY(def, sizeof(def)), dhash + 1);
                file_put_data(ef, CONST_BYTE_ARRAY(dhash, 33));
            }
            else {
                dhash[0] = sizeof(def);
                dhash[1] = 0x1; // Format
                pin_derive_verifier(CONST_BYTE_ARRAY(def, sizeof(def)), dhash + 2);
                file_put_data(ef, CONST_BYTE_ARRAY(dhash, sizeof(dhash)));
            }
        }
    }
    if ((ef = file_search_by_fid(EF_SIG_COUNT, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("SigCount is empty. Initializing to zero\r\n");
            const uint8_t def[3] = { 0 };
            file_put_data(ef, CONST_BYTE_ARRAY(def, sizeof(def)));
        }
    }
#ifdef ENABLE_ADMINLESS_MODE
    uint8_t legacy_adminless_mode = ADMINLESS_MODE_DISABLED;
    bool migrate_legacy_adminless_mode = false;
#endif
    if ((ef = file_search_by_fid(EF_PW_PRIV, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("PW status is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x1, 127, 127, 127, 3, 0, 3 };
            file_put_data(ef, CONST_BYTE_ARRAY(def, sizeof(def)));
        }
#ifdef ENABLE_ADMINLESS_MODE
        else if (file_get_size(ef) == 8) {
            /* Migration from the unreleased PW-status-byte implementation. */
            legacy_adminless_mode = file_get_data(ef)[7];
            migrate_legacy_adminless_mode = legacy_adminless_mode <= ADMINLESS_MODE_KDF_MIGRATION;
            file_put_data(ef, CONST_BYTE_ARRAY(file_get_data(ef), 7));
        }
#endif
    }
    file_t *rc = file_search_by_fid(EF_RC, NULL, SPECIFY_EF);
    if (!rc || !file_has_data(rc) || reset_dek || reset_code_is_public_default(rc)) {
        openpgp_reset_code_deactivate();
    }
    if ((ef = file_search_by_fid(EF_UIF_SIG, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("UIF SIG is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x0, 0x20 };
            file_put_data(ef, CONST_BYTE_ARRAY(def, sizeof(def)));
        }
    }
    if ((ef = file_search_by_fid(EF_UIF_DEC, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("UIF DEC is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x0, 0x20 };
            file_put_data(ef, CONST_BYTE_ARRAY(def, sizeof(def)));
        }
    }
    if ((ef = file_search_by_fid(EF_UIF_AUT, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("UIF AUT is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x0, 0x20 };
            file_put_data(ef, CONST_BYTE_ARRAY(def, sizeof(def)));
        }
    }
    if ((ef = file_search_by_fid(EF_KDF, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("KDF is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x81, 0x1, 0x0 };
            file_put_data(ef, CONST_BYTE_ARRAY(def, sizeof(def)));
        }
    }
    if ((ef = file_search_by_fid(EF_SEX, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("Sex is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x30 };
            file_put_data(ef, CONST_BYTE_ARRAY(def, sizeof(def)));
        }
    }
    if ((ef = file_search_by_fid(EF_PW_RETRIES, NULL, SPECIFY_ANY))) {
        if (!ef->data
#ifdef ENABLE_ADMINLESS_MODE
            || reset_dek || file_get_size(ef) < ADMINLESS_RETRIES_SIZE
#endif
        ) {
            printf("PW retries is empty. Initializing to default\r\n");
#ifdef ENABLE_ADMINLESS_MODE
            uint8_t def[ADMINLESS_RETRIES_SIZE] = { 0x1, 3, 3, 3, 3, 3, ADMINLESS_MODE_DISABLED };
            if (file_has_data(ef) && !reset_dek) {
                memcpy(def, file_get_data(ef), MIN(file_get_size(ef), ADMINLESS_MODE_OFFSET));
            }
            if (migrate_legacy_adminless_mode) {
                def[ADMINLESS_MODE_OFFSET] = legacy_adminless_mode;
            }
            else if (pw1_and_pw3_are_factory_default()) {
                def[ADMINLESS_MODE_OFFSET] = ADMINLESS_MODE_PENDING;
            }
            file_put_data(ef, CONST_BYTE_ARRAY(def, sizeof(def)));
#else
            const uint8_t def[] = { 0x1, 3, 3, 3 };
            file_put_data(ef, CONST_BYTE_ARRAY(def, sizeof(def)));
#endif
        }
    }
    flash_commit();
}

void release_dek(void) {
    memset(dek, 0, sizeof(dek));
}

extern bool has_pwpiv;
extern uint8_t session_pwpiv[32];
int load_dek(void) {
    if (!has_pw1 && !has_pw2 && !has_pw3 && !has_rc && !has_pwpiv) {
        return PICOKEYS_NO_LOGIN;
    }
    int r = PICOKEYS_OK;

    if (has_pw1 || has_pw2) {
        file_t *ef_dek_pw1 = file_search(EF_DEK_PW1);
        if (file_has_data(ef_dek_pw1)) {
            uint8_t *ef_data = file_get_data(ef_dek_pw1);
            if (ef_data[0] == 0x3) { // Format
                r = decrypt_with_aad(session_pw1, CONST_BYTE_ARRAY(ef_data + 1, DEK_AAD_SIZE), PIN_KDF_DEFAULT_VERSION, dek);
            }
            else {
                return PICOKEYS_ERR_NULL_PARAM;
            }
        }
        else {
            file_t *tf = file_search_by_fid(EF_DEK, NULL, SPECIFY_EF);
            if (!tf) {
                return PICOKEYS_ERR_FILE_NOT_FOUND;
            }

            memcpy(dek, file_get_data(tf), IV_SIZE + 32);
            r = aes_decrypt_cfb_256(session_pw1, dek, BYTE_ARRAY(dek + IV_SIZE, 32));
        }
    }
    else if (has_rc) {
        file_t *ef_dek_rc = file_search(EF_DEK_RC);
        if (file_has_data(ef_dek_rc)) {
            uint8_t *ef_data = file_get_data(ef_dek_rc);
            if (ef_data[0] == 0x3) { // Format
                r = decrypt_with_aad(session_rc, CONST_BYTE_ARRAY(ef_data + 1, DEK_AAD_SIZE), PIN_KDF_DEFAULT_VERSION, dek);
            }
            else {
                return PICOKEYS_ERR_NULL_PARAM;
            }
        }
        else {
            file_t *tf = file_search_by_fid(EF_DEK, NULL, SPECIFY_EF);
            if (!tf) {
                return PICOKEYS_ERR_FILE_NOT_FOUND;
            }

            memcpy(dek, file_get_data(tf), IV_SIZE);
            memcpy(dek + IV_SIZE, file_get_data(tf) + IV_SIZE + 32, 32);
            r = aes_decrypt_cfb_256(session_rc, dek, BYTE_ARRAY(dek + IV_SIZE, 32));
        }
    }
    else if (has_pw3) {
        file_t *ef_dek_pw3 = file_search(EF_DEK_PW3);
        if (file_has_data(ef_dek_pw3)) {
            uint8_t *ef_data = file_get_data(ef_dek_pw3);
            if (ef_data[0] == 0x3) { // Format
                r = decrypt_with_aad(session_pw3, CONST_BYTE_ARRAY(ef_data + 1, DEK_AAD_SIZE), PIN_KDF_DEFAULT_VERSION, dek);
            }
            else {
                return PICOKEYS_ERR_NULL_PARAM;
            }
        }
        else {
            file_t *tf = file_search_by_fid(EF_DEK, NULL, SPECIFY_EF);
            if (!tf) {
                return PICOKEYS_ERR_FILE_NOT_FOUND;
            }

            memcpy(dek, file_get_data(tf), IV_SIZE);
            memcpy(dek + IV_SIZE, file_get_data(tf) + IV_SIZE + 32 + 32, 32);
            r = aes_decrypt_cfb_256(session_pw3, dek, BYTE_ARRAY(dek + IV_SIZE, 32));
        }
    }
    else if (has_pwpiv) {
        file_t *ef_dek_pwpiv = file_search(EF_DEK_PWPIV);
        if (file_has_data(ef_dek_pwpiv)) {
            uint8_t *ef_data = file_get_data(ef_dek_pwpiv);
            if (ef_data[0] == 0x3) { // Format
                r = decrypt_with_aad(session_pwpiv, CONST_BYTE_ARRAY(ef_data + 1, DEK_AAD_SIZE), PIN_KDF_DEFAULT_VERSION, dek);
            }
            else {
                return PICOKEYS_ERR_NULL_PARAM;
            }
        }
        else {
            file_t *tf = file_search_by_fid(EF_DEK, NULL, SPECIFY_EF);
            if (!tf) {
                return PICOKEYS_ERR_FILE_NOT_FOUND;
            }

            memcpy(dek, file_get_data(tf), IV_SIZE);
            memcpy(dek + IV_SIZE, file_get_data(tf) + IV_SIZE + 32 + 32 + 32, 32);
            r = aes_decrypt_cfb_256(session_pwpiv, dek, BYTE_ARRAY(dek + IV_SIZE, 32));
        }
    }
    if (r != 0) {
        release_dek();
        return PICOKEYS_EXEC_ERROR;
    }
    return PICOKEYS_OK;
}

static int dek_decrypt_legacy(uint8_t *data, size_t len) {
    int r;
    if ((r = load_dek()) != PICOKEYS_OK) {
        return r;
    }
    r = aes_decrypt_cfb_256(dek + IV_SIZE, dek, BYTE_ARRAY(data, len));
    release_dek();
    return r;
}

#define ENCRYPTED_KEY_MAGIC_SIZE 4
#define ENCRYPTED_KEY_NONCE_SIZE 12
#define ENCRYPTED_KEY_TAG_SIZE   16
#define ENCRYPTED_KEY_OVERHEAD   (ENCRYPTED_KEY_MAGIC_SIZE + ENCRYPTED_KEY_NONCE_SIZE + ENCRYPTED_KEY_TAG_SIZE)

static const uint8_t encrypted_key_magic[ENCRYPTED_KEY_MAGIC_SIZE] = { 'P', 'G', 'K', 1 };

static int derive_encrypted_key_nonce(uint16_t fid, const uint8_t *plaintext, size_t plaintext_len, uint8_t nonce[ENCRYPTED_KEY_NONCE_SIZE]) {
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md_info) {
        return PICOKEYS_EXEC_ERROR;
    }
    mbedtls_md_context_t md;
    mbedtls_md_init(&md);
    uint8_t digest[32] = { 0 };
    uint8_t fid_data[2] = { fid >> 8, fid & 0xff };
    int r = mbedtls_md_setup(&md, md_info, 1);
    if (r == 0) {
        r = mbedtls_md_hmac_starts(&md, dek, sizeof(dek));
    }
    if (r == 0) {
        r = mbedtls_md_hmac_update(&md, fid_data, sizeof(fid_data));
    }
    if (r == 0) {
        r = mbedtls_md_hmac_update(&md, plaintext, plaintext_len);
    }
    if (r == 0) {
        r = mbedtls_md_hmac_finish(&md, digest);
    }
    mbedtls_md_free(&md);
    if (r == 0) {
        memcpy(nonce, digest, ENCRYPTED_KEY_NONCE_SIZE);
    }
    mbedtls_platform_zeroize(digest, sizeof(digest));
    return r == 0 ? PICOKEYS_OK : PICOKEYS_EXEC_ERROR;
}

static void encrypted_key_aad(uint16_t fid, uint8_t aad[ENCRYPTED_KEY_MAGIC_SIZE + 2]) {
    memcpy(aad, encrypted_key_magic, ENCRYPTED_KEY_MAGIC_SIZE);
    aad[ENCRYPTED_KEY_MAGIC_SIZE] = fid >> 8;
    aad[ENCRYPTED_KEY_MAGIC_SIZE + 1] = fid & 0xff;
}

static int store_encrypted_key(file_t *ef, const uint8_t *plaintext, size_t plaintext_len) {
    if (!ef || !plaintext || plaintext_len > UINT16_MAX - ENCRYPTED_KEY_OVERHEAD) {
        return PICOKEYS_WRONG_DATA;
    }
    int r = load_dek();
    if (r != PICOKEYS_OK) {
        return r;
    }

    size_t record_len = plaintext_len + ENCRYPTED_KEY_OVERHEAD;
    uint8_t *record = calloc(1, record_len);
    if (!record) {
        release_dek();
        return PICOKEYS_ERR_MEMORY_FATAL;
    }
    memcpy(record, encrypted_key_magic, ENCRYPTED_KEY_MAGIC_SIZE);
    uint8_t *nonce = record + ENCRYPTED_KEY_MAGIC_SIZE;
    uint8_t *ciphertext = nonce + ENCRYPTED_KEY_NONCE_SIZE;
    uint8_t *tag = ciphertext + plaintext_len;
    uint8_t aad[ENCRYPTED_KEY_MAGIC_SIZE + 2];
    encrypted_key_aad(ef->fid, aad);

    r = derive_encrypted_key_nonce(ef->fid, plaintext, plaintext_len, nonce);
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    if (r == PICOKEYS_OK) {
        r = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, dek + IV_SIZE, 256);
    }
    if (r == 0) {
        r = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plaintext_len, nonce, ENCRYPTED_KEY_NONCE_SIZE, aad, sizeof(aad), plaintext, ciphertext, ENCRYPTED_KEY_TAG_SIZE, tag);
    }
    mbedtls_gcm_free(&gcm);
    release_dek();
    if (r != 0) {
        mbedtls_platform_zeroize(record, record_len);
        free(record);
        return PICOKEYS_EXEC_ERROR;
    }

    r = file_put_data(ef, CONST_BYTE_ARRAY(record, record_len));
    mbedtls_platform_zeroize(record, record_len);
    free(record);
    return r;
}

int load_key_data(file_t *fkey, byte_buffer_t *out, bool use_dek) {
    if (!file_has_data(fkey) || !out || out->len > out->capacity || (!out->data && out->capacity > 0)) {
        return PICOKEYS_WRONG_DATA;
    }
    if (openpgp_key_container_is_marker(fkey)) {
        uint16_t operation = FILE_OBJECT_OPERATION_USE;
        if (fkey->fid == EF_PK_SIG) {
            operation = FILE_OBJECT_OPERATION_SIGN;
        }
        else if (fkey->fid == EF_PK_DEC || fkey->fid == EF_AES_KEY) {
            operation = FILE_OBJECT_OPERATION_DECRYPT;
        }
        return openpgp_key_container_read_private(fkey->fid, operation, true, out);
    }
    size_t stored_len = file_get_size(fkey);
    const uint8_t *stored = file_get_data(fkey);
    size_t available = out->capacity - out->len;
    uint8_t *output = out->data ? out->data + out->len : NULL;

    if (!use_dek) {
        if (stored_len > available) {
            return PICOKEYS_WRONG_DATA;
        }
        memcpy(output, stored, stored_len);
        out->len += stored_len;
        return PICOKEYS_OK;
    }

    if (stored_len >= ENCRYPTED_KEY_MAGIC_SIZE &&
        memcmp(stored, encrypted_key_magic, ENCRYPTED_KEY_MAGIC_SIZE) == 0) {
        if (stored_len < ENCRYPTED_KEY_OVERHEAD) {
            return PICOKEYS_WRONG_DATA;
        }
        size_t plaintext_len = stored_len - ENCRYPTED_KEY_OVERHEAD;
        if (plaintext_len > available) {
            return PICOKEYS_WRONG_DATA;
        }
        const uint8_t *nonce = stored + ENCRYPTED_KEY_MAGIC_SIZE;
        const uint8_t *ciphertext = nonce + ENCRYPTED_KEY_NONCE_SIZE;
        const uint8_t *tag = ciphertext + plaintext_len;
        uint8_t aad[ENCRYPTED_KEY_MAGIC_SIZE + 2];
        encrypted_key_aad(fkey->fid, aad);

        int r = load_dek();
        if (r != PICOKEYS_OK) {
            return r;
        }
        mbedtls_gcm_context gcm;
        mbedtls_gcm_init(&gcm);
        r = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, dek + IV_SIZE, 256);
        if (r == 0) {
            r = mbedtls_gcm_auth_decrypt(&gcm, plaintext_len, nonce, ENCRYPTED_KEY_NONCE_SIZE, aad, sizeof(aad), tag, ENCRYPTED_KEY_TAG_SIZE, ciphertext, output);
        }
        mbedtls_gcm_free(&gcm);
        release_dek();
        if (r != 0) {
            mbedtls_platform_zeroize(output, available);
            return PICOKEYS_WRONG_DATA;
        }
        out->len += plaintext_len;
        return PICOKEYS_OK;
    }

    if (stored_len > available) {
        return PICOKEYS_WRONG_DATA;
    }
    memcpy(output, stored, stored_len);
    int r = dek_decrypt_legacy(output, stored_len);
    if (r != 0) {
        mbedtls_platform_zeroize(output, available);
        return PICOKEYS_EXEC_ERROR;
    }
    r = store_encrypted_key(fkey, output, stored_len);
    if (r != PICOKEYS_OK) {
        mbedtls_platform_zeroize(output, available);
        return r;
    }
    flash_commit();
    out->len += stored_len;
    return PICOKEYS_OK;
}

static void init_openpgp(void) {
    isUserAuthenticated = false;
    has_pw1 = has_pw2 = has_pw3 = false;
    algo_dec = EF_ALGO_PRIV2;
    algo_aut = EF_ALGO_PRIV3;
    pk_dec = EF_PK_DEC;
    pk_aut = EF_PK_AUT;
    scan_files_openpgp();
    //cmd_select();
}

static int openpgp_unload(void) {
    isUserAuthenticated = false;
    has_pw1 = has_pw2 = has_pw3 = false;
    algo_dec = EF_ALGO_PRIV2;
    algo_aut = EF_ALGO_PRIV3;
    pk_dec = EF_PK_DEC;
    pk_aut = EF_PK_AUT;
    return PICOKEYS_OK;
}

extern char __StackLimit;
static int heapLeft(void) {
#if !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
    char *p = malloc(256);   // try to avoid undue fragmentation
    int left = &__StackLimit - p;
    free(p);
#else
    int left = 1024 * 1024;
#endif
    return left;
}

static int openpgp_select_aid(app_t *a, uint8_t force) {
    (void) force;
    a->process_apdu = openpgp_process_apdu;
    a->unload = openpgp_unload;
    is_gpg = true;
    init_openpgp();
    file_process_fci(file_openpgp, 1);
    memcpy(res_APDU + res_APDU_size, "\x64\x06\x53\x04", 4);
    res_APDU_size += 4;
    int heap_left = heapLeft();
    res_APDU[res_APDU_size++] = ((heap_left >> 24) & 0xff);
    res_APDU[res_APDU_size++] = ((heap_left >> 16) & 0xff);
    res_APDU[res_APDU_size++] = ((heap_left >> 8) & 0xff);
    res_APDU[res_APDU_size++] = ((heap_left >> 0) & 0xff);
    res_APDU[1] += 8;
    apdu.ne = res_APDU_size;
    return PICOKEYS_OK;
}

INITIALIZER( openpgp_ctor ) {
    register_app(openpgp_select_aid, openpgp_aid);
}

int set_atr(void) {
    ccid_atr = (uint8_t *) atr_openpgp;
    return 0;
}

int pin_reset_retries(const file_t *pin, bool force) {
    if (!pin) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    file_t *pw_status = file_search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF);
    file_t *pw_retries = file_search_by_fid(EF_PW_RETRIES, NULL, SPECIFY_EF);
    if (!pw_status || !pw_retries) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    if (3u + (pin->fid & 0xfu) >= file_get_size(pw_status) || (pin->fid & 0xfu) >= file_get_size(pw_retries)) {
        return PICOKEYS_ERR_MEMORY_FATAL;
    }
    uint8_t p[64];
    memcpy(p, file_get_data(pw_status), file_get_size(pw_status));
    uint8_t retries = p[3 + (pin->fid & 0xf)];
    if (retries == 0 && force == false) { //blocked
        return PICOKEYS_ERR_BLOCKED;
    }
    uint8_t max_retries = file_get_data(pw_retries)[(pin->fid & 0xf)];
    p[3 + (pin->fid & 0xf)] = max_retries;
    int r = file_put_data(pw_status, CONST_BYTE_ARRAY(p, file_get_size(pw_status)));
    flash_commit();
    return r;
}

static int pin_wrong_retry(const file_t *pin) {
    if (!pin) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    file_t *pw_status = file_search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF);
    if (!pw_status) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    uint8_t p[64];
    memcpy(p, file_get_data(pw_status), file_get_size(pw_status));
    if (p[3 + (pin->fid & 0xf)] > 0) {
        p[3 + (pin->fid & 0xf)] -= 1;
        int r = file_put_data(pw_status, CONST_BYTE_ARRAY(p, file_get_size(pw_status)));
        if (r != PICOKEYS_OK) {
            return r;
        }
        flash_commit();
        if (p[3 + (pin->fid & 0xf)] == 0) {
            return PICOKEYS_ERR_BLOCKED;
        }
        return p[3 + (pin->fid & 0xf)];
    }
    return PICOKEYS_ERR_BLOCKED;
}

int check_pin(const file_t *pin, const uint8_t *data, size_t len) {
    if (!file_has_data(pin)) {
        return SW_REFERENCE_NOT_FOUND();
    }
    isUserAuthenticated = false;
    //has_pw1 = has_pw3 = false;

    uint8_t dhash[32], off = 2;
    if (file_get_size(pin) == 33) {
        off = 1;
        double_hash_pin(CONST_BYTE_ARRAY(data, len), dhash);
    }
    else {
        pin_derive_verifier(CONST_BYTE_ARRAY(data, len), dhash);
    }
    if (sizeof(dhash) != file_get_size(pin) - off) { //1 byte for pin len and 1 byte for format
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if (mbedtls_ct_memcmp(file_get_data(pin) + off, dhash, sizeof(dhash)) != 0) {
        int retries;
        if ((retries = pin_wrong_retry(pin)) < PICOKEYS_OK) {
            return SW_PIN_BLOCKED();
        }
        return set_res_sw(0x63, 0xc0 | retries);
    }

    int r = pin_reset_retries(pin, false);
    if (r == PICOKEYS_ERR_BLOCKED) {
        return SW_PIN_BLOCKED();
    }
    if (r != PICOKEYS_OK) {
        return SW_MEMORY_FAILURE();
    }
    if (off == 1) {
        uint8_t pin_data[34], *pin_sp = NULL;
        pin_data[0] = len;
        pin_data[1] = 0x1; // Format
        pin_derive_verifier(CONST_BYTE_ARRAY(data, len), pin_data + 2);
        file_put_data((file_t *)pin, CONST_BYTE_ARRAY(pin_data, sizeof(pin_data)));
        if (pin->fid == EF_PW1) {
            if (P2(apdu) == 0x81) {
                has_pw1 = true;
            }
            else {
                has_pw2 = true;
            }
            pin_sp = session_pw1;
        }
        else if (pin->fid == EF_PW3) {
            has_pw3 = true;
            pin_sp = session_pw3;
        }
        else if (pin->fid == EF_PIV_PIN) {
            has_pwpiv = true;
            pin_sp = session_pwpiv;
        }
        if (pin_sp) {
            hash_multi(CONST_BYTE_ARRAY(data, len), pin_sp);
            r = load_dek();
            if (r != PICOKEYS_OK) {
                return SW_EXEC_ERROR();
            }
            uint8_t old_data[DEK_FILE_SIZE_OLD], ef_data[DEK_FILE_SIZE];
            file_t *ef_dek_pw = NULL;
            if (pin->fid == EF_PW1) {
                ef_dek_pw = file_search_by_fid(EF_DEK_PW1, NULL, SPECIFY_EF);
            }
            else if (pin->fid == EF_PW3) {
                ef_dek_pw = file_search_by_fid(EF_DEK_PW3, NULL, SPECIFY_EF);
            }
            else if (pin->fid == EF_PIV_PIN) {
                ef_dek_pw = file_search_by_fid(EF_DEK_PWPIV, NULL, SPECIFY_EF);
            }
            if (!ef_dek_pw) {
                return PICOKEYS_ERR_FILE_NOT_FOUND;
            }
            ef_data[0] = 0x3; // Format
            pin_derive_session(CONST_BYTE_ARRAY(data, len), pin_sp);
            if ((r = encrypt_with_aad(pin_sp, CONST_BYTE_ARRAY(dek, DEK_SIZE), PIN_KDF_DEFAULT_VERSION, ef_data + 1)) != PICOKEYS_OK) {
                return SW_EXEC_ERROR();
            }
            if ((r = file_put_data(ef_dek_pw, CONST_BYTE_ARRAY(ef_data, sizeof(ef_data)))) != PICOKEYS_OK) {
                return SW_MEMORY_FAILURE();
            }

            file_t *ef_dek = file_search_by_fid(EF_DEK, NULL, SPECIFY_EF);
            if (!ef_dek) {
                return PICOKEYS_ERR_FILE_NOT_FOUND;
            }
            memcpy(old_data, file_get_data(ef_dek), sizeof(old_data));
            if (pin->fid == EF_PW1) {
                memset(old_data + IV_SIZE, 0, 32);
            }
            else if (pin->fid == EF_PW3) {
                memset(old_data + IV_SIZE + 32 + 32, 0, 32);
            }
            else if (pin->fid == EF_PIV_PIN) {
                memset(old_data + IV_SIZE + 32 + 32 + 32, 0, 32);
            }
            if ((r = file_put_data(ef_dek, CONST_BYTE_ARRAY(old_data, sizeof(old_data)))) != PICOKEYS_OK) {
                return SW_MEMORY_FAILURE();
            }
            flash_commit();
        }
    }
    isUserAuthenticated = true;
    if (pin->fid == EF_PW1) {
        if (P2(apdu) == 0x81) {
            has_pw1 = true;
#ifdef ENABLE_ADMINLESS_MODE
            if (openpgp_adminless_is_active()) {
                has_pw3 = true;
            }
#endif
        }
        else {
            has_pw2 = true;
        }
        pin_derive_session(CONST_BYTE_ARRAY(data, len), session_pw1);
    }
    else if (pin->fid == EF_PW3) {
        has_pw3 = true;
        pin_derive_session(CONST_BYTE_ARRAY(data, len), session_pw3);
    }
    return SW_OK();
}

int inc_sig_count(void) {
    file_t *pw_status;
    if (!(pw_status = file_search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF)) || !pw_status->data) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (file_get_data(pw_status)[0] == 0) {
        has_pw1 = false;
#ifdef ENABLE_ADMINLESS_MODE
        if (openpgp_adminless_is_active()) {
            has_pw3 = false;
        }
#endif
    }
    file_t *ef = file_search_by_fid(EF_SIG_COUNT, NULL, SPECIFY_ANY);
    if (!ef || !ef->data) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    uint8_t *p = file_get_data(ef);
    uint32_t counter = (p[0] << 16) | (p[1] << 8) | p[2];
    counter++;
    uint8_t q[3] = { (counter >> 16) & 0xff, (counter >> 8) & 0xff, counter & 0xff };
    int r = file_put_data(ef, CONST_BYTE_ARRAY(q, sizeof(q)));
    if (r != PICOKEYS_OK) {
        return PICOKEYS_EXEC_ERROR;
    }
    flash_commit();
    return PICOKEYS_OK;
}

int reset_sig_count(void) {
    file_t *ef = file_search_by_fid(EF_SIG_COUNT, NULL, SPECIFY_ANY);
    if (!ef || !ef->data) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    uint8_t q[3] = { 0 };
    int r = file_put_data(ef, CONST_BYTE_ARRAY(q, sizeof(q)));
    if (r != PICOKEYS_OK) {
        return PICOKEYS_EXEC_ERROR;
    }
    flash_commit();
    return PICOKEYS_OK;
}

static int serialize_key(void *key_ctx, int type, uint8_t *kdata, size_t capacity, size_t *key_size) {
    if (!key_ctx || !kdata || !key_size) {
        return PICOKEYS_ERR_NULL_PARAM;
    }

    *key_size = 0;
    if (type == ALGO_RSA) {
        mbedtls_rsa_context *rsa = (mbedtls_rsa_context *) key_ctx;
        *key_size = mbedtls_mpi_size(&rsa->P) + mbedtls_mpi_size(&rsa->Q);
        if (*key_size > capacity || mbedtls_mpi_write_binary(&rsa->P, kdata, *key_size / 2) != 0 || mbedtls_mpi_write_binary(&rsa->Q, kdata + *key_size / 2, *key_size / 2) != 0) {
            return PICOKEYS_WRONG_DATA;
        }
    }
    else if (type == ALGO_ECDSA || type == ALGO_ECDH || type == ALGO_EDDSA) {
        mbedtls_ecp_keypair *ecdsa = (mbedtls_ecp_keypair *) key_ctx;
        size_t olen = 0;
        if (capacity < 2) {
            return PICOKEYS_WRONG_DATA;
        }
        kdata[0] = ecdsa->grp.id & 0xff;
        if (mbedtls_ecp_write_key_ext(ecdsa, &olen, kdata + 1, capacity - 1) != 0) {
            return PICOKEYS_WRONG_DATA;
        }
        *key_size = olen + 1;
    }
    else if (type & ALGO_AES) {
        if (type == ALGO_AES_128) {
            *key_size = 16;
        }
        else if (type == ALGO_AES_192) {
            *key_size = 24;
        }
        else if (type == ALGO_AES_256) {
            *key_size = 32;
        }
        else {
            return PICOKEYS_WRONG_DATA;
        }
        if (*key_size > capacity) {
            return PICOKEYS_WRONG_DATA;
        }
        memcpy(kdata, key_ctx, *key_size);
    }
    else {
        return PICOKEYS_WRONG_DATA;
    }
    return PICOKEYS_OK;
}

int store_keypair(void *key_ctx, int type, uint16_t key_id, const uint8_t *public_data, size_t public_size) {
    if (!openpgp_key_container_supported(key_id) || key_id == EF_AES_KEY || !public_data || public_size == 0) {
        return PICOKEYS_WRONG_DATA;
    }

    uint8_t kdata[4096 / 8];
    size_t key_size = 0;
    int r = serialize_key(key_ctx, type, kdata, sizeof(kdata), &key_size);
    if (r == PICOKEYS_OK) {
        r = openpgp_key_container_store(key_id, kdata, key_size, public_data, (uint32_t)public_size, false);
    }
    mbedtls_platform_zeroize(kdata, sizeof(kdata));
    return r;
}

int store_keys(void *key_ctx, int type, uint16_t key_id, bool use_kek) {
    file_t *ef = file_search_by_fid(key_id, NULL, SPECIFY_EF);
    if (!ef) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }

    uint8_t kdata[4096 / 8];
    size_t key_size = 0;
    int r = serialize_key(key_ctx, type, kdata, sizeof(kdata), &key_size);
    if (r == PICOKEYS_OK && openpgp_key_container_supported(key_id)) {
        r = openpgp_key_container_store(key_id, kdata, key_size, NULL, 0, !use_kek);
    }
    else if (r == PICOKEYS_OK) {
        r = use_kek ? store_encrypted_key(ef, kdata, key_size) : file_put_data(ef, CONST_BYTE_ARRAY(kdata, key_size));
    }
    mbedtls_platform_zeroize(kdata, sizeof(kdata));
    if (r != PICOKEYS_OK) {
        return r;
    }
    flash_commit();
    return PICOKEYS_OK;
}

int load_private_key_rsa(mbedtls_rsa_context *ctx, file_t *fkey, bool use_dek) {
    uint8_t kdata[4096 / 8];
    byte_buffer_t key = BYTE_BUFFER(kdata, sizeof(kdata));
    int r = load_key_data(fkey, &key, use_dek);
    size_t key_size = key.len;
    if (r != PICOKEYS_OK || key_size == 0 || key_size % 2 != 0) {
        mbedtls_platform_zeroize(kdata, sizeof(kdata));
        return r == PICOKEYS_OK ? PICOKEYS_WRONG_DATA : r;
    }
    if (mbedtls_mpi_read_binary(&ctx->P, kdata, key_size / 2) != 0) {
        mbedtls_rsa_free(ctx);
        mbedtls_platform_zeroize(kdata, sizeof(kdata));
        return PICOKEYS_WRONG_DATA;
    }
    if (mbedtls_mpi_read_binary(&ctx->Q, kdata + key_size / 2, key_size / 2) != 0) {
        mbedtls_rsa_free(ctx);
        mbedtls_platform_zeroize(kdata, sizeof(kdata));
        return PICOKEYS_WRONG_DATA;
    }
    if (mbedtls_mpi_lset(&ctx->E, 0x10001) != 0) {
        mbedtls_rsa_free(ctx);
        mbedtls_platform_zeroize(kdata, sizeof(kdata));
        return PICOKEYS_EXEC_ERROR;
    }
    if (mbedtls_rsa_import(ctx, NULL, &ctx->P, &ctx->Q, NULL, &ctx->E) != 0) {
        mbedtls_rsa_free(ctx);
        mbedtls_platform_zeroize(kdata, sizeof(kdata));
        return PICOKEYS_WRONG_DATA;
    }
    if (mbedtls_rsa_complete(ctx) != 0) {
        mbedtls_rsa_free(ctx);
        mbedtls_platform_zeroize(kdata, sizeof(kdata));
        return PICOKEYS_WRONG_DATA;
    }
    if (mbedtls_rsa_check_privkey(ctx) != 0) {
        mbedtls_rsa_free(ctx);
        mbedtls_platform_zeroize(kdata, sizeof(kdata));
        return PICOKEYS_WRONG_DATA;
    }
    mbedtls_platform_zeroize(kdata, sizeof(kdata));
    return PICOKEYS_OK;
}

int load_private_key_ecdsa(mbedtls_ecp_keypair *ctx, file_t *fkey, bool use_dek) {
    uint8_t kdata[67]; //Worst case, 521 bit + 1byte
    byte_buffer_t key = BYTE_BUFFER(kdata, sizeof(kdata));
    int r = load_key_data(fkey, &key, use_dek);
    size_t key_size = key.len;
    if (r != PICOKEYS_OK || key_size < 2) {
        mbedtls_platform_zeroize(kdata, sizeof(kdata));
        return r == PICOKEYS_OK ? PICOKEYS_WRONG_DATA : r;
    }
    mbedtls_ecp_group_id gid = kdata[0];
    r = mbedtls_ecp_read_key(gid, ctx, kdata + 1, key_size - 1);
    if (r != 0) {
        mbedtls_ecp_keypair_free(ctx);
        mbedtls_platform_zeroize(kdata, sizeof(kdata));
        return PICOKEYS_EXEC_ERROR;
    }
    mbedtls_platform_zeroize(kdata, sizeof(kdata));
#if defined(MBEDTLS_ECP_EDWARDS_ENABLED)
    if (mbedtls_ecp_get_type(&ctx->grp) == MBEDTLS_ECP_TYPE_EDWARDS) {
        r = mbedtls_ecp_point_edwards(&ctx->grp, &ctx->Q, &ctx->d, random_fill_iterator, NULL);
    }
    else
#endif
    {
        r = mbedtls_ecp_keypair_calc_public(ctx, random_fill_iterator, NULL);
    }
    if (r != 0) {
        mbedtls_ecp_keypair_free(ctx);
        return PICOKEYS_EXEC_ERROR;
    }
    return PICOKEYS_OK;
}

int load_aes_key(uint8_t *aes_key, size_t *key_size, file_t *fkey) {
    byte_buffer_t key = BYTE_BUFFER(aes_key, 32);
    int r = load_key_data(fkey, &key, true);
    *key_size = key.len;
    if (r != PICOKEYS_OK || (*key_size != 16 && *key_size != 24 && *key_size != 32)) {
        mbedtls_platform_zeroize(aes_key, 32);
        return r == PICOKEYS_OK ? PICOKEYS_WRONG_DATA : r;
    }
    return r;
}

mbedtls_ecp_group_id get_ec_group_id_from_attr(const uint8_t *algo, size_t algo_len) {
#define ALGORITHM_ATTR_MATCH(attr) \
    (algo_len == (size_t)((attr)[0] - 1u) && memcmp((attr) + 2, algo, algo_len) == 0)
    if (ALGORITHM_ATTR_MATCH(algorithm_attr_p256k1)) {
        return MBEDTLS_ECP_DP_SECP256K1;
    }
    else if (ALGORITHM_ATTR_MATCH(algorithm_attr_p256r1)) {
        return MBEDTLS_ECP_DP_SECP256R1;
    }
    else if (ALGORITHM_ATTR_MATCH(algorithm_attr_p384r1)) {
        return MBEDTLS_ECP_DP_SECP384R1;
    }
    else if (ALGORITHM_ATTR_MATCH(algorithm_attr_p521r1)) {
        return MBEDTLS_ECP_DP_SECP521R1;
    }
    else if (ALGORITHM_ATTR_MATCH(algorithm_attr_bp256r1)) {
        return MBEDTLS_ECP_DP_BP256R1;
    }
    else if (ALGORITHM_ATTR_MATCH(algorithm_attr_bp384r1)) {
        return MBEDTLS_ECP_DP_BP384R1;
    }
    else if (ALGORITHM_ATTR_MATCH(algorithm_attr_bp512r1)) {
        return MBEDTLS_ECP_DP_BP512R1;
    }
    else if (ALGORITHM_ATTR_MATCH(algorithm_attr_cv25519)) {
        return MBEDTLS_ECP_DP_CURVE25519;
    }
    else if (ALGORITHM_ATTR_MATCH(algorithm_attr_x448)) {
        return MBEDTLS_ECP_DP_CURVE448;
    }
#ifdef MBEDTLS_EDDSA_C
    else if (ALGORITHM_ATTR_MATCH(algorithm_attr_ed25519)) {
        return MBEDTLS_ECP_DP_ED25519;
    }
    else if (ALGORITHM_ATTR_MATCH(algorithm_attr_ed448)) {
        return MBEDTLS_ECP_DP_ED448;
    }
#endif
#undef ALGORITHM_ATTR_MATCH
    return MBEDTLS_ECP_DP_NONE;
}

void make_rsa_response(mbedtls_rsa_context *rsa) {
    memcpy(res_APDU, "\x7f\x49\x82\x00\x00", 5);
    res_APDU_size = 5;
    res_APDU[res_APDU_size++] = 0x81;
    res_APDU[res_APDU_size++] = 0x82;
    put_uint16_be(mbedtls_mpi_size(&rsa->N), res_APDU + res_APDU_size); res_APDU_size += 2;
    mbedtls_mpi_write_binary(&rsa->N, res_APDU + res_APDU_size, mbedtls_mpi_size(&rsa->N));
    res_APDU_size += mbedtls_mpi_size(&rsa->N);
    res_APDU[res_APDU_size++] = 0x82;
    res_APDU[res_APDU_size++] = mbedtls_mpi_size(&rsa->E) & 0xff;
    mbedtls_mpi_write_binary(&rsa->E, res_APDU + res_APDU_size, mbedtls_mpi_size(&rsa->E));
    res_APDU_size += mbedtls_mpi_size(&rsa->E);
    put_uint16_be(res_APDU_size - 5, res_APDU + 3);
}

void make_ecdsa_response(mbedtls_ecp_keypair *ecdsa) {
    uint8_t pt[MBEDTLS_ECP_MAX_PT_LEN];
    size_t plen = 0;
    mbedtls_ecp_point_write_binary(&ecdsa->grp, &ecdsa->Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &plen, pt, sizeof(pt));
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

int rsa_sign(mbedtls_rsa_context *ctx, const uint8_t *data, size_t data_len, uint8_t *out, size_t *out_len) {
    uint8_t *d = (uint8_t *) data, *end = d + data_len, *hsh = NULL;
    size_t seq_len = 0, hash_len = 0;
    size_t key_size = ctx->len;
    int r = 0;
    mbedtls_md_type_t md = MBEDTLS_MD_NONE;
    if (mbedtls_asn1_get_tag(&d, end, &seq_len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) == 0) {
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
        r = mbedtls_rsa_private(ctx, random_fill_iterator, NULL, data, out);
    }
    else {
        uint8_t *signature = (uint8_t *) calloc(key_size, sizeof(uint8_t));
        r = mbedtls_rsa_pkcs1_sign(ctx, random_fill_iterator, NULL, md, hash_len, hsh, signature);
        memcpy(out, signature, key_size);
        free(signature);
    }
    *out_len = key_size;
    return r;
}

int ecdsa_sign(mbedtls_ecp_keypair *ctx, const uint8_t *data, size_t data_len, uint8_t *out, size_t *out_len) {

    int r = 0;
#ifdef MBEDTLS_EDDSA_C
    if (ctx->grp.id == MBEDTLS_ECP_DP_ED25519 || ctx->grp.id == MBEDTLS_ECP_DP_ED448) {
           r = mbedtls_eddsa_write_signature(ctx, data, data_len, out, 114, out_len, MBEDTLS_EDDSA_PURE, NULL, 0, random_fill_iterator, NULL);
    }
    else
#endif
    {
        mbedtls_mpi ri, si;
        mbedtls_mpi_init(&ri);
        mbedtls_mpi_init(&si);
        r = mbedtls_ecdsa_sign(&ctx->grp, &ri, &si, &ctx->d, data, data_len, random_fill_iterator, NULL);
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
#define INS_GET_BULK_DATA   0xCE
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
    { INS_VERSION, cmd_version_openpgp },
    { INS_SELECT_DATA, cmd_select_data },
    { INS_GET_NEXT_DATA, cmd_get_next_data },
    { INS_GET_BULK_DATA, cmd_get_bulk_data },
    { 0x00, NULL }
};

int openpgp_process_apdu(void) {
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
