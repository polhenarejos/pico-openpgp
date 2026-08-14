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
#include "files.h"
#include "apdu.h"
#include "picokeys.h"
#include "serial.h"
#include "random.h"
#include "eac.h"
#include "crypto_utils.h"
#include "version.h"
#include "tlv.h"
#include "mbedtls/aes.h"
#include "mbedtls/des.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/constant_time.h"
#include "key_container.h"
#include "openpgp.h"

#define PIV_ALGO_3DES   0x03
#define PIV_ALGO_AES128 0x08
#define PIV_ALGO_AES192 0x0a
#define PIV_ALGO_AES256 0x0c
#define PIV_ALGO_RSA1024 0x06
#define PIV_ALGO_RSA2048 0x07
#define PIV_ALGO_RSA3072 0x05
#define PIV_ALGO_RSA4096 0x16
#define PIV_ALGO_ECCP256 0x11
#define PIV_ALGO_ECCP384 0x14
#define PIV_ALGO_X25519 0xE1
#define PIV_ALGO_PIN    0xFF
#define PIV_DATA_ADMIN_ID 0x5FFF00u
#define PIV_DATA_ATTESTATION_ID 0x5FFF01u

#define PINPOLICY_DEFAULT 0
#define PINPOLICY_NEVER 1
#define PINPOLICY_ONCE 2
#define PINPOLICY_ALWAYS 3
#define MGM_PIN_POLICY PINPOLICY_DEFAULT

#define TOUCHPOLICY_DEFAULT 0
#define TOUCHPOLICY_NEVER 1
#define TOUCHPOLICY_ALWAYS 2
#define TOUCHPOLICY_CACHED 3
#define TOUCHPOLICY_AUTO 0xFF
#define PIV_DEFAULT_TOUCH_POLICY TOUCHPOLICY_NEVER

#define ORIGIN_GENERATED 0x01
#define ORIGIN_IMPORTED 0x02
#define PIV_MANAGEMENT_KEY_DEFAULT_SIZE 24u
#define PIV_FLASH_COMMIT_TIMEOUT_MS 5000u

#define IS_RETIRED(x) ((x) >= EF_PIV_KEY_RETIRED1 && (x) <= EF_PIV_KEY_RETIRED20)
#define IS_ACTIVE(x) ((x) >= EF_PIV_KEY_AUTHENTICATION && (x) <= EF_PIV_KEY_CARDAUTH)
#define IS_KEY(x) ((IS_ACTIVE((x))) || (IS_RETIRED((x))))

static size_t piv_rsa_modulus_size(uint8_t algo) {
    if (algo == PIV_ALGO_RSA1024) {
        return 128;
    }
    if (algo == PIV_ALGO_RSA2048) {
        return 256;
    }
    if (algo == PIV_ALGO_RSA3072) {
        return 384;
    }
    if (algo == PIV_ALGO_RSA4096) {
        return 512;
    }
    return 0;
}

static uint8_t piv_default_pin_policy(uint8_t key_ref) {
    if (key_ref == EF_PIV_KEY_SIGNATURE) {
        return PINPOLICY_ALWAYS;
    }
    if (key_ref == EF_PIV_KEY_CARDAUTH) {
        return PINPOLICY_NEVER;
    }
    return PINPOLICY_ONCE;
}

uint8_t piv_aid[] = {
    5,
    0xA0, 0x00, 0x00, 0x03, 0x8,
};
uint8_t yk_aid[] = {
    8,
    0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x1, 0x1
};

bool has_pwpiv = false;
uint8_t session_pwpiv[32];

typedef enum {
    MGM_CHALLENGE_NONE = 0,
    MGM_CHALLENGE_MUTUAL,
    MGM_CHALLENGE_SINGLE,
} mgm_challenge_kind_t;

static uint8_t mgm_challenge[16];
static mgm_challenge_kind_t mgm_challenge_kind = MGM_CHALLENGE_NONE;
static uint8_t mgm_challenge_algo = 0;
static bool has_mgm = false;
static const uint8_t piv_management_key_default[PIV_MANAGEMENT_KEY_DEFAULT_SIZE] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};

bool piv_key_operation_authorized(uint16_t operation, bool internal_firmware) {
    if (internal_firmware) {
        return true;
    }
    if (operation == FILE_OBJECT_OPERATION_UPDATE || operation == FILE_OBJECT_OPERATION_DELETE || operation == FILE_OBJECT_OPERATION_CHANGE_POLICY) {
        return has_mgm;
    }
    return false;
}

static void clear_mgm_challenge(void) {
    memset(mgm_challenge, 0, sizeof(mgm_challenge));
    mgm_challenge_kind = MGM_CHALLENGE_NONE;
    mgm_challenge_algo = 0;
}

int piv_process_apdu(void);
void init_piv(void);
int piv_parse_discovery(const file_t *ef);

static int get_serial(void) {
    uint32_t serial = (pico_serial.id[0] & 0x7F) << 24 | pico_serial.id[1] << 16 | pico_serial.id[2] << 8 | pico_serial.id[3];
    return serial;
}

static int x509_create_cert(void *pk_ctx, uint8_t algo, uint8_t slot, bool attestation, uint8_t *buffer, size_t buffer_size) {
    mbedtls_x509write_cert ctx;
    mbedtls_x509write_crt_init(&ctx);
    mbedtls_x509write_crt_set_version(&ctx, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_validity(&ctx, "20240325000000", "20741231235959");
    uint8_t serial[20];
    random_fill_buffer(BYTE_ARRAY(serial, sizeof(serial)));
    mbedtls_x509write_crt_set_serial_raw(&ctx, serial, sizeof(serial));
    mbedtls_pk_context skey, ikey;
    mbedtls_ecdsa_context actx; // attestation key
    mbedtls_pk_init(&skey);
    mbedtls_pk_init(&ikey);
    if (algo == PIV_ALGO_RSA1024 || algo == PIV_ALGO_RSA2048) {
        mbedtls_pk_setup(&skey, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    }
    else if (algo == PIV_ALGO_ECCP256 || algo == PIV_ALGO_ECCP384) {
        mbedtls_pk_setup(&skey, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    }
    skey.pk_ctx = pk_ctx;
    mbedtls_x509write_crt_set_subject_key(&ctx, &skey);
    char buf_sname[256];
    if (attestation) {
        sprintf(buf_sname, "C=ES,O=Pico Keys,CN=Pico OpenPGP PIV Attestation %X", slot);
        mbedtls_x509write_crt_set_subject_name(&ctx, buf_sname);
        mbedtls_x509write_crt_set_issuer_name(&ctx, "C=ES,O=Pico Keys,CN=Pico OpenPGP PIV Slot F9");
        file_t *ef_key = file_search_by_fid(EF_PIV_KEY_ATTESTATION, NULL, SPECIFY_EF);
        mbedtls_ecdsa_init(&actx);
        load_private_key_ecdsa(&actx, ef_key, false);
        mbedtls_pk_setup(&ikey, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
        ikey.pk_ctx = &actx;
        mbedtls_x509write_crt_set_issuer_key(&ctx, &ikey);
        uint8_t ver[] = {PIV_VERSION_MAJOR, PIV_VERSION_MINOR, 0};
        mbedtls_x509write_crt_set_extension(&ctx, "\x2B\x06\x01\x04\x01\x82\xC4\x0A\x03\x03", 10, 0, ver, sizeof(ver));
        uint32_t device_serial = get_serial();
        mbedtls_x509write_crt_set_extension(&ctx, "\x2B\x06\x01\x04\x01\x82\xC4\x0A\x03\x07", 10, 0, (const uint8_t *)&device_serial, sizeof(device_serial));
        byte_array_t metadata = meta_find(slot);
        if (metadata.len >= 3) {
            mbedtls_x509write_crt_set_extension(&ctx, "\x2B\x06\x01\x04\x01\x82\xC4\x0A\x03\x08", 10, 0, metadata.data + 1, 2);
        }
        uint8_t v = 1;
        mbedtls_x509write_crt_set_extension(&ctx, "\x2B\x06\x01\x04\x01\x82\xC4\x0A\x03\x09", 10, 0, &v, sizeof(v));
    }
    else {
        uint8_t wslot = slot;
        if (slot == EF_PIV_KEY_ATTESTATION) {
            wslot = 0xF9;
        }
        else if (slot == EF_PIV_KEY_RETIRED18) {
            wslot = 0x93;
        }
        sprintf(buf_sname, "C=ES,O=Pico Keys,CN=Pico OpenPGP PIV Slot %X", wslot);
        mbedtls_x509write_crt_set_issuer_name(&ctx, buf_sname);
        mbedtls_x509write_crt_set_subject_name(&ctx, buf_sname);
        mbedtls_x509write_crt_set_issuer_key(&ctx, &skey);
    }
    if (algo == PIV_ALGO_ECCP384) {
        mbedtls_x509write_crt_set_md_alg(&ctx, MBEDTLS_MD_SHA384);
    }
    else {
        mbedtls_x509write_crt_set_md_alg(&ctx, MBEDTLS_MD_SHA256);
    }
    if (slot == EF_PIV_KEY_ATTESTATION) {
        mbedtls_x509write_crt_set_basic_constraints(&ctx, 1, 1);
    }
    else {
        mbedtls_x509write_crt_set_basic_constraints(&ctx, 0, 0);
    }
    mbedtls_x509write_crt_set_subject_key_identifier(&ctx);
    mbedtls_x509write_crt_set_authority_key_identifier(&ctx);
    mbedtls_x509write_crt_set_key_usage(&ctx, MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_CERT_SIGN);
    int ret = mbedtls_x509write_crt_der(&ctx, buffer, buffer_size, random_fill_iterator, NULL);
    /* skey cannot be freed, as it is freed later */
    if (attestation) {
        mbedtls_ecdsa_free(&actx);
    }
    mbedtls_x509write_crt_free(&ctx);
    return ret;
}

static void scan_files_piv(void) {
    file_scan_flash();
    file_t *ef = file_search_by_fid(EF_PIV_KEY_CARDMGM, NULL, SPECIFY_EF);
    if ((ef = file_search_by_fid(EF_PW_PRIV, NULL, SPECIFY_ANY))) {
        if (file_get_size(ef) == 0) {
            printf("PW status is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x1, 127, 127, 127, 3, 3, 3, 3, 3 };
            file_put_data(ef, CONST_BYTE_ARRAY(def, sizeof(def)));
        }
        else if (file_get_size(ef) == 7) {
            printf("PW status is older. Initializing to default\r\n");
            uint8_t def[9] = { 0 };
            memcpy(def, file_get_data(ef), 7);
            def[7] = def[8] = 3; // PIV retries
            file_put_data(ef, CONST_BYTE_ARRAY(def, sizeof(def)));
        }
    }
    if ((ef = file_search_by_fid(EF_PW_RETRIES, NULL, SPECIFY_ANY))) {
        if (file_get_size(ef) == 0) {
            printf("PW retries is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x1, 3, 3, 3, 3, 3 };
            file_put_data(ef, CONST_BYTE_ARRAY(def, sizeof(def)));
        }
        else if (file_get_size(ef) == 4) {
            printf("PW retries is older. Initializing to default\r\n");
            uint8_t def[6] = { 0 };
            memcpy(def, file_get_data(ef), 4);
            def[4] = def[5] = 3; // PIV retries
            file_put_data(ef, CONST_BYTE_ARRAY(def, sizeof(def)));
        }
    }
    bool reset_dek = false;
    if ((ef = file_search_by_fid(EF_DEK_PWPIV, NULL, SPECIFY_ANY)) && !file_has_data(ef)) {
        printf("DEK PIV is empty or older\r\n");
        const uint8_t defpin[8] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36 };
        const uint8_t *random_dek = random_bytes_get(IV_SIZE + 32);

        uint8_t def[DEK_FILE_SIZE];
        def[0] = 0x3; // Format

        pin_derive_session(CONST_BYTE_ARRAY(defpin, sizeof(defpin)), session_pwpiv);
        encrypt_with_aad(session_pwpiv, CONST_BYTE_ARRAY(random_dek, DEK_SIZE), PIN_KDF_DEFAULT_VERSION, def + 1);
        mbedtls_platform_zeroize(session_pwpiv, sizeof(session_pwpiv));
        file_put_data(ef, CONST_BYTE_ARRAY(def, sizeof(def)));

        openpgp_key_container_store(EF_PIV_KEY_CARDMGM, piv_management_key_default, sizeof(piv_management_key_default), NULL, 0, true);
        uint8_t meta[] = { PIV_ALGO_AES192, MGM_PIN_POLICY, TOUCHPOLICY_ALWAYS };
        meta_add(EF_PIV_KEY_CARDMGM, CONST_BYTE_ARRAY(meta, sizeof(meta)));

        reset_dek = true;
    }
    if ((ef = file_search_by_fid(EF_PIV_PIN, NULL, SPECIFY_ANY))) {
        if (!ef->data || reset_dek) {
            printf("PIV PIN is empty. Initializing with default password\r\n");
            const uint8_t def[8] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF };
            uint8_t dhash[34];
            dhash[0] = sizeof(def);
            dhash[1] = 0x1; // Format
            pin_derive_verifier(CONST_BYTE_ARRAY(def, sizeof(def)), dhash + 2);
            file_put_data(ef, CONST_BYTE_ARRAY(dhash, sizeof(dhash)));
        }
    }
    if ((ef = file_search_by_fid(EF_PIV_PUK, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("PIV PUK is empty. Initializing with default password\r\n");
            const uint8_t def[8] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
            uint8_t dhash[34];
            dhash[0] = sizeof(def);
            dhash[1] = 0x1; // Format
            pin_derive_verifier(CONST_BYTE_ARRAY(def, sizeof(def)), dhash + 2);
            file_put_data(ef, CONST_BYTE_ARRAY(dhash, sizeof(dhash)));
        }
    }
    if ((ef = file_search_by_fid(EF_PIV_KEY_ATTESTATION, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("ATTESTATION key is empty. Initializing with random one\r\n");
            mbedtls_ecdsa_context ecdsa;
            mbedtls_ecdsa_init(&ecdsa);
            int r = mbedtls_ecdsa_genkey(&ecdsa, MBEDTLS_ECP_DP_SECP384R1, random_fill_iterator, NULL);
            r = store_keys(&ecdsa, ALGO_ECDSA, EF_PIV_KEY_ATTESTATION, false);
            uint8_t cert[2048];
            r = x509_create_cert(&ecdsa, PIV_ALGO_ECCP384, EF_PIV_KEY_ATTESTATION, false, cert, sizeof(cert));
            ef = file_search_by_fid(EF_PIV_ATTESTATION, NULL, SPECIFY_ANY);
            file_put_data(ef, CONST_BYTE_ARRAY(cert + sizeof(cert) - r, r));
            mbedtls_ecdsa_free(&ecdsa);
        }
    }
    flash_commit();
}

void init_piv(void) {
    scan_files_piv();
    has_pwpiv = false;
    has_mgm = false;
    clear_mgm_challenge();
    // cmd_select();
}

static int piv_unload(void) {
    has_pwpiv = false;
    has_mgm = false;
    clear_mgm_challenge();
    return PICOKEYS_OK;
}

static void select_piv_aid(void) {
    res_APDU[res_APDU_size++] = 0x61;
    res_APDU[res_APDU_size++] = 0; //filled later
    res_APDU[res_APDU_size++] = 0x4F;
    res_APDU[res_APDU_size++] = 2;
    res_APDU[res_APDU_size++] = 0x01;
    res_APDU[res_APDU_size++] = 0x00;
    res_APDU[res_APDU_size++] = 0x79;
    res_APDU[res_APDU_size++] = 9;
    memcpy(res_APDU + res_APDU_size, "\xA0\x00\x00\x03\x08\x00\x00\x10\x00", 9);
    res_APDU_size += 9;
    const char *app_label = "Pico Keys PIV";
    res_APDU[res_APDU_size++] = 0x50;
    res_APDU[res_APDU_size++] = strlen(app_label);
    memcpy(res_APDU + res_APDU_size, app_label, strlen(app_label));

    res_APDU[res_APDU_size++] = 0xAC;
    res_APDU[res_APDU_size++] = 12;
    res_APDU[res_APDU_size++] = 0x80;
    res_APDU[res_APDU_size++] = 7;
    memcpy(res_APDU + res_APDU_size, "\x07\x08\x0A\x0C\x11\x14\x2E", 7);
    res_APDU_size += 7;
    res_APDU[res_APDU_size++] = 0x6;
    res_APDU[res_APDU_size++] = 1;
    res_APDU[res_APDU_size++] = 0x00;
}

static int piv_select_aid(app_t *a, uint8_t force) {
    (void) force;
    a->process_apdu = piv_process_apdu;
    a->unload = piv_unload;
    init_piv();
    select_piv_aid();
    return PICOKEYS_OK;
}

INITIALIZER( piv_ctor ) {
    register_app(piv_select_aid, piv_aid);
    register_app(piv_select_aid, yk_aid);
}

static int cmd_version(void) {
    res_APDU[res_APDU_size++] = PIV_VERSION_MAJOR;
    res_APDU[res_APDU_size++] = PIV_VERSION_MINOR;
    res_APDU[res_APDU_size++] = 0x0;
    return SW_OK();
}

static int cmd_piv_select(void) {
    if (P2(apdu) != 0x1) {
        return SW_WRONG_P1P2();
    }
    if (memcmp(apdu.data, piv_aid, 5) == 0) {
        select_piv_aid();
    }
    return SW_OK();
}

int piv_parse_discovery(const file_t *ef) {
    (void) ef;
    memcpy(res_APDU, "\x7E\x12\x4F\x0B\xA0\x00\x00\x03\x08\x00\x00\x10\x00\x01\x00\x5F\x2F\x02\x40\x10", 20);
    res_APDU_size = 20;
    return res_APDU_size;
}

static int cmd_get_serial(void) {
    uint32_t serial = get_serial();
    res_APDU[res_APDU_size++] = serial >> 24;
    res_APDU[res_APDU_size++] = serial >> 16;
    res_APDU[res_APDU_size++] = serial >> 8;
    res_APDU[res_APDU_size++] = serial & 0xFF;
    return SW_OK();
}

static int cmd_piv_verify(void) {
    uint8_t key_ref = P2(apdu);
    if (P1(apdu) != 0x00 && P1(apdu) != 0xFF) {
        return SW_INCORRECT_PARAMS();
    }
    if (key_ref != 0x80) {
        return SW_INCORRECT_PARAMS();
    }
    file_t *pw, *pw_status;
    uint16_t fid = EF_PIV_PIN;
    if (!(pw = file_search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!(pw_status = file_search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (file_get_data(pw)[0] == 0) { //not initialized
        return SW_REFERENCE_NOT_FOUND();
    }
    if (P1(apdu) == 0xFF) {
        if (apdu.nc != 0) {
            return SW_INCORRECT_PARAMS();
        }
        has_pwpiv = false;
        mbedtls_platform_zeroize(session_pwpiv, sizeof(session_pwpiv));
        return SW_OK();
    }
    if (apdu.nc > 0) {
        uint16_t ret = check_pin(pw, apdu.data, apdu.nc);
        if (ret == 0x9000) {
            has_pwpiv = true;
            hash_multi(CONST_BYTE_ARRAY(apdu.data, apdu.nc), session_pwpiv);
        }
        return ret; //SW already set
    }
    uint8_t retries = *(file_get_data(pw_status) + 3 + (fid & 0xf));
    if (retries == 0) {
        return SW_PIN_BLOCKED();
    }
    if ((key_ref == 0x80 && has_pwpiv)) {
        return SW_OK();
    }
    return set_res_sw(0x63, 0xc0 | retries);
}

static int cmd_piv_get_data(void) {
    if (P1(apdu) != 0x3F || P2(apdu) != 0xFF) {
        return SW_INCORRECT_P1P2();
    }
    if (apdu.nc < 3) {
        return SW_WRONG_LENGTH();
    }
    if (apdu.data[0] != 0x5C || (apdu.data[1] & 0x80) || apdu.data[1] >= 4 || apdu.data[1] == 0) {
        return SW_WRONG_DATA();
    }
    if (apdu.nc != (uint32_t)apdu.data[1] + 2u) {
        return SW_WRONG_LENGTH();
    }
    uint32_t fid = apdu.data[2];
    for (uint8_t lt = 1; lt < apdu.data[1]; lt++) {
        fid <<= 8;
        fid |= apdu.data[2 + lt];
    }
    if ((fid & 0xFFFF00) != 0x5FC100 && fid != EF_PIV_BITGT && fid != EF_PIV_DISCOVERY && fid != PIV_DATA_ADMIN_ID && fid != PIV_DATA_ATTESTATION_ID) {
        return SW_FILE_NOT_FOUND();
    }
    file_t *ef = NULL;
    if ((ef = file_search_by_fid((uint16_t)(fid & 0xFFFF), NULL, SPECIFY_EF))) {
        uint16_t data_len = 0;
        res_APDU_size = 2; // Minimum: TAG+LEN
        if ((file_get_type(ef) & FILE_DATA_FUNC) == FILE_DATA_FUNC) {
            int (*file_data_func)(const file_t *) = NULL;
            memcpy(&file_data_func, &ef->data, sizeof(file_data_func));
            data_len = file_data_func(ef);
        }
        else {
            if (ef->data) {
                data_len = MIN(file_get_size(ef), OPENPGP_MAX_OBJECT_SIZE);
                data_len = MIN(data_len, OPENPGP_MAX_RESPONSE_SIZE - 4);
                memcpy(res_APDU + res_APDU_size, file_get_data(ef), data_len);
            }
        }
        if (data_len == 0) {
            return SW_FILE_NOT_FOUND();
        }
        if (data_len > 255) {
            memmove(res_APDU + res_APDU_size + 2, res_APDU + res_APDU_size, data_len);
        }
        else if (data_len > 127) {
            memmove(res_APDU + res_APDU_size + 1, res_APDU + res_APDU_size, data_len);
        }
        res_APDU[0] = 0x53;
        res_APDU_size = 1 + tlv_format_len(data_len, res_APDU + 1) + data_len;
    }
    else {
        return SW_FILE_NOT_FOUND();
    }
    return SW_OK();
}

static int cmd_get_metadata(void) {
    if (P1(apdu) != 0x00) {
        return SW_INCORRECT_P1P2();
    }
    uint16_t key_ref = P2(apdu);
    if (key_ref == 0x80) {
        key_ref = EF_PIV_PIN;
    }
    else if (key_ref == 0x81) {
        key_ref = EF_PIV_PUK;
    }
    else if (key_ref == 0xF9) {
        key_ref = EF_PIV_KEY_ATTESTATION;
    }
    uint16_t key_fid = key_ref == 0x93 ? EF_PIV_KEY_RETIRED18 : key_ref;
    byte_array_t metadata = meta_find(key_ref);
    uint8_t *meta = metadata.data;
    file_t *ef_key = file_search_by_fid(key_fid, NULL, SPECIFY_EF);
    if (!file_has_data(ef_key)) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (key_ref != EF_PIV_PIN && key_ref != EF_PIV_PUK) {
        uint8_t attestation_meta[] = {PIV_ALGO_ECCP384, PINPOLICY_ONCE, TOUCHPOLICY_NEVER, ORIGIN_GENERATED};
        if (!meta && key_ref == EF_PIV_KEY_ATTESTATION) {
            meta = attestation_meta;
        }
        if (!meta) {
            return SW_REFERENCE_NOT_FOUND();
        }
        res_APDU[res_APDU_size++] = 0x1;
        res_APDU[res_APDU_size++] = 1;
        res_APDU[res_APDU_size++] = meta[0];
        res_APDU[res_APDU_size++] = 0x2;
        res_APDU[res_APDU_size++] = 2;
        res_APDU[res_APDU_size++] = meta[1];
        res_APDU[res_APDU_size++] = meta[2];
        if (key_ref != EF_PIV_KEY_CARDMGM) {
            res_APDU[res_APDU_size++] = 0x3;
            res_APDU[res_APDU_size++] = 1;
            res_APDU[res_APDU_size++] = meta[3];
            if (meta[0] == PIV_ALGO_RSA1024 || meta[0] == PIV_ALGO_RSA2048 || meta[0] == PIV_ALGO_RSA3072 || meta[0] == PIV_ALGO_RSA4096 || meta[0] == PIV_ALGO_ECCP256 || meta[0] == PIV_ALGO_ECCP384) {
                res_APDU[res_APDU_size++] = 0x4;
                res_APDU[res_APDU_size++] = 0; // Filled later
                uint8_t *pk = &res_APDU[res_APDU_size];
                if (meta[0] == PIV_ALGO_RSA1024 || meta[0] == PIV_ALGO_RSA2048 || meta[0] == PIV_ALGO_RSA3072 || meta[0] == PIV_ALGO_RSA4096) {
                    mbedtls_rsa_context ctx;
                    mbedtls_rsa_init(&ctx);
                    int r = load_private_key_rsa(&ctx, ef_key, false);
                    if (r != PICOKEYS_OK) {
                        mbedtls_rsa_free(&ctx);
                        return SW_EXEC_ERROR();
                    }
                    res_APDU[res_APDU_size++] = 0x81;
                    res_APDU[res_APDU_size++] = 0x82;
                    put_uint16_be(mbedtls_mpi_size(&ctx.N), res_APDU + res_APDU_size); res_APDU_size += 2;
                    mbedtls_mpi_write_binary(&ctx.N, res_APDU + res_APDU_size, mbedtls_mpi_size(&ctx.N));
                    res_APDU_size += mbedtls_mpi_size(&ctx.N);
                    res_APDU[res_APDU_size++] = 0x82;
                    res_APDU[res_APDU_size++] = mbedtls_mpi_size(&ctx.E) & 0xff;
                    mbedtls_mpi_write_binary(&ctx.E, res_APDU + res_APDU_size, mbedtls_mpi_size(&ctx.E));
                    res_APDU_size += mbedtls_mpi_size(&ctx.E);
                    mbedtls_rsa_free(&ctx);
                }
                else {
                    mbedtls_ecdsa_context ctx;
                    mbedtls_ecdsa_init(&ctx);
                    int r = load_private_key_ecdsa(&ctx, ef_key, false);
                    if (r != PICOKEYS_OK) {
                        mbedtls_ecdsa_free(&ctx);
                        return SW_EXEC_ERROR();
                    }
                    uint8_t pt[MBEDTLS_ECP_MAX_PT_LEN];
                    size_t plen = 0;
                    mbedtls_ecp_point_write_binary(&ctx.grp, &ctx.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &plen, pt, sizeof(pt));
                    mbedtls_ecdsa_free(&ctx);
                    res_APDU[res_APDU_size++] = 0x86;
                    if (plen >= 128) {
                        res_APDU[res_APDU_size++] = 0x81;
                    }
                    res_APDU[res_APDU_size++] = plen;
                    memcpy(res_APDU + res_APDU_size, pt, plen);
                    res_APDU_size += plen;
                }
                uint16_t pk_len = res_APDU_size - (pk - res_APDU);
                if (pk_len > 255) {
                    memmove(pk + 2, pk, pk_len);
                    pk[-1] = 0x82;
                    pk[0] = pk_len >> 8;
                    pk[1] = pk_len & 0xff;
                    res_APDU_size += 2;
                }
                else if (pk_len > 127) {
                    memmove(pk + 1, pk, pk_len);
                    pk[-1] = 0x81;
                    pk[0] = pk_len;
                    res_APDU_size += 1;
                }
                else {
                    pk[-1] = pk_len;
                }
            }
        }
    }
    if (key_ref == EF_PIV_PIN || key_ref == EF_PIV_PUK || key_ref == EF_PIV_KEY_CARDMGM) {
        uint8_t dhash[32];
        int32_t eq = 0;
        bool is_default;
        if (key_ref == EF_PIV_PIN) {
            pin_derive_verifier(CONST_BYTE_ARRAY((const uint8_t *)"\x31\x32\x33\x34\x35\x36\xFF\xFF", 8), dhash);
            eq = file_get_size(ef_key) == 34u && file_get_data(ef_key)[1] == 1u ? mbedtls_ct_memcmp(dhash, file_get_data(ef_key) + 2, sizeof(dhash)) : -1;
        }
        else if (key_ref == EF_PIV_PUK) {
            pin_derive_verifier(CONST_BYTE_ARRAY((const uint8_t *)"\x31\x32\x33\x34\x35\x36\x37\x38", 8), dhash);
            eq = file_get_size(ef_key) == 34u && file_get_data(ef_key)[1] == 1u ? mbedtls_ct_memcmp(dhash, file_get_data(ef_key) + 2, sizeof(dhash)) : -1;
        }
        else if (key_ref == EF_PIV_KEY_CARDMGM) {
            uint8_t management_key[32] = { 0 };
            byte_buffer_t management_key_data = BYTE_BUFFER(management_key, sizeof(management_key));
            int r = openpgp_key_container_is_marker(ef_key) ? openpgp_key_container_read_private(EF_PIV_KEY_CARDMGM, FILE_OBJECT_OPERATION_USE, true, &management_key_data) : PICOKEYS_OK;
            size_t management_key_size = management_key_data.len;
            if (!openpgp_key_container_is_marker(ef_key)) {
                management_key_size = MIN(file_get_size(ef_key), sizeof(management_key));
                memcpy(management_key, file_get_data(ef_key), management_key_size);
            }
            eq = r == PICOKEYS_OK && management_key_size == sizeof(piv_management_key_default) ? mbedtls_ct_memcmp(piv_management_key_default, management_key, management_key_size) : -1;
            mbedtls_platform_zeroize(management_key, sizeof(management_key));
        }
        is_default = eq == 0;
        if (key_ref == EF_PIV_KEY_CARDMGM) {
            is_default = is_default & (meta[2] == TOUCHPOLICY_NEVER);
        }
        if (key_ref == EF_PIV_PIN || key_ref == EF_PIV_PUK) {
            res_APDU[res_APDU_size++] = 0x1;
            res_APDU[res_APDU_size++] = 0x1;
            res_APDU[res_APDU_size++] = PIV_ALGO_PIN;
        }
        res_APDU[res_APDU_size++] = 0x5;
        res_APDU[res_APDU_size++] = 1;
        res_APDU[res_APDU_size++] = is_default;
        if (key_ref == EF_PIV_PIN || key_ref == EF_PIV_PUK) {
            file_t *pw_status;
            if (!(pw_status = file_search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF))) {
                return SW_REFERENCE_NOT_FOUND();
            }
            uint8_t retries = *(file_get_data(pw_status) + 3 + (key_ref & 0xf));
            if (!(pw_status = file_search_by_fid(EF_PW_RETRIES, NULL, SPECIFY_EF))) {
                return SW_REFERENCE_NOT_FOUND();
            }
            uint8_t total = *(file_get_data(pw_status) + (key_ref & 0xf));
            res_APDU[res_APDU_size++] = 0x6;
            res_APDU[res_APDU_size++] = 2;
            res_APDU[res_APDU_size++] = total;
            res_APDU[res_APDU_size++] = retries;
        }
    }
    return SW_OK();
}
static int mgm_crypt(uint8_t algo, const file_t *ef_mgm, const uint8_t *input, uint8_t *output, bool encrypt) {
    uint8_t management_key[32] = { 0 };
    size_t key_len = 0;
    int r = PICOKEYS_OK;
    if (openpgp_key_container_is_marker(ef_mgm)) {
        byte_buffer_t key = BYTE_BUFFER(management_key, sizeof(management_key));
        r = openpgp_key_container_read_private(EF_PIV_KEY_CARDMGM, FILE_OBJECT_OPERATION_USE, true, &key);
        key_len = key.len;
    }
    else if (file_has_data(ef_mgm) && file_get_size(ef_mgm) <= sizeof(management_key)) {
        key_len = file_get_size(ef_mgm);
        memcpy(management_key, file_get_data(ef_mgm), key_len);
    }
    else {
        r = PICOKEYS_WRONG_DATA;
    }
    if (r != PICOKEYS_OK) {
        return r;
    }

    if (algo == PIV_ALGO_3DES) {
        mbedtls_des3_context ctx;
        mbedtls_des3_init(&ctx);
        r = key_len == 24 ? (encrypt ? mbedtls_des3_set3key_enc(&ctx, management_key) : mbedtls_des3_set3key_dec(&ctx, management_key)) : PICOKEYS_WRONG_DATA;
        if (r == 0) {
            r = mbedtls_des3_crypt_ecb(&ctx, input, output);
        }
        mbedtls_des3_free(&ctx);
        mbedtls_platform_zeroize(management_key, sizeof(management_key));
        return r;
    }

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    r = encrypt ? mbedtls_aes_setkey_enc(&ctx, management_key, (unsigned int)(key_len * 8u)) : mbedtls_aes_setkey_dec(&ctx, management_key, (unsigned int)(key_len * 8u));
    if (r == 0) {
        r = mbedtls_aes_crypt_ecb(&ctx, encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT,
                                  input, output);
    }
    mbedtls_aes_free(&ctx);
    mbedtls_platform_zeroize(management_key, sizeof(management_key));
    return r;
}

static int authenticate_mgm(uint8_t algo, file_t *ef_mgm, uint8_t chal_len,
                            const tlv_ctx_t *a80, const tlv_ctx_t *a81,
                            const tlv_ctx_t *a82) {
    bool has_80 = a80->data != NULL;
    bool has_81 = a81->data != NULL;
    bool has_82 = a82->data != NULL;

    if (has_80 && a80->len == 0 && !has_81 && !has_82) {
        clear_mgm_challenge();
        memcpy(mgm_challenge, random_bytes_get(chal_len), chal_len);
        mgm_challenge_kind = MGM_CHALLENGE_MUTUAL;
        mgm_challenge_algo = algo;
        res_APDU[res_APDU_size++] = 0x7C;
        res_APDU[res_APDU_size++] = chal_len + 2;
        res_APDU[res_APDU_size++] = 0x80;
        res_APDU[res_APDU_size++] = chal_len;
        if (mgm_crypt(algo, ef_mgm, mgm_challenge, res_APDU + res_APDU_size, true) != 0) {
            clear_mgm_challenge();
            return SW_EXEC_ERROR();
        }
        has_mgm = false;
        res_APDU_size += chal_len;
        return SW_OK();
    }

    if (has_81 && a81->len == 0 && !has_80 && !has_82) {
        clear_mgm_challenge();
        memcpy(mgm_challenge, random_bytes_get(chal_len), chal_len);
        mgm_challenge_kind = MGM_CHALLENGE_SINGLE;
        mgm_challenge_algo = algo;
        res_APDU[res_APDU_size++] = 0x7C;
        res_APDU[res_APDU_size++] = chal_len + 2;
        res_APDU[res_APDU_size++] = 0x81;
        res_APDU[res_APDU_size++] = chal_len;
        memcpy(res_APDU + res_APDU_size, mgm_challenge, chal_len);
        res_APDU_size += chal_len;
        has_mgm = false;
        return SW_OK();
    }

    if (has_80 && a80->len > 0) {
        bool valid_state = mgm_challenge_kind == MGM_CHALLENGE_MUTUAL &&
                           mgm_challenge_algo == algo &&
                           a80->len == chal_len && has_81 && a81->len == chal_len && !has_82;
        bool witness_matches = valid_state &&
                               mbedtls_ct_memcmp(a80->data, mgm_challenge, chal_len) == 0;
        clear_mgm_challenge();
        if (!witness_matches) {
            return SW_DATA_INVALID();
        }

        res_APDU[res_APDU_size++] = 0x7C;
        res_APDU[res_APDU_size++] = chal_len + 2;
        res_APDU[res_APDU_size++] = 0x82;
        res_APDU[res_APDU_size++] = chal_len;
        if (mgm_crypt(algo, ef_mgm, a81->data, res_APDU + res_APDU_size, true) != 0) {
            return SW_EXEC_ERROR();
        }
        res_APDU_size += chal_len;
        has_mgm = true;
        return SW_OK();
    }

    if (has_82 && a82->len > 0) {
        bool valid_state = mgm_challenge_kind == MGM_CHALLENGE_SINGLE &&
                           mgm_challenge_algo == algo &&
                           a82->len == chal_len && !has_80 && !has_81;
        uint8_t response[sizeof(mgm_challenge)] = { 0 };
        int r = valid_state ? mgm_crypt(algo, ef_mgm, a82->data, response, false) : -1;
        bool response_matches = r == 0 &&
                                mbedtls_ct_memcmp(response, mgm_challenge, chal_len) == 0;
        memset(response, 0, sizeof(response));
        clear_mgm_challenge();
        if (r != 0 && valid_state) {
            return SW_EXEC_ERROR();
        }
        if (!response_matches) {
            return SW_DATA_INVALID();
        }
        has_mgm = true;
        return SW_OK();
    }

    clear_mgm_challenge();
    return SW_INCORRECT_PARAMS();
}

static bool piv_first_auth_operation(const tlv_ctx_t *ctx, uint16_t *tag, tlv_ctx_t *value) {
    uint8_t *p = NULL;
    tlv_item_t item;
    while (tlv_walk(ctx, &p, &item)) {
        if (item.tag == 0x82 && item.value.len == 0) {
            continue;
        }
        if (item.tag == 0x80 || item.tag == 0x81 || item.tag == 0x82 || item.tag == 0x85) {
            *tag = item.tag;
            value->data = (uint8_t *)item.value.data;
            value->len = item.value.len;
            return true;
        }
    }
    return false;
}

static int cmd_authenticate(void) {
    uint8_t algo = P1(apdu), key_ref = P2(apdu);
    if (apdu.nc == 0 || apdu.data[0] != 0x7C) {
        return SW_INCORRECT_PARAMS();
    }
    file_t *ef_mgm = NULL;
    if (key_ref == EF_PIV_KEY_CARDMGM) {
        ef_mgm = file_search_by_fid(key_ref, NULL, SPECIFY_EF);
        if (!file_has_data(ef_mgm)) {
            return SW_MEMORY_FAILURE();
        }
    }
    byte_array_t metadata = meta_find(key_ref);
    uint8_t *meta = metadata.data;
    if (metadata.len < 3) {
        return SW_REFERENCE_NOT_FOUND();
    }
    bool pending_mgm_challenge = key_ref == EF_PIV_KEY_CARDMGM && mgm_challenge_kind != MGM_CHALLENGE_NONE;
    if (key_ref == EF_PIV_KEY_CARDMGM) {
        if (algo != PIV_ALGO_AES128 && algo != PIV_ALGO_AES192 && algo != PIV_ALGO_AES256 && algo != PIV_ALGO_3DES) {
            return SW_INCORRECT_PARAMS();
        }
        uint8_t management_key[32] = { 0 };
        byte_buffer_t management_key_data = BYTE_BUFFER(management_key, sizeof(management_key));
        int r = openpgp_key_container_is_marker(ef_mgm) ? openpgp_key_container_read_private(EF_PIV_KEY_CARDMGM, FILE_OBJECT_OPERATION_USE, true, &management_key_data) : PICOKEYS_OK;
        size_t mgm_len = management_key_data.len;
        if (!openpgp_key_container_is_marker(ef_mgm)) {
            mgm_len = MIN(file_get_size(ef_mgm), sizeof(management_key));
        }
        mbedtls_platform_zeroize(management_key, sizeof(management_key));
        if (r != PICOKEYS_OK) {
            return SW_MEMORY_FAILURE();
        }
        if ((algo == PIV_ALGO_AES128 && mgm_len != 16) || (algo == PIV_ALGO_AES192 && mgm_len != 24) || (algo == PIV_ALGO_AES256 && mgm_len != 32) || (algo == PIV_ALGO_3DES && mgm_len != 24)) {
            return SW_INCORRECT_PARAMS();
        }
    }
    if (meta[1] == PINPOLICY_DEFAULT) {
        meta[1] = piv_default_pin_policy(key_ref);
    }
    if ((meta[1] == PINPOLICY_ALWAYS || meta[1] == PINPOLICY_ONCE) && (!has_pwpiv && (key_ref == EF_PIV_KEY_AUTHENTICATION || key_ref == EF_PIV_KEY_SIGNATURE || key_ref == EF_PIV_KEY_KEYMGM || key_ref == EF_PIV_KEY_CARDAUTH || IS_RETIRED(key_ref)))) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    uint8_t chal_len = algo == PIV_ALGO_3DES ? sizeof(mgm_challenge) / 2 : sizeof(mgm_challenge);
    tlv_ctx_t ctxi, a7c = { 0 };
    tlv_ctx_init(BYTE_ARRAY(apdu.data, apdu.nc), &ctxi);
    if (!tlv_find_tag(&ctxi, 0x7C, &a7c) || tlv_len(&a7c) == 0) {
        return SW_INCORRECT_PARAMS();
    }
    uint16_t operation_tag = 0;
    tlv_ctx_t operation = { 0 };
    if (!piv_first_auth_operation(&a7c, &operation_tag, &operation)) {
        return SW_INCORRECT_PARAMS();
    }
    bool challenge_response = (operation_tag == 0x80 || operation_tag == 0x82) && operation.len > 0;
    size_t slot_rsa_modulus_size = piv_rsa_modulus_size(meta[0]);
    bool rsa_family_match = slot_rsa_modulus_size > 0 && piv_rsa_modulus_size(algo) > 0 && operation_tag == 0x81 && operation.len == slot_rsa_modulus_size;
    if (algo != meta[0] && !rsa_family_match && !(pending_mgm_challenge && challenge_response)) {
        return SW_WRONG_DATA();
    }
    if (key_ref == EF_PIV_KEY_CARDMGM) {
        tlv_ctx_t empty = { 0 };
        if (operation_tag == 0x80) {
            tlv_ctx_t host_challenge = { 0 };
            tlv_find_tag(&a7c, 0x81, &host_challenge);
            return authenticate_mgm(algo, ef_mgm, chal_len, &operation, &host_challenge, &empty);
        }
        if (operation_tag == 0x81 && operation.len == 0) {
            return authenticate_mgm(algo, ef_mgm, chal_len, &empty, &operation, &empty);
        }
        if (operation_tag == 0x82) {
            return authenticate_mgm(algo, ef_mgm, chal_len, &empty, &empty, &operation);
        }
        return SW_INCORRECT_PARAMS();
    }
    if (operation_tag != 0x81) {
        return SW_INCORRECT_PARAMS();
    }
    if (algo != PIV_ALGO_RSA1024 && algo != PIV_ALGO_RSA2048 && algo != PIV_ALGO_RSA3072 && algo != PIV_ALGO_RSA4096 && algo != PIV_ALGO_ECCP256 && algo != PIV_ALGO_ECCP384) {
        return SW_INCORRECT_PARAMS();
    }

    file_t *ef_key = file_search_by_fid(key_ref == 0x93 ? EF_PIV_KEY_RETIRED18 : key_ref, NULL, SPECIFY_EF);
    if (!file_has_data(ef_key)) {
        return SW_MEMORY_FAILURE();
    }
    if (algo == PIV_ALGO_RSA1024 || algo == PIV_ALGO_RSA2048 || algo == PIV_ALGO_RSA3072 || algo == PIV_ALGO_RSA4096) {
        mbedtls_rsa_context ctx;
        mbedtls_rsa_init(&ctx);
        int r = load_private_key_rsa(&ctx, ef_key, false);
        if (r != PICOKEYS_OK) {
            mbedtls_rsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        size_t olen = mbedtls_rsa_get_len(&ctx);
        if (olen < 256) {
            memcpy(res_APDU, "\x7C\x81\x00\x82\x81\x00", 6);
            res_APDU_size = 6;
        }
        else {
            memcpy(res_APDU, "\x7C\x82\x00\x00\x82\x82\x00\x00", 8);
            res_APDU_size = 8;
        }
        r = mbedtls_rsa_private(&ctx, random_fill_iterator, NULL, operation.data, res_APDU + res_APDU_size);
        mbedtls_rsa_free(&ctx);
        if (olen < 256) {
            res_APDU[res_APDU_size - 1] = olen;
            res_APDU[res_APDU_size - 4] = olen + 3;
        }
        else {
            res_APDU[res_APDU_size - 2] = olen >> 8;
            res_APDU[res_APDU_size - 1] = olen & 0xFF;
            res_APDU[res_APDU_size - 6] = (olen + 4) >> 8;
            res_APDU[res_APDU_size - 5] = (olen + 4) & 0xFF;
        }
        res_APDU_size += olen;
        if (r != 0) {
            return SW_EXEC_ERROR();
        }
    }
    else if (algo == PIV_ALGO_ECCP256 || algo == PIV_ALGO_ECCP384) {
        mbedtls_ecdsa_context ctx;
        mbedtls_ecdsa_init(&ctx);
        int r = load_private_key_ecdsa(&ctx, ef_key, false);
        if (r != PICOKEYS_OK) {
            mbedtls_ecdsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        size_t olen = 0;
        memcpy(res_APDU, "\x7C\x00\x82\x00", 4);
        res_APDU_size = 4;
        r = mbedtls_ecdsa_write_signature(&ctx, algo == PIV_ALGO_ECCP256 ? MBEDTLS_MD_SHA256 : MBEDTLS_MD_SHA384, operation.data, operation.len, res_APDU + res_APDU_size, MBEDTLS_ECDSA_MAX_LEN, &olen, random_fill_iterator, NULL);
        mbedtls_ecdsa_free(&ctx);
        res_APDU[res_APDU_size - 1] = olen;
        res_APDU[res_APDU_size - 3] = olen + 2;
        res_APDU_size += olen;
        if (r != 0) {
            return SW_EXEC_ERROR();
        }
    }
    else {
        return SW_INCORRECT_PARAMS();
    }
    if (meta[1] == PINPOLICY_ALWAYS) {
        has_pwpiv = false;
    }
    return SW_OK();
}

static int cmd_asym_keygen(void) {
    uint8_t key_ref = P2(apdu);
    if (!has_mgm) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (apdu.nc == 0 || apdu.data[0] != 0xAC) {
        return SW_INCORRECT_PARAMS();
    }
    if (P1(apdu) != 0x0) {
        return SW_INCORRECT_P1P2();
    }
    if (key_ref != EF_PIV_KEY_AUTHENTICATION && key_ref != EF_PIV_KEY_SIGNATURE && key_ref != EF_PIV_KEY_KEYMGM && key_ref != EF_PIV_KEY_CARDAUTH && !(key_ref >= EF_PIV_KEY_RETIRED1 && key_ref <= EF_PIV_KEY_RETIRED20)) {
        return SW_INCORRECT_P1P2();
    }
    tlv_ctx_t ctxi, aac = {0};
    tlv_ctx_init(BYTE_ARRAY(apdu.data, apdu.nc), &ctxi);
    if (!tlv_find_tag(&ctxi, 0xAC, &aac) || tlv_len(&aac) == 0) {
        return SW_WRONG_DATA();
    }
    tlv_ctx_t a80 = {0}, aaa = {0}, aab = {0};
    tlv_find_tag(&aac, 0x80, &a80);
    tlv_find_tag(&aac, 0xAA, &aaa);
    tlv_find_tag(&aac, 0xAB, &aab);
    if (tlv_len(&a80) == 0) {
        return SW_WRONG_DATA();
    }
    uint16_t key_cert = 0;
    if (key_ref == EF_PIV_KEY_AUTHENTICATION) {
        key_cert = EF_PIV_AUTHENTICATION;
    }
    else if (key_ref == EF_PIV_KEY_SIGNATURE) {
        key_cert = EF_PIV_SIGNATURE;
    }
    else if (key_ref == EF_PIV_KEY_KEYMGM) {
        key_cert = EF_PIV_KEY_MANAGEMENT;
    }
    else if (key_ref == EF_PIV_KEY_CARDAUTH) {
        key_cert = EF_PIV_CARD_AUTH;
    }
    else {
        key_cert = key_ref + 0xC08B;
    }
    if (a80.data[0] == PIV_ALGO_RSA1024 || a80.data[0] == PIV_ALGO_RSA2048) {
        printf("KEYPAIR RSA\r\n");
        tlv_ctx_t a81 = {0};
        tlv_find_tag(&aac, 0x81, &a81);
        mbedtls_rsa_context rsa;
        mbedtls_rsa_init(&rsa);
        int exponent = 65537, nlen = (a80.data[0] == PIV_ALGO_RSA1024 ? 1024 : 2048);
        if (tlv_len(&a81)) {
            exponent = (int)tlv_get_uint(&a81);
        }
        int r = mbedtls_rsa_gen_key(&rsa, random_fill_iterator, NULL, nlen, exponent);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_EXEC_ERROR();
        }
        make_rsa_response(&rsa);
        uint8_t cert[2048];
        r = x509_create_cert(&rsa, a80.data[0], key_ref, false, cert, sizeof(cert));
        file_t *ef = file_search_by_fid(key_cert, NULL, SPECIFY_ANY);
        file_put_data(ef, CONST_BYTE_ARRAY(cert + sizeof(cert) - r, r));
        r = store_keys(&rsa, ALGO_RSA, key_ref == 0x93 ? EF_PIV_KEY_RETIRED18 : key_ref, false);
        mbedtls_rsa_free(&rsa);
        if (r != PICOKEYS_OK) {
            return SW_EXEC_ERROR();
        }
    }
    else if (a80.data[0] == PIV_ALGO_ECCP256 || a80.data[0] == PIV_ALGO_ECCP384) {
        printf("KEYPAIR ECDSA\r\n");
        mbedtls_ecp_group_id gid = a80.data[0] == PIV_ALGO_ECCP256 ? MBEDTLS_ECP_DP_SECP256R1 : MBEDTLS_ECP_DP_SECP384R1;
        mbedtls_ecdsa_context ecdsa;
        mbedtls_ecdsa_init(&ecdsa);
        int r = mbedtls_ecdsa_genkey(&ecdsa, gid, random_fill_iterator, NULL);
        if (r != 0) {
            mbedtls_ecdsa_free(&ecdsa);
            return SW_EXEC_ERROR();
        }
        make_ecdsa_response(&ecdsa);
        uint8_t cert[2048];
        r = x509_create_cert(&ecdsa, a80.data[0], key_ref, false, cert, sizeof(cert));
        file_t *ef = file_search_by_fid(key_cert, NULL, SPECIFY_ANY);
        file_put_data(ef, CONST_BYTE_ARRAY(cert + sizeof(cert) - r, r));
        r = store_keys(&ecdsa, ALGO_ECDSA, key_ref == 0x93 ? EF_PIV_KEY_RETIRED18 : key_ref, false);
        mbedtls_ecdsa_free(&ecdsa);
        if (r != PICOKEYS_OK) {
            return SW_EXEC_ERROR();
        }
    }
    else if (a80.data[0] == PIV_ALGO_X25519) {
    }
    else {
        return SW_DATA_INVALID();
    }
    uint8_t def_pinpol = piv_default_pin_policy(key_ref);
    uint8_t meta[] = {a80.data[0], tlv_len(&aaa) ? aaa.data[0] : def_pinpol, tlv_len(&aab) ? aab.data[0] : PIV_DEFAULT_TOUCH_POLICY, ORIGIN_GENERATED};
    if (meta_add(key_ref, CONST_BYTE_ARRAY(meta, sizeof(meta))) != PICOKEYS_OK || !flash_commit_sync(PIV_FLASH_COMMIT_TIMEOUT_MS)) {
        return SW_MEMORY_FAILURE();
    }
    return SW_OK();
}

static int cmd_piv_put_data(void) {
    if (P1(apdu) != 0x3F || P2(apdu) != 0xFF) {
        return SW_INCORRECT_P1P2();
    }
    if (!has_mgm) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (apdu.nc == 0) {
        return SW_WRONG_LENGTH();
    }
    tlv_ctx_t ctxi, a5c = {0}, a53 = {0};
    tlv_ctx_init(BYTE_ARRAY(apdu.data, apdu.nc), &ctxi);
    if (apdu.data[0] != 0x7E && apdu.data[0] != 0x7F && (!tlv_find_tag(&ctxi, 0x5C, &a5c) || !tlv_find_tag(&ctxi, 0x53, &a53))) {
        return SW_WRONG_DATA();
    }
    if (a5c.data && a53.data) {
        if (a5c.len != 3 || a5c.data[0] != 0x5F || a5c.data[1] != 0xC1) {
            return SW_WRONG_DATA();
        }
        uint16_t fid = (a5c.data[1] << 8 | a5c.data[2]);
        file_t *ef = file_search_by_fid(fid, NULL, SPECIFY_EF);
        if (!ef) {
            return SW_MEMORY_FAILURE();
        }
        if (a53.len > OPENPGP_MAX_OBJECT_SIZE) {
            return SW_WRONG_LENGTH();
        }
        if (a53.len > 0) {
            file_put_data(ef, CONST_BYTE_ARRAY(a53.data, a53.len));
        }
        else {
            if (flash_clear_file(ef) != PICOKEYS_OK) {
                return SW_MEMORY_FAILURE();
            }
        }
        flash_commit();
    }
    return SW_OK();
}

static int cmd_set_mgmkey(void) {
    if (P1(apdu) != 0xFF) {
        return SW_INCORRECT_P1P2();
    }
    if (apdu.nc < 5) {
        return SW_WRONG_LENGTH();
    }
    if (!has_mgm) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    uint8_t touch = P2(apdu);
    if (touch != 0xFF && touch != 0xFE) {
        return SW_INCORRECT_P1P2();
    }
    if (touch == 0xFF) {
        touch = TOUCHPOLICY_NEVER;
    }
    else if (touch == 0xFE) {
        touch = TOUCHPOLICY_ALWAYS;
    }
    uint8_t algo = apdu.data[0], key_ref = apdu.data[1], pinlen = apdu.data[2];
    if ((key_ref != EF_PIV_KEY_CARDMGM) || (!(algo == PIV_ALGO_AES128 && pinlen == 16) && !(algo == PIV_ALGO_AES192 && pinlen == 24) && !(algo == PIV_ALGO_AES256 && pinlen == 32) && !(algo == PIV_ALGO_3DES && pinlen == 24))) {
        return SW_WRONG_DATA();
    }
    if (apdu.nc != (uint32_t)pinlen + 3u) {
        return SW_WRONG_LENGTH();
    }
    if (openpgp_key_container_store(key_ref, apdu.data + 3, pinlen, NULL, 0, true) != PICOKEYS_OK) {
        return SW_MEMORY_FAILURE();
    }
    byte_array_t metadata = meta_find(key_ref);
    uint8_t *meta = metadata.data;
    uint8_t new_meta[4];
    if (!meta) {
        return SW_REFERENCE_NOT_FOUND();
    }
    memcpy(new_meta, meta, 4);
    new_meta[0] = algo;
    new_meta[2] = touch;
    if (meta_add(key_ref, CONST_BYTE_ARRAY(new_meta, sizeof(new_meta))) != PICOKEYS_OK || !flash_commit_sync(PIV_FLASH_COMMIT_TIMEOUT_MS)) {
        return SW_MEMORY_FAILURE();
    }
    return SW_OK();
}

static int cmd_move_key(void) {
    if (!has_mgm) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    uint8_t to = P1(apdu), from = P2(apdu);
    if ((!IS_KEY(to) && to != 0xFF) || !IS_KEY(from)) {
        return SW_INCORRECT_P1P2();
    }
    if (to == from) {
        return SW_INCORRECT_P1P2();
    }
    if (from == 0x93) {
        from = EF_PIV_KEY_RETIRED18;
    }
    if (to == 0x93) {
        to = EF_PIV_KEY_RETIRED18;
    }
    file_t *efs, *efd;
    if (!(efs = file_search_by_fid(from, NULL, SPECIFY_EF)) || (!(efd = file_search_by_fid(to, NULL, SPECIFY_EF)) && to != 0xFF)) {
        return SW_FILE_NOT_FOUND();
    }
    uint16_t cert_from_fid = 0;
    uint16_t cert_to_fid = 0;
    if (from == EF_PIV_KEY_AUTHENTICATION) {
        cert_from_fid = EF_PIV_AUTHENTICATION;
    }
    else if (from == EF_PIV_KEY_SIGNATURE) {
        cert_from_fid = EF_PIV_SIGNATURE;
    }
    else if (from == EF_PIV_KEY_KEYMGM) {
        cert_from_fid = EF_PIV_KEY_MANAGEMENT;
    }
    else if (from == EF_PIV_KEY_CARDAUTH) {
        cert_from_fid = EF_PIV_CARD_AUTH;
    }
    else if (from == EF_PIV_KEY_RETIRED18) {
        cert_from_fid = EF_PIV_RETIRED18;
    }
    else {
        cert_from_fid = from + 0xC08B;
    }
    if (to != 0xFF) {
        if (to == EF_PIV_KEY_AUTHENTICATION) {
            cert_to_fid = EF_PIV_AUTHENTICATION;
        }
        else if (to == EF_PIV_KEY_SIGNATURE) {
            cert_to_fid = EF_PIV_SIGNATURE;
        }
        else if (to == EF_PIV_KEY_KEYMGM) {
            cert_to_fid = EF_PIV_KEY_MANAGEMENT;
        }
        else if (to == EF_PIV_KEY_CARDAUTH) {
            cert_to_fid = EF_PIV_CARD_AUTH;
        }
        else if (to == EF_PIV_KEY_RETIRED18) {
            cert_to_fid = EF_PIV_RETIRED18;
        }
        else {
            cert_to_fid = to + 0xC08B;
        }
    }

    if (to != 0xFF) {
        uint8_t key_data[4096 / 8] = { 0 };
        byte_buffer_t key = BYTE_BUFFER(key_data, sizeof(key_data));
        int r = PICOKEYS_OK;
        if (openpgp_key_container_is_marker(efs)) {
            r = openpgp_key_container_read_private(from, FILE_OBJECT_OPERATION_USE, true, &key);
        }
        else if (file_has_data(efs) && file_get_size(efs) <= sizeof(key_data)) {
            key.len = file_get_size(efs);
            memcpy(key_data, file_get_data(efs), key.len);
        }
        else {
            r = PICOKEYS_WRONG_DATA;
        }
        if (r == PICOKEYS_OK) {
            r = openpgp_key_container_store(to, key_data, key.len, NULL, 0, true);
        }
        mbedtls_platform_zeroize(key_data, sizeof(key_data));
        if (r != PICOKEYS_OK) {
            return SW_EXEC_ERROR();
        }
    }

    file_t *ef_cert_from = file_search_by_fid(cert_from_fid, NULL, SPECIFY_EF);
    if (to != 0xFF) {
        file_t *ef_cert_to = file_search_by_fid(cert_to_fid, NULL, SPECIFY_EF);
        if (!ef_cert_to) {
            return SW_FILE_NOT_FOUND();
        }
        if (file_has_data(ef_cert_from)) {
            uint16_t cert_len = MIN(file_get_size(ef_cert_from), OPENPGP_MAX_OBJECT_SIZE);
            file_put_data(ef_cert_to, CONST_BYTE_ARRAY(file_get_data(ef_cert_from), cert_len));
        }
        else {
            flash_clear_file(ef_cert_to);
        }
    }
    if (ef_cert_from) {
        flash_clear_file(ef_cert_from);
    }

    byte_array_t metadata = meta_find(from);
    uint8_t *meta_src = metadata.data;
    size_t meta_len = metadata.len;
    if (to != 0xFF) {
        if (meta_len > 0 && meta_src != NULL) {
            uint8_t *meta_copy = (uint8_t *)calloc(1, (size_t)meta_len);
            if (!meta_copy) {
                return SW_MEMORY_FAILURE();
            }
            memcpy(meta_copy, meta_src, (size_t)meta_len);
            meta_add(to, CONST_BYTE_ARRAY(meta_copy, meta_len));
            free(meta_copy);
        }
        else {
            meta_delete(to);
        }
    }
    meta_delete(from);
    if (openpgp_key_container_is_marker(efs)) {
        if (openpgp_key_container_delete(from, true) != PICOKEYS_OK) {
            return SW_EXEC_ERROR();
        }
    }
    else {
        flash_clear_file(efs);
    }
    flash_commit();
    return SW_OK();
}

static int cmd_piv_change_pin(void) {
    uint8_t pin_ref = P2(apdu);
    if (P1(apdu) != 0x0 || (pin_ref != 0x80 && pin_ref != 0x81)) {
        return SW_REFERENCE_NOT_FOUND();
    }
    file_t *ef = file_search_by_fid(pin_ref == 0x80 ? EF_PIV_PIN : EF_PIV_PUK, NULL, SPECIFY_ANY);
    if (!ef) {
        return SW_MEMORY_FAILURE();
    }
    uint8_t *pin_data = file_get_data(ef), pin_len = apdu.nc - pin_data[0];
    uint16_t ret = check_pin(ef, apdu.data, pin_data[0]);
    if (ret != 0x9000) {
        return ret;
    }

    uint8_t dhash[34];
    dhash[0] = pin_len;
    dhash[1] = 0x1; // Format
    pin_derive_verifier(CONST_BYTE_ARRAY(apdu.data + pin_data[0], pin_len), dhash + 2);
    file_put_data(ef, CONST_BYTE_ARRAY(dhash, sizeof(dhash)));
    flash_commit();
    return SW_OK();
}

static int cmd_piv_reset_retry(void) {
    if (P1(apdu) != 0x0 || P2(apdu) != 0x80) {
        return SW_REFERENCE_NOT_FOUND();
    }
    file_t *ef = file_search_by_fid(EF_PIV_PUK, NULL, SPECIFY_ANY);
    if (!ef) {
        return SW_MEMORY_FAILURE();
    }
    uint8_t *puk_data = file_get_data(ef), pin_len = apdu.nc - puk_data[0];
    uint16_t ret = check_pin(ef, apdu.data, puk_data[0]);
    if (ret != 0x9000) {
        return ret;
    }
    uint8_t dhash[34];
    dhash[0] = pin_len;
    dhash[1] = 0x1; // Format
    pin_derive_verifier(CONST_BYTE_ARRAY(apdu.data + puk_data[0], pin_len), dhash + 2);
    ef = file_search_by_fid(EF_PIV_PIN, NULL, SPECIFY_ANY);
    file_put_data(ef, CONST_BYTE_ARRAY(dhash, sizeof(dhash)));
    pin_reset_retries(ef, true);
    flash_commit();
    return SW_OK();
}

static int cmd_set_retries(void) {
    if (!has_mgm || !has_pwpiv) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    file_t *ef = file_search_by_fid(EF_PW_RETRIES, NULL, SPECIFY_ANY);
    if (!ef) {
        return SW_MEMORY_FAILURE();
    }
    uint16_t retries_len = file_get_size(ef);
    if (retries_len < 6) {
        return SW_WRONG_DATA();
    }
    uint8_t *tmp = (uint8_t *)calloc(1, retries_len);
    if (!tmp) {
        return SW_MEMORY_FAILURE();
    }
    memcpy(tmp, file_get_data(ef), retries_len);
    tmp[4] = P1(apdu);
    tmp[5] = P2(apdu);
    file_put_data(ef, CONST_BYTE_ARRAY(tmp, retries_len));
    free(tmp);

    ef = file_search_by_fid(EF_PIV_PIN, NULL, SPECIFY_ANY);
    const uint8_t def_pin[8] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF };

    uint8_t dhash[34];
    dhash[0] = sizeof(def_pin);
    dhash[1] = 0x1; // Format
    pin_derive_verifier(CONST_BYTE_ARRAY(def_pin, sizeof(def_pin)), dhash + 2);
    file_put_data(ef, CONST_BYTE_ARRAY(dhash, sizeof(dhash)));
    pin_reset_retries(ef, true);

    ef = file_search_by_fid(EF_PIV_PUK, NULL, SPECIFY_ANY);
    const uint8_t def_puk[8] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
    dhash[0] = sizeof(def_puk);
    dhash[1] = 0x1; // Format
    pin_derive_verifier(CONST_BYTE_ARRAY(def_puk, sizeof(def_puk)), dhash + 2);
    file_put_data(ef, CONST_BYTE_ARRAY(dhash, sizeof(dhash)));
    pin_reset_retries(ef, true);

    flash_commit();
    return SW_OK();
}

static int cmd_reset(void) {
    if (P1(apdu) != 0x0 || P2(apdu) != 0x0) {
        return SW_INCORRECT_P1P2();
    }
    file_t *pw_status;
    if (!(pw_status = file_search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF)))
    {
        return SW_REFERENCE_NOT_FOUND();
    }
    uint8_t retPIN = *(file_get_data(pw_status) + 3 + (EF_PIV_PIN & 0xf)), retPUK = *(file_get_data(pw_status) + 3 + (EF_PIV_PUK & 0xf));
    if (retPIN != 0 || retPUK != 0) {
        return SW_INCORRECT_PARAMS();
    }
    file_initialize_flash(true);
    flash_commit();
    init_piv();
    return SW_OK();
}

static int cmd_attestation(void) {
    uint8_t key_ref = P1(apdu);
    if (P2(apdu) != 0x00) {
        return SW_INCORRECT_P1P2();
    }
    if (!IS_KEY(key_ref)) {
        return SW_REFERENCE_NOT_FOUND();
    }
    file_t *ef_key = NULL;
    byte_array_t metadata = meta_find(key_ref);
    uint8_t *meta = metadata.data;
    if (!(ef_key = file_search_by_fid(key_ref == 0x93 ? EF_PIV_KEY_RETIRED18 : key_ref, NULL, SPECIFY_EF)) || !file_has_data(ef_key)) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!meta) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (meta[3] != ORIGIN_GENERATED) {
        return SW_INCORRECT_PARAMS();
    }
    int r = 0;
    uint8_t abuf[2048];
    if (meta[0] == PIV_ALGO_RSA1024 || meta[0] == PIV_ALGO_RSA2048) {
        mbedtls_rsa_context ctx;
        mbedtls_rsa_init(&ctx);
        r = load_private_key_rsa(&ctx, ef_key, false);
        if (r != PICOKEYS_OK) {
            mbedtls_rsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        r = x509_create_cert(&ctx, meta[0], key_ref, true, abuf, sizeof(abuf));
        mbedtls_rsa_free(&ctx);
    }
    else if (meta[0] == PIV_ALGO_ECCP256 || meta[0] == PIV_ALGO_ECCP384) {
        mbedtls_ecdsa_context ctx;
        mbedtls_ecdsa_init(&ctx);
        r = load_private_key_ecdsa(&ctx, ef_key, false);
        if (r != PICOKEYS_OK) {
            mbedtls_ecdsa_free(&ctx);
            return SW_EXEC_ERROR();
        }
        r = x509_create_cert(&ctx, meta[0], key_ref, true, abuf, sizeof(abuf));
        mbedtls_ecdsa_free(&ctx);
    }
    else {
        return SW_WRONG_DATA();
    }
    if (r <= 0) {
        return SW_EXEC_ERROR();
    }
    memcpy(res_APDU, abuf + sizeof(abuf) - r, r);
    res_APDU_size = r;
    return SW_OK();
}

static int cmd_import_asym(void) {
    if (!has_mgm) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    uint8_t algo = P1(apdu), key_ref = P2(apdu);
    if (key_ref != EF_PIV_KEY_AUTHENTICATION && key_ref != EF_PIV_KEY_SIGNATURE && key_ref != EF_PIV_KEY_KEYMGM && key_ref != EF_PIV_KEY_CARDAUTH && !(key_ref >= EF_PIV_KEY_RETIRED1 && key_ref <= EF_PIV_KEY_RETIRED20)) {
        return SW_INCORRECT_P1P2();
    }
    tlv_ctx_t ctxi, aaa = {0}, aab = {0};
    tlv_ctx_init(BYTE_ARRAY(apdu.data, apdu.nc), &ctxi);
    tlv_find_tag(&ctxi, 0xAA, &aaa);
    tlv_find_tag(&ctxi, 0xAB, &aab);
    if (algo == PIV_ALGO_RSA1024 || algo == PIV_ALGO_RSA2048 || algo == PIV_ALGO_RSA3072 || algo == PIV_ALGO_RSA4096) {
        tlv_ctx_t a1 = { 0 }, a2 = { 0 };
        tlv_find_tag(&ctxi, 0x01, &a1);
        tlv_find_tag(&ctxi, 0x02, &a2);
        if (tlv_len(&a1) <= 0 || tlv_len(&a2) <= 0) {
            return SW_WRONG_DATA();
        }
        mbedtls_rsa_context rsa;
        mbedtls_rsa_init(&rsa);
        int r = mbedtls_mpi_read_binary(&rsa.P, a1.data, a1.len);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_WRONG_DATA();
        }
        r = mbedtls_mpi_read_binary(&rsa.Q, a2.data, a2.len);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_WRONG_DATA();
        }
        int exponent = 65537;
        mbedtls_mpi_lset(&rsa.E, exponent);
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
        r = store_keys(&rsa, ALGO_RSA, key_ref == 0x93 ? EF_PIV_KEY_RETIRED18 : key_ref, false);
        mbedtls_rsa_free(&rsa);
        if (r != 0) {
            return SW_EXEC_ERROR();
        }
    }
    else if (algo == PIV_ALGO_ECCP256 || algo == PIV_ALGO_ECCP384) {
        tlv_ctx_t a6 = {0};
        tlv_find_tag(&ctxi, 0x06, &a6);
        size_t scalar_size = algo == PIV_ALGO_ECCP256 ? 32 : 48;
        if (tlv_len(&a6) != scalar_size) {
            return SW_WRONG_DATA();
        }
        mbedtls_ecp_group_id gid = algo == PIV_ALGO_ECCP256 ? MBEDTLS_ECP_DP_SECP256R1 : MBEDTLS_ECP_DP_SECP384R1;
        mbedtls_ecdsa_context ecdsa;
        mbedtls_ecdsa_init(&ecdsa);
        int r = mbedtls_ecp_read_key(gid, &ecdsa, a6.data, a6.len);
        if (r != 0) {
            mbedtls_ecdsa_free(&ecdsa);
            return SW_EXEC_ERROR();
        }
        r = mbedtls_ecp_keypair_calc_public(&ecdsa, random_fill_iterator, NULL);
        if (r != 0) {
            mbedtls_ecdsa_free(&ecdsa);
            return SW_EXEC_ERROR();
        }
        r = mbedtls_ecp_check_pub_priv(&ecdsa, &ecdsa, random_fill_iterator, NULL);
        if (r != 0) {
            mbedtls_ecdsa_free(&ecdsa);
            return SW_EXEC_ERROR();
        }
        r = store_keys(&ecdsa, ALGO_ECDSA, key_ref == 0x93 ? EF_PIV_KEY_RETIRED18 : key_ref, false);
        mbedtls_ecdsa_free(&ecdsa);
        if (r != 0) {
            return SW_EXEC_ERROR();
        }
    }
    else {
        return SW_WRONG_DATA();
    }
    uint8_t def_pinpol = piv_default_pin_policy(key_ref);
    uint8_t meta[] = { algo,  tlv_len(&aaa) ? aaa.data[0] : def_pinpol, tlv_len(&aab) ? aab.data[0] : PIV_DEFAULT_TOUCH_POLICY, ORIGIN_IMPORTED };
    if (meta_add(key_ref, CONST_BYTE_ARRAY(meta, sizeof(meta))) != PICOKEYS_OK || !flash_commit_sync(PIV_FLASH_COMMIT_TIMEOUT_MS)) {
        return SW_MEMORY_FAILURE();
    }
    return SW_OK();
}

#define INS_VERIFY          0x20
#define INS_VERSION         0xFD
#define INS_SELECT          0xA4
#define INS_YK_SERIAL       0xF8
#define INS_VERIFY          0x20
#define INS_GET_DATA        0xCB
#define INS_GET_METADATA    0xF7
#define INS_AUTHENTICATE    0x87
#define INS_ASYM_KEYGEN     0x47
#define INS_PUT_DATA        0xDB
#define INS_SET_MGMKEY      0xFF
#define INS_MOVE_KEY        0xF6
#define INS_CHANGE_PIN      0x24
#define INS_RESET_RETRY     0x2C
#define INS_SET_RETRIES     0xFA
#define INS_RESET           0xFB
#define INS_ATTESTATION     0xF9
#define INS_IMPORT_ASYM     0xFE

static const cmd_t cmds[] = {
    { INS_VERSION, cmd_version },
    { INS_SELECT, cmd_piv_select },
    { INS_YK_SERIAL, cmd_get_serial },
    { INS_VERIFY, cmd_piv_verify },
    { INS_GET_DATA, cmd_piv_get_data },
    { INS_GET_METADATA, cmd_get_metadata },
    { INS_AUTHENTICATE, cmd_authenticate },
    { INS_ASYM_KEYGEN, cmd_asym_keygen },
    { INS_PUT_DATA, cmd_piv_put_data },
    { INS_SET_MGMKEY, cmd_set_mgmkey },
    { INS_MOVE_KEY, cmd_move_key },
    { INS_CHANGE_PIN, cmd_piv_change_pin },
    { INS_RESET_RETRY, cmd_piv_reset_retry },
    { INS_SET_RETRIES, cmd_set_retries },
    { INS_RESET, cmd_reset },
    { INS_ATTESTATION, cmd_attestation },
    { INS_IMPORT_ASYM, cmd_import_asym },
    { 0x00, 0x0 }
};

int piv_process_apdu(void) {
    sm_unwrap();
    if (apdu.nc == 1) {
        return SW_INCORRECT_PARAMS();
    }
    for (const cmd_t *cmd = cmds; cmd->ins != 0x00; cmd++) {
        if (cmd->ins == INS(apdu)) {
            int r = cmd->cmd_handler();
            sm_wrap();
            return r;
        }
    }
    return SW_INS_NOT_SUPPORTED();
}
