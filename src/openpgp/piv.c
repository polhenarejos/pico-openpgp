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
#include "compat/esp_compat.h"
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
#include "mbedtls/ecdh.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/constant_time.h"
#include "key_container.h"
#include "openpgp.h"
#include "usb.h"
#include "piv.h"

#ifndef ENABLE_EMULATION
bool piv_button_wait(void) {
    uint32_t event = EV_PRESS_BUTTON;
    queue_add_blocking(&card_to_usb_q, &event);
    do {
        queue_remove_blocking(&usb_to_card_q, &event);
    } while (event != EV_BUTTON_PRESSED && event != EV_BUTTON_TIMEOUT && event != EV_BUTTON_CANCELLED);
    return event != EV_BUTTON_PRESSED;
}
#endif

size_t piv_rsa_modulus_size(uint8_t algo) {
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

uint8_t piv_default_pin_policy(uint8_t key_ref) {
    if (key_ref == EF_PIV_KEY_SIGNATURE) {
        return PINPOLICY_ALWAYS;
    }
    if (key_ref == EF_PIV_KEY_CARDAUTH) {
        return PINPOLICY_NEVER;
    }
    return PINPOLICY_ONCE;
}

bool piv_resolve_policies(uint8_t key_ref, bool has_pin, const tlv_ctx_t *pin, bool has_touch, const tlv_ctx_t *touch, uint8_t *pin_policy, uint8_t *touch_policy) {
    *pin_policy = piv_default_pin_policy(key_ref);
    *touch_policy = PIV_DEFAULT_TOUCH_POLICY;
    if (has_pin) {
        if (tlv_len(pin) != 1 || (pin->data[0] != PINPOLICY_NEVER && pin->data[0] != PINPOLICY_ONCE && pin->data[0] != PINPOLICY_ALWAYS)) {
            return false;
        }
        *pin_policy = pin->data[0];
    }
    if (has_touch) {
        if (tlv_len(touch) != 1 || (touch->data[0] != TOUCHPOLICY_NEVER && touch->data[0] != TOUCHPOLICY_ALWAYS && touch->data[0] != TOUCHPOLICY_CACHED)) {
            return false;
        }
        *touch_policy = touch->data[0];
    }
    return true;
}

bool piv_reference_pair(const uint8_t **old_ref, const uint8_t **new_ref) {
    if (apdu.nc != 2u * PIV_PIN_WIRE_SIZE) {
        return false;
    }
    *old_ref = apdu.data;
    *new_ref = apdu.data + PIV_PIN_WIRE_SIZE;
    return true;
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

uint8_t mgm_challenge[16];
mgm_challenge_kind_t mgm_challenge_kind = MGM_CHALLENGE_NONE;
uint8_t mgm_challenge_algo = 0;
bool has_mgm = false;
const uint8_t piv_management_key_default[PIV_MANAGEMENT_KEY_DEFAULT_SIZE] = {
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

void clear_mgm_challenge(void) {
    memset(mgm_challenge, 0, sizeof(mgm_challenge));
    mgm_challenge_kind = MGM_CHALLENGE_NONE;
    mgm_challenge_algo = 0;
}

int get_serial(void) {
    uint32_t serial = (pico_serial.id[0] & 0x7F) << 24 | pico_serial.id[1] << 16 | pico_serial.id[2] << 8 | pico_serial.id[3];
    return serial;
}

int x509_create_cert(void *pk_ctx, uint8_t algo, uint8_t slot, bool attestation, uint8_t *buffer, size_t buffer_size) {
    mbedtls_x509write_cert ctx;
    mbedtls_x509write_crt_init(&ctx);
    mbedtls_x509write_crt_set_version(&ctx, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_validity(&ctx, "20240325000000", "20741231235959");
    uint8_t serial[20];
    random_fill_buffer(BYTE_ARRAY(serial, sizeof(serial)));
    serial[0] = (serial[0] & 0x7F) | 0x01;
    mbedtls_x509write_crt_set_serial_raw(&ctx, serial, sizeof(serial));
    mbedtls_pk_context skey, ikey;
    mbedtls_ecdsa_context actx; // attestation key
    mbedtls_pk_init(&skey);
    mbedtls_pk_init(&ikey);
    if (algo == PIV_ALGO_RSA1024 || algo == PIV_ALGO_RSA2048 || algo == PIV_ALGO_RSA3072) {
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
    uint32_t key_usage = MBEDTLS_X509_KU_DIGITAL_SIGNATURE;
    if (slot == EF_PIV_KEY_ATTESTATION) {
        key_usage |= MBEDTLS_X509_KU_KEY_CERT_SIGN;
    }
    mbedtls_x509write_crt_set_key_usage(&ctx, key_usage);
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
        const uint8_t defpin[8] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF };
        const uint8_t *random_dek = random_bytes_get(IV_SIZE + 32);

        uint8_t def[DEK_FILE_SIZE];
        def[0] = 0x3; // Format

        pin_derive_session(CONST_BYTE_ARRAY(defpin, sizeof(defpin)), session_pwpiv);
        encrypt_with_aad(session_pwpiv, CONST_BYTE_ARRAY(random_dek, DEK_SIZE), PIN_KDF_DEFAULT_VERSION, def + 1);
        mbedtls_platform_zeroize(session_pwpiv, sizeof(session_pwpiv));
        file_put_data(ef, CONST_BYTE_ARRAY(def, sizeof(def)));

        openpgp_key_container_store(EF_PIV_KEY_CARDMGM, piv_management_key_default, sizeof(piv_management_key_default), NULL, 0, true);
        uint8_t meta[] = { PIV_ALGO_AES192, MGM_PIN_POLICY, TOUCHPOLICY_NEVER };
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

void select_piv_aid(void) {
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

bool piv_validate_certificate_object(uint8_t *data, uint16_t data_len) {
    tlv_ctx_t object = { .data = data, .len = data_len };
    const_byte_array_t certificate = {0};
    uint8_t cert_info = 0;
    bool has_certificate = false;
    bool has_cert_info = false;
    uint8_t *p = NULL;
    tlv_item_t item;

    while (tlv_walk(&object, &p, &item)) {
        if (item.tag == 0x70) {
            if (has_certificate) {
                return false;
            }
            certificate = item.value;
            has_certificate = true;
        }
        else if (item.tag == 0x71) {
            if (has_cert_info || item.value.len != 1) {
                return false;
            }
            cert_info = item.value.data[0];
            has_cert_info = true;
        }
    }

    if (p && (size_t)(p - data) != data_len) {
        return false;
    }
    if (!has_certificate || certificate.len == 0) {
        return false;
    }
    if (has_cert_info && cert_info == 1) {
        return true;
    }
    if (has_cert_info && cert_info != 0) {
        return false;
    }
    if (certificate.data[0] != 0x30) {
        return false;
    }

    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    int r = mbedtls_x509_crt_parse(&crt, certificate.data, certificate.len);
    bool valid = r == 0 && crt.next == NULL && crt.raw.len == certificate.len;
    mbedtls_x509_crt_free(&crt);
    return valid;
}

int piv_format_certificate_object(const uint8_t *certificate, uint16_t certificate_len, uint8_t *object, uint16_t object_size) {
    uint16_t object_len = tlv_len_tag(0x70, certificate_len) + 3;
    if (!certificate || !object || object_len > object_size) {
        return PICOKEYS_ERR_NO_MEMORY;
    }

    uint8_t *p = object;
    *p++ = 0x70;
    p += tlv_format_len(certificate_len, p);
    memmove(p, certificate, certificate_len);
    p += certificate_len;
    *p++ = 0x71;
    *p++ = 1;
    *p++ = 0;
    return (int)(p - object);
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

int piv_parse_discovery(const file_t *ef) {
    (void) ef;
    memcpy(res_APDU, "\x7E\x12\x4F\x0B\xA0\x00\x00\x03\x08\x00\x00\x10\x00\x01\x00\x5F\x2F\x02\x40\x10", 20);
    res_APDU_size = 20;
    return res_APDU_size;
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
        r = mbedtls_aes_crypt_ecb(&ctx, encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT, input, output);
    }
    mbedtls_aes_free(&ctx);
    mbedtls_platform_zeroize(management_key, sizeof(management_key));
    return r;
}

int authenticate_mgm(uint8_t algo, file_t *ef_mgm, uint8_t chal_len, const tlv_ctx_t *a80, const tlv_ctx_t *a81, const tlv_ctx_t *a82) {
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
        bool valid_state = mgm_challenge_kind == MGM_CHALLENGE_MUTUAL && mgm_challenge_algo == algo && a80->len == chal_len && has_81 && a81->len == chal_len && !has_82;
        bool witness_matches = valid_state && mbedtls_ct_memcmp(a80->data, mgm_challenge, chal_len) == 0;
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
        bool valid_state = mgm_challenge_kind == MGM_CHALLENGE_SINGLE && mgm_challenge_algo == algo && a82->len == chal_len && !has_80 && !has_81;
        uint8_t response[sizeof(mgm_challenge)] = { 0 };
        int r = valid_state ? mgm_crypt(algo, ef_mgm, a82->data, response, false) : -1;
        bool response_matches = r == 0 && mbedtls_ct_memcmp(response, mgm_challenge, chal_len) == 0;
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

bool piv_first_auth_operation(const tlv_ctx_t *ctx, uint16_t *tag, tlv_ctx_t *value) {
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

int piv_ecdh(file_t *ef_key, uint8_t algo, const tlv_ctx_t *peer_key) {
    size_t expected_len = algo == PIV_ALGO_ECCP256 ? 65 : 97;
    uint8_t tls_peer_key[1 + 97];
    if (peer_key->len != expected_len || peer_key->data[0] != 0x04) {
        return SW_DATA_INVALID();
    }
    tls_peer_key[0] = peer_key->len;
    memcpy(tls_peer_key + 1, peer_key->data, peer_key->len);

    mbedtls_ecp_keypair key;
    mbedtls_ecdh_context ctx;
    uint8_t shared_secret[MBEDTLS_ECP_MAX_BYTES] = { 0 };
    size_t shared_len = 0;
    mbedtls_ecp_keypair_init(&key);
    mbedtls_ecdh_init(&ctx);

    int r = load_private_key_ecdsa(&key, ef_key, false);
    if (r == PICOKEYS_OK) {
        r = mbedtls_ecdh_setup(&ctx, key.grp.id);
    }
    if (r == 0) {
        r = mbedtls_ecdh_get_params(&ctx, &key, MBEDTLS_ECDH_OURS);
    }
    if (r != 0) {
        mbedtls_ecdh_free(&ctx);
        mbedtls_ecp_keypair_free(&key);
        mbedtls_platform_zeroize(shared_secret, sizeof(shared_secret));
        return SW_EXEC_ERROR();
    }

    r = mbedtls_ecdh_read_public(&ctx, tls_peer_key, peer_key->len + 1);
    if (r != 0) {
        mbedtls_ecdh_free(&ctx);
        mbedtls_ecp_keypair_free(&key);
        mbedtls_platform_zeroize(shared_secret, sizeof(shared_secret));
        return SW_DATA_INVALID();
    }
    r = mbedtls_ecdh_calc_secret(&ctx, &shared_len, shared_secret, sizeof(shared_secret), random_fill_iterator, NULL);
    mbedtls_ecdh_free(&ctx);
    mbedtls_ecp_keypair_free(&key);
    if (r != 0 || shared_len == 0 || shared_len > 127) {
        mbedtls_platform_zeroize(shared_secret, sizeof(shared_secret));
        return SW_EXEC_ERROR();
    }

    res_APDU[0] = 0x7C;
    res_APDU[1] = shared_len + 2;
    res_APDU[2] = 0x82;
    res_APDU[3] = shared_len;
    memcpy(res_APDU + 4, shared_secret, shared_len);
    res_APDU_size = shared_len + 4;
    mbedtls_platform_zeroize(shared_secret, sizeof(shared_secret));
    return SW_OK();
}

static const cmd_t standard_cmds[] = {
    { INS_SELECT, cmd_piv_select },
    { INS_VERIFY, cmd_piv_verify },
    { INS_GET_DATA, cmd_piv_get_data },
    { INS_AUTHENTICATE, cmd_authenticate },
    { INS_ASYM_KEYGEN, cmd_asym_keygen },
    { INS_PUT_DATA, cmd_piv_put_data },
    { INS_CHANGE_PIN, cmd_piv_change_pin },
    { INS_RESET_RETRY, cmd_piv_reset_retry },
    { 0x00, 0x0 }
};

static const cmd_t extension_cmds[] = {
    { INS_VERSION, cmd_version },
    { INS_YK_SERIAL, cmd_get_serial },
    { INS_GET_METADATA, cmd_get_metadata },
    { INS_SET_MGMKEY, cmd_set_mgmkey },
    { INS_MOVE_KEY, cmd_move_key },
    { INS_SET_RETRIES, cmd_set_retries },
    { INS_RESET, cmd_reset },
    { INS_ATTESTATION, cmd_attestation },
    { INS_IMPORT_ASYM, cmd_import_asym },
    { INS_VAULT, cmd_piv_vault },
    { 0x00, 0x0 }
};

int piv_process_apdu(void) {
    int r = sm_unwrap();
    if (r != PICOKEYS_OK) {
        res_APDU_size = 0;
        return SW_SECURE_MESSAGE_EXEC_ERROR();
    }
    if (INS(apdu) != INS_AUTHENTICATE && INS(apdu) != INS_SELECT && !(INS(apdu) == INS_GET_METADATA && P2(apdu) == EF_PIV_KEY_CARDMGM)) {
        clear_mgm_challenge();
    }
    if (apdu.nc == 1 && (INS(apdu) == INS_VERSION || INS(apdu) == INS_YK_SERIAL || INS(apdu) == INS_GET_METADATA || INS(apdu) == INS_VERIFY || INS(apdu) == INS_AUTHENTICATE || INS(apdu) == INS_ASYM_KEYGEN || INS(apdu) == INS_PUT_DATA || INS(apdu) == INS_MOVE_KEY)) {
        r = SW_INCORRECT_PARAMS();
        goto wrap_response;
    }
    for (const cmd_t *cmd = standard_cmds; cmd->ins != 0x00; cmd++) {
        if (cmd->ins == INS(apdu)) {
            r = cmd->cmd_handler();
            goto wrap_response;
        }
    }

    for (const cmd_t *cmd = extension_cmds; cmd->ins != 0x00; cmd++) {
        if (cmd->ins == INS(apdu)) {
            r = cmd->cmd_handler();
            goto wrap_response;
        }
    }
    r = SW_INS_NOT_SUPPORTED();

wrap_response:
    if (sm_wrap() != PICOKEYS_OK) {
        res_APDU_size = 0;
        return SW_SECURE_MESSAGE_EXEC_ERROR();
    }
    return r;
}
