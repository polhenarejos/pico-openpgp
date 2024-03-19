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

#include "common.h"
#include "files.h"
#include "apdu.h"
#include "pico_keys.h"
#include "random.h"
#include "eac.h"
#include "crypto_utils.h"
#include "version.h"
#ifndef ENABLE_EMULATION
#include "pico/unique_id.h"
#endif
#include "asn1.h"
#include "mbedtls/aes.h"
#include "openpgp.h"

#define PIV_ALGO_AES128 0x08
#define PIV_ALGO_AES192 0x0a
#define PIV_ALGO_AES256 0x0c
#define PIV_ALGO_RSA1024 0x06
#define PIV_ALGO_RSA2048 0x07
#define PIV_ALGO_ECCP256 0x11
#define PIV_ALGO_ECCP384 0x14
#define PIV_ALGO_X25519 0xE1

uint8_t piv_aid[] = {
    5,
    0xA0, 0x00, 0x00, 0x03, 0x8,
};
uint8_t yk_aid[] = {
    8,
    0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x1, 0x1
};
uint8_t mgmt_aid[] = {
    8,
    0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17
};

bool has_pwpiv = false;
uint8_t session_pwpiv[32];

int piv_process_apdu();
/*
static int piv_generate_key(uint8_t key_ref, uint8_t algo) {
    int r = CCID_OK;
    if (algo == PIV_ALGO_AES128 || algo == PIV_ALGO_AES192 || algo == PIV_ALGO_AES256) {
        size_t ksize = 0;
        if (algo == PIV_ALGO_AES128) {
            ksize = 16;
        }
        else if (algo == PIV_ALGO_AES192) {
            ksize = 24;
        }
        else if (algo == PIV_ALGO_AES256) {
            ksize = 32;
        }
        const uint8_t *key = random_bytes_get(ksize);
        r = store_keys((uint8_t *)key, ALGO_AES, key_ref);
    }
    else if (algo == PIV_ALGO_RSA1024 || algo == PIV_ALGO_RSA2048) {
        mbedtls_rsa_context rsa;
        mbedtls_rsa_init(&rsa);
        int exponent = 65537, nlen = 0;
        if (algo == PIV_ALGO_RSA1024) {
            nlen = 1024;
        }
        else if (algo == PIV_ALGO_RSA2048) {
            nlen = 2048;
        }
        r = mbedtls_rsa_gen_key(&rsa, random_gen, NULL, nlen, exponent);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return CCID_EXEC_ERROR;
        }
        r = store_keys(&rsa, ALGO_RSA, key_ref);
        mbedtls_rsa_free(&rsa);
    }
    else if (algo == PIV_ALGO_ECCP256 || algo == PIV_ALGO_ECCP384 || algo == PIV_ALGO_X25519) {
        mbedtls_ecdsa_context ecdsa;
        mbedtls_ecdsa_init(&ecdsa);
        mbedtls_ecp_group_id gid = MBEDTLS_ECP_DP_NONE;
        if (algo == PIV_ALGO_ECCP256) {
            gid = MBEDTLS_ECP_DP_SECP256R1;
        }
        else if (algo == PIV_ALGO_ECCP384) {
            gid = MBEDTLS_ECP_DP_SECP384R1;
        }
        else if (algo == PIV_ALGO_X25519) {
            gid = MBEDTLS_ECP_DP_CURVE25519;
        }
        r = mbedtls_ecdsa_genkey(&ecdsa, gid, random_gen, NULL);
        if (r != 0) {
            mbedtls_ecdsa_free(&ecdsa);
            return CCID_EXEC_ERROR;
        }
        r = store_keys(&ecdsa, ALGO_ECDSA, key_ref);
        mbedtls_ecdsa_free(&ecdsa);
    }
    if (r != CCID_OK) {
        return CCID_ERR_NO_MEMORY;
    }
    uint8_t meta[] = { algo, 0, 0, 1 };
    if ((r = meta_add(key_ref, meta, sizeof(meta))) != CCID_OK) {
        return r;
    }
    low_flash_available();
    return r;
}
*/
static void scan_files() {
    scan_flash();
    file_t *ef = search_by_fid(EF_PIV_KEY_CARDMGM, NULL, SPECIFY_EF);
    if ((ef = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_ANY))) {
        if (file_get_size(ef) == 0) {
            printf("PW status is empty. Initializing to default\r\n");
            const uint8_t def[] = { 0x1, 127, 127, 127, 3, 3, 3, 3, 3 };
            flash_write_data_to_file(ef, def, sizeof(def));
        }
        else if (file_get_size(ef) == 7) {
            printf("PW status is older. Initializing to default\r\n");
            uint8_t def[9] = { 0 };
            memcpy(def, file_get_data(ef), 7);
            def[7] = def[8] = 3; // PIV retries
            flash_write_data_to_file(ef, def, sizeof(def));
        }
    }
    bool reset_dek = false;
    if ((ef = search_by_fid(EF_DEK, NULL, SPECIFY_ANY))) {
        if (file_get_size(ef) == 0 || file_get_size(ef) == IV_SIZE+32*3) {
            printf("DEK is empty or older\r\n");
            const uint8_t defpin[6] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36 };
            const uint8_t *dek = random_bytes_get(IV_SIZE + 32);
            uint8_t def[IV_SIZE + 32 + 32 + 32 + 32];
            if (file_get_size(ef) > 0) {
                memcpy(def, file_get_data(ef), file_get_size(ef));
            }
            else {
                memcpy(def, dek, IV_SIZE);
            }
            memcpy(def + IV_SIZE + 32*3, dek + IV_SIZE, 32);
            hash_multi(defpin, sizeof(defpin), session_pwpiv);
            aes_encrypt_cfb_256(session_pwpiv, def, def + IV_SIZE + 32*3, 32);
            flash_write_data_to_file(ef, def, sizeof(def));

            has_pwpiv = true;
            uint8_t *key = (uint8_t *)"\x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x05\x06\x07\x08";
            file_t *ef = search_by_fid(EF_PIV_KEY_CARDMGM, NULL, SPECIFY_ANY);
            flash_write_data_to_file(ef, key, 24);
            uint8_t meta[] = { PIV_ALGO_AES192, 0, 0, 1 };
            meta_add(EF_PIV_KEY_CARDMGM, meta, sizeof(meta));
            has_pwpiv = false;
            memset(session_pwpiv, 0, sizeof(session_pwpiv));

            reset_dek = true;
        }
    }
    if ((ef = search_by_fid(EF_PIV_PIN, NULL, SPECIFY_ANY))) {
        if (!ef->data || reset_dek) {
            printf("PIV PIN is empty. Initializing with default password\r\n");
            const uint8_t def[8] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF };
            uint8_t dhash[33];
            dhash[0] = sizeof(def);
            double_hash_pin(def, sizeof(def), dhash + 1);
            flash_write_data_to_file(ef, dhash, sizeof(dhash));
        }
    }
    if ((ef = search_by_fid(EF_PIV_PUK, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            printf("PIV PUK is empty. Initializing with default password\r\n");
            const uint8_t def[8] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
            uint8_t dhash[33];
            dhash[0] = sizeof(def);
            double_hash_pin(def, sizeof(def), dhash + 1);
            flash_write_data_to_file(ef, dhash, sizeof(dhash));
        }
    }
    low_flash_available();
}

void init_piv() {
    scan_files();
    //cmd_select();
}

int piv_unload() {
    return CCID_OK;
}

void select_piv_aid() {
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

int piv_select_aid(app_t *a) {
    a->process_apdu = piv_process_apdu;
    a->unload = piv_unload;
    init_piv();
    select_piv_aid();
    return CCID_OK;
}

void __attribute__((constructor)) piv_ctor() {
    register_app(piv_select_aid, piv_aid);
    register_app(piv_select_aid, yk_aid);
    register_app(piv_select_aid, mgmt_aid);
}

static int cmd_version() {
    res_APDU[res_APDU_size++] = PIV_VERSION_MAJOR;
    res_APDU[res_APDU_size++] = PIV_VERSION_MINOR;
    res_APDU[res_APDU_size++] = 0x0;
    return SW_OK();
}

static int cmd_select() {
    if (P2(apdu) != 0x1) {
        return SW_WRONG_P1P2();
    }
    if (memcmp(apdu.data, piv_aid, 5) == 0) {
        select_piv_aid();
    }
    return SW_OK();
}

int piv_parse_discovery(const file_t *ef) {
    memcpy(res_APDU, "\x7E\x12\x4F\x0B\xA0\x00\x00\x03\x08\x00\x00\x10\x00\x01\x00\x5F\x2F\x02\x40\x10", 20);
    res_APDU_size = 20;
    return res_APDU_size;
}

static int cmd_get_serial() {
#ifndef ENABLE_EMULATION
        pico_unique_board_id_t unique_id;
        pico_get_unique_board_id(&unique_id);
        memcpy(res_APDU, unique_id.id, 4);
#else
        memset(res_APDU, 0, 4);
#endif
    res_APDU_size = 4;
    return SW_OK();
}

extern int check_pin(const file_t *pin, const uint8_t *data, size_t len);
static int cmd_verify() {
    uint8_t key_ref = P2(apdu);
    if (P1(apdu) != 0x00 && P1(apdu) != 0xFF) {
        return SW_INCORRECT_P1P2();
    }
    if (key_ref != 0x80) {
        return SW_REFERENCE_NOT_FOUND();
    }
    file_t *pw, *pw_status;
    uint16_t fid = EF_PIV_PIN;
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
        uint16_t ret = check_pin(pw, apdu.data, apdu.nc);
        if (ret == 0x9000) {
            has_pwpiv = true;
            hash_multi(apdu.data, apdu.nc, session_pwpiv);
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

static int cmd_get_data() {
    if (P1(apdu) != 0x3F || P2(apdu) != 0xFF) {
        return SW_INCORRECT_P1P2();
    }
    if (apdu.data[0] != 0x5C || (apdu.data[1] & 0x80) || apdu.data[1] >= 4 || apdu.data[1] == 0) {
        return SW_WRONG_DATA();
    }
    uint32_t fid = apdu.data[2];
    for (uint8_t lt = 1; lt < apdu.data[1]; lt++) {
        fid <<= 8;
        fid |= apdu.data[2 + lt];
    }
    if ((fid & 0xFFFF00) != 0x5FC100 && fid != EF_PIV_BITGT && fid != EF_PIV_DISCOVERY) {
        return SW_REFERENCE_NOT_FOUND();
    }
    file_t *ef = NULL;
    if ((ef = search_by_fid((uint16_t)(fid & 0xFFFF), NULL, SPECIFY_EF))) {
        uint16_t data_len = 0;
        res_APDU_size = 2; // Minimum: TAG+LEN
        if ((ef->type & FILE_DATA_FUNC) == FILE_DATA_FUNC) {
            data_len = ((int (*)(const file_t *))(ef->data))((const file_t *) ef);
        }
        else {
            if (ef->data) {
                data_len = file_get_size(ef);
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
        res_APDU_size = 1 + format_tlv_len(data_len, res_APDU + 1) + data_len;
    }
    else {
        return SW_FILE_NOT_FOUND();
    }
    return SW_OK();
}

static int cmd_get_metadata() {
    if (P1(apdu) != 0x00) {
        return SW_INCORRECT_P1P2();
    }
    uint8_t *meta = NULL;
    int meta_len = 0;
    if ((meta_len = meta_find(P2(apdu), &meta)) <= 0) {
        return SW_REFERENCE_NOT_FOUND();
    }
    res_APDU[res_APDU_size++] = 0x1;
    res_APDU[res_APDU_size++] = 1;
    res_APDU[res_APDU_size++] = meta[0];
    res_APDU[res_APDU_size++] = 0x2;
    res_APDU[res_APDU_size++] = 2;
    res_APDU[res_APDU_size++] = meta[1];
    res_APDU[res_APDU_size++] = meta[2];
    res_APDU[res_APDU_size++] = 0x3;
    res_APDU[res_APDU_size++] = 1;
    res_APDU[res_APDU_size++] = meta[3];
    return SW_OK();
}
uint8_t challenge[16];
bool has_challenge = false;
bool has_mgm = false;
static int cmd_authenticate() {
    uint8_t algo = P1(apdu), key_ref = P2(apdu);
    if (apdu.nc == 0) {
        return SW_WRONG_LENGTH();
    }
    if (apdu.data[0] != 0x7C) {
        return SW_WRONG_DATA();
    }
    if (key_ref == EF_PIV_KEY_CARDMGM) {
        if (algo != PIV_ALGO_AES128 && algo != PIV_ALGO_AES192 && algo != PIV_ALGO_AES256) {
            return SW_INCORRECT_P1P2();
        }
        file_t *ef_mgm = search_by_fid(key_ref, NULL, SPECIFY_EF);
        if (!file_has_data(ef_mgm)) {
            return SW_MEMORY_FAILURE();
        }
        uint16_t mgm_len = file_get_size(ef_mgm);
        if ((algo == PIV_ALGO_AES128 && mgm_len != 16) || (algo == PIV_ALGO_AES192 && mgm_len != 24) || (algo == PIV_ALGO_AES256 && mgm_len != 32)) {
            return SW_INCORRECT_P1P2();
        }
    }
    asn1_ctx_t ctxi, a7c = { 0 };
    asn1_ctx_init(apdu.data, (uint16_t)apdu.nc, &ctxi);
    if (!asn1_find_tag(&ctxi, 0x7C, &a7c) || asn1_len(&ctxi) == 0) {
        return SW_WRONG_DATA();
    }
    asn1_ctx_t a80 = { 0 }, a81 = { 0 }, a82 = { 0 };
    asn1_find_tag(&a7c, 0x80, &a80);
    asn1_find_tag(&a7c, 0x81, &a81);
    asn1_find_tag(&a7c, 0x82, &a82);
    if (a80.data) {
        if (a80.len == 0) {
            memcpy(challenge, random_bytes_get(sizeof(challenge)), sizeof(challenge));
            if (algo == PIV_ALGO_AES128 || algo == PIV_ALGO_AES192 || algo == PIV_ALGO_AES256) {
                if (key_ref != EF_PIV_KEY_CARDMGM) {
                    return SW_INCORRECT_P1P2();
                }
                file_t *ef_mgm = search_by_fid(key_ref, NULL, SPECIFY_EF);
                if (!file_has_data(ef_mgm)) {
                    return SW_MEMORY_FAILURE();
                }
                uint16_t mgm_len = file_get_size(ef_mgm);
                mbedtls_aes_context ctx;
                mbedtls_aes_init(&ctx);
                int r = mbedtls_aes_setkey_enc(&ctx, file_get_data(ef_mgm), mgm_len * 8);
                if (r != 0) {
                    mbedtls_aes_free(&ctx);
                    return SW_EXEC_ERROR();
                }
                res_APDU[res_APDU_size++] = 0x7C;
                res_APDU[res_APDU_size++] = 10;
                res_APDU[res_APDU_size++] = 0x80;
                res_APDU[res_APDU_size++] = 16;
                r = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, challenge, res_APDU + res_APDU_size);
                res_APDU_size += 16;
                mbedtls_aes_free(&ctx);
                if (r != 0) {
                    return SW_EXEC_ERROR();
                }
                has_challenge = true;
            }
        }
        else {
            if (!has_challenge) {
                return SW_COMMAND_NOT_ALLOWED();
            }
            if (sizeof(challenge) != a80.len || memcmp(a80.data, challenge, a80.len) != 0) {
                return SW_DATA_INVALID();
            }
            if (!asn1_len(&a81)) {
                return SW_INCORRECT_PARAMS();
            }
            if (key_ref != EF_PIV_KEY_CARDMGM) {
                return SW_INCORRECT_P1P2();
            }
            has_mgm = true;
        }
    }
    if (a81.data) {
        if (!a81.len) {
            memcpy(challenge, random_bytes_get(sizeof(challenge)), sizeof(challenge));
            res_APDU[res_APDU_size++] = 0x7C;
            res_APDU[res_APDU_size++] = 10;
            res_APDU[res_APDU_size++] = 0x81;
            res_APDU[res_APDU_size++] = sizeof(challenge);
            memcpy(res_APDU + res_APDU_size, challenge, sizeof(challenge));
            res_APDU_size += sizeof(challenge);
            has_challenge = true;
        }
        else {
            file_t *ef_key = search_by_fid(key_ref, NULL, SPECIFY_EF);
            if (!file_has_data(ef_key)) {
                return SW_MEMORY_FAILURE();
            }
            if (algo == PIV_ALGO_RSA1024 || algo == PIV_ALGO_RSA2048) {
                mbedtls_rsa_context ctx;
                mbedtls_rsa_init(&ctx);
                int r = load_private_key_rsa(&ctx, ef_key, false);
                if (r != CCID_OK) {
                    mbedtls_rsa_free(&ctx);
                    return SW_EXEC_ERROR();
                }
                size_t olen = 0;
                res_APDU[res_APDU_size++] = 0x7C;
                res_APDU[res_APDU_size++] = 10;
                res_APDU[res_APDU_size++] = 0x82;
                res_APDU[res_APDU_size++] = 0x82;
                r = rsa_sign(&ctx, a81.data, a81.len, res_APDU + res_APDU_size + 2, &olen);
                mbedtls_rsa_free(&ctx);
                res_APDU[res_APDU_size++] = olen >> 8;
                res_APDU[res_APDU_size++] = olen & 0xFF;
                res_APDU_size += olen;
                if (r != 0) {
                    return SW_EXEC_ERROR();
                }
            }
            else if (algo == PIV_ALGO_ECCP256 || algo == PIV_ALGO_ECCP384) {
                mbedtls_ecdsa_context ctx;
                mbedtls_ecdsa_init(&ctx);
                int r = load_private_key_ecdsa(&ctx, ef_key, false);
                if (r != CCID_OK) {
                    mbedtls_ecdsa_free(&ctx);
                    return SW_EXEC_ERROR();
                }
                size_t olen = 0;
                res_APDU[res_APDU_size++] = 0x7C;
                res_APDU[res_APDU_size++] = 10;
                res_APDU[res_APDU_size++] = 0x82;
                res_APDU[res_APDU_size++] = 0x82;
                r = ecdsa_sign(&ctx, a81.data, a81.len, res_APDU + res_APDU_size + 2, &olen);
                mbedtls_ecdsa_free(&ctx);
                res_APDU[res_APDU_size++] = olen >> 8;
                res_APDU[res_APDU_size++] = olen & 0xFF;
                res_APDU_size += olen;
                if (r != 0) {
                    return SW_EXEC_ERROR();
                }
            }
            else if (algo == PIV_ALGO_AES128 || algo == PIV_ALGO_AES192 || algo == PIV_ALGO_AES256) {
                uint16_t key_len = file_get_size(ef_key);
                if (a81.len % 16 != 0) {
                    return SW_DATA_INVALID();
                }
                mbedtls_aes_context ctx;
                mbedtls_aes_init(&ctx);
                int r = mbedtls_aes_setkey_enc(&ctx, file_get_data(ef_key), key_len * 8);
                if (r != 0) {
                    mbedtls_aes_free(&ctx);
                    return SW_EXEC_ERROR();
                }
                res_APDU[res_APDU_size++] = 0x7C;
                res_APDU[res_APDU_size++] = 10;
                res_APDU[res_APDU_size++] = 0x82;
                res_APDU[res_APDU_size++] = a81.len;
                r = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, a81.data, res_APDU + res_APDU_size);
                mbedtls_aes_free(&ctx);
                res_APDU_size += a81.len;
                if (r != 0) {
                    return SW_EXEC_ERROR();
                }
            }
        }
    }
    if (a82.data) {
        if (!a82.len) {
            // Should be handled by a81 or a80
        }
        else {
            if (key_ref != EF_PIV_KEY_CARDMGM) {
                return SW_INCORRECT_P1P2();
            }
            if (!has_challenge) {
                return SW_COMMAND_NOT_ALLOWED();
            }
            if (sizeof(challenge) != a82.len) {
                return SW_DATA_INVALID();
            }
            file_t *ef_key = search_by_fid(key_ref, NULL, SPECIFY_EF);
            if (!file_has_data(ef_key)) {
                return SW_MEMORY_FAILURE();
            }
            uint16_t key_len = file_get_size(ef_key);
            mbedtls_aes_context ctx;
            mbedtls_aes_init(&ctx);
            int r = mbedtls_aes_setkey_dec(&ctx, file_get_data(ef_key), key_len * 8);
            if (r != 0) {
                mbedtls_aes_free(&ctx);
                return SW_EXEC_ERROR();
            }
            r = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, a82.data, res_APDU);
            mbedtls_aes_free(&ctx);
            if (r != 0) {
                return SW_EXEC_ERROR();
            }
            if (memcmp(res_APDU, challenge, sizeof(challenge)) != 0) {
                return SW_DATA_INVALID();
            }
        }
    }
    return SW_OK();
}

static int cmd_asym_keygen() {
    uint8_t key_ref = P2(apdu);
    if (apdu.nc == 0) {
        return SW_WRONG_LENGTH();
    }
    if (apdu.data[0] != 0xAC) {
        return SW_WRONG_DATA();
    }
    if (P1(apdu) != 0x0) {
        return SW_INCORRECT_P1P2();
    }
    if (!has_mgm) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (key_ref == 0x9E) {
        key_ref = EF_PIV_KEY_RETIRED18;
    }
    else if (key_ref == 0xF9) {
        key_ref = EF_PIV_KEY_ATTESTATION;
    }
    asn1_ctx_t ctxi, aac = {0};
    asn1_ctx_init(apdu.data, (uint16_t)apdu.nc, &ctxi);
    if (!asn1_find_tag(&ctxi, 0xAC, &aac) || asn1_len(&aac) == 0) {
        return SW_WRONG_DATA();
    }
    asn1_ctx_t a80 = {0}, a81 = {0};
    asn1_find_tag(&aac, 0x80, &a80);
    asn1_find_tag(&aac, 0x81, &a81);
    if (asn1_len(&a80) == 0) {
        return SW_WRONG_DATA();
    }
    if (a80.data[0] == PIV_ALGO_RSA1024 || a80.data[0] == PIV_ALGO_RSA2048) {
        printf("KEYPAIR RSA\r\n");
        mbedtls_rsa_context rsa;
        mbedtls_rsa_init(&rsa);
        uint8_t index = 0;
        int exponent = 65537, nlen = (a80.data[0] == PIV_ALGO_RSA1024 ? 1024 : 2048);
        if (asn1_len(&a81)) {
            exponent = (int)asn1_get_uint(&a81);
        }
        int r = mbedtls_rsa_gen_key(&rsa, random_gen, &index, nlen, exponent);
        if (r != 0) {
            mbedtls_rsa_free(&rsa);
            return SW_EXEC_ERROR();
        }
        r = store_keys(&rsa, ALGO_RSA, key_ref, false);
        make_rsa_response(&rsa);
        mbedtls_rsa_free(&rsa);
        if (r != CCID_OK) {
            return SW_EXEC_ERROR();
        }
    }
    else if (a80.data[0] == PIV_ALGO_ECCP256 || a80.data[0] == PIV_ALGO_ECCP384) {
        printf("KEYPAIR ECDSA\r\n");
        mbedtls_ecp_group_id gid = a80.data[0] == PIV_ALGO_ECCP256 ? MBEDTLS_ECP_DP_SECP256R1 : MBEDTLS_ECP_DP_SECP384R1;
        mbedtls_ecdsa_context ecdsa;
        mbedtls_ecdsa_init(&ecdsa);
        uint8_t index = 0;
        int r = mbedtls_ecdsa_genkey(&ecdsa, gid, random_gen, &index);
        if (r != 0) {
            mbedtls_ecdsa_free(&ecdsa);
            return SW_EXEC_ERROR();
        }
        r = store_keys(&ecdsa, ALGO_ECDSA, key_ref, false);
        make_ecdsa_response(&ecdsa);
        mbedtls_ecdsa_free(&ecdsa);
        if (r != CCID_OK) {
            return SW_EXEC_ERROR();
        }
    }
    else if (a80.data[0] == PIV_ALGO_X25519) {
    }
    return SW_OK();
}

int cmd_put_data() {
    if (P1(apdu) != 0x3F || P2(apdu) != 0xFF) {
        return SW_INCORRECT_P1P2();
    }
    asn1_ctx_t ctxi, a5c = {0}, a53 = {0};
    asn1_ctx_init(apdu.data, (uint16_t)apdu.nc, &ctxi);
    if (apdu.data[0] != 0x7E && apdu.data[0] != 0x7F && (!asn1_find_tag(&ctxi, 0x5C, &a5c) || !asn1_find_tag(&ctxi, 0x53, &a53))) {
        return SW_WRONG_DATA();
    }
    if (a5c.data && a53.data) {
        if (a5c.len != 3 || a5c.data[0] != 0x5F || a5c.data[1] != 0xC1) {
            return SW_WRONG_DATA();
        }
        uint16_t fid = (a5c.data[1] << 8 | a5c.data[2]);
        file_t *ef = search_by_fid(fid, NULL, SPECIFY_EF);
        if (!ef) {
            return SW_MEMORY_FAILURE();
        }
        if (a53.len > 0) {
            flash_write_data_to_file(ef, a53.data, a53.len);
        }
        else {
            flash_clear_file(ef);
        }
        low_flash_available();
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

static const cmd_t cmds[] = {
    { INS_VERSION, cmd_version },
    { INS_SELECT, cmd_select },
    { INS_YK_SERIAL, cmd_get_serial },
    { INS_VERIFY, cmd_verify },
    { INS_GET_DATA, cmd_get_data },
    { INS_GET_METADATA, cmd_get_metadata },
    { INS_AUTHENTICATE, cmd_authenticate },
    { INS_ASYM_KEYGEN, cmd_asym_keygen },
    { INS_PUT_DATA, cmd_put_data },
    { 0x00, 0x0 }
};

int piv_process_apdu() {
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
