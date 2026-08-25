/*
 * This file is part of the Pico OpenPGP distribution (https://github.com/polhenarejos/pico-openpgp).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "vault.h"

#include <string.h>

#include "files.h"
#include "key_container.h"
#include "mbedtls/constant_time.h"
#include "object_provider.h"
#include "openpgp.h"
#include "random.h"
#include "serial.h"

#define OPENPGP_VAULT_SUBCOMMAND_STATUS 0x01
#define OPENPGP_VAULT_SUBCOMMAND_START_ENROLLMENT 0x02
#define OPENPGP_VAULT_SUBCOMMAND_FINISH_ENROLLMENT 0x03
#define OPENPGP_VAULT_SUBCOMMAND_EXPORT 0x04
#define OPENPGP_VAULT_SUBCOMMAND_IMPORT 0x05
#define OPENPGP_VAULT_SUBCOMMAND_UNENROLL 0x06

#define OPENPGP_VAULT_BLOB_HEADER_SIZE 86u
#define OPENPGP_VAULT_BLOB_SERIAL_MAX 16u
#define OPENPGP_VAULT_BLOB_SERIAL_LENGTH_OFFSET 68u
#define OPENPGP_VAULT_BLOB_SERIAL_OFFSET 69u
#define OPENPGP_VAULT_BLOB_ALGORITHM_OFFSET 85u
#define OPENPGP_VAULT_PLAIN_MAX OPENPGP_MAX_RESPONSE_SIZE
#define OPENPGP_VAULT_BLOB_MAX OPENPGP_MAX_RESPONSE_SIZE

#define OPENPGP_VAULT_HANDLE_SIGNATURE 0x01
#define OPENPGP_VAULT_HANDLE_DECRYPTION 0x02
#define OPENPGP_VAULT_HANDLE_AUTHENTICATION 0x03
#define OPENPGP_VAULT_HANDLE_AES 0x04

static const uint8_t openpgp_vault_blob_magic[] = { 'P', 'K', 'V', 1 };

typedef struct openpgp_vault_plaintext {
    uint8_t app;
    uint16_t fid;
    uint8_t private_data[OPENPGP_MAX_OBJECT_SIZE];
    size_t private_len;
    uint8_t public_data[OPENPGP_MAX_OBJECT_SIZE];
    size_t public_len;
} openpgp_vault_plaintext_t;

static file_t *openpgp_vault_file(void) {
    return file_search_by_fid(EF_VAULT_KEY, NULL, SPECIFY_EF);
}

static int openpgp_vault_sdk_init(void) {
    file_object_container_crypto_t primary = {
        .auth = openpgp_vault_object_manifest_authenticator(),
        .protector = openpgp_vault_object_record_protector()
    };
    if (!primary.auth || !primary.protector) {
        return PICOKEYS_EXEC_ERROR;
    }
    return picokeys_vault_init(&primary, NULL, openpgp_vault_file(), NULL);
}

static bool openpgp_vault_app_valid(openpgp_vault_app_t app) {
    return app < OPENPGP_VAULT_APP_COUNT && app != OPENPGP_VAULT_APP_FIDO;
}

static bool openpgp_vault_app_authenticated(openpgp_vault_app_t app) {
    return app == OPENPGP_VAULT_APP_OPENPGP ? has_pw3 : app == OPENPGP_VAULT_APP_PIV ? has_pwpiv : false;
}

static int openpgp_vault_load_root(openpgp_vault_app_t app, uint8_t root[OPENPGP_VAULT_KEY_SIZE]) {
    if (!root || !openpgp_vault_app_valid(app) || !openpgp_vault_app_authenticated(app)) {
        return PICOKEYS_NO_LOGIN;
    }
    int ret = load_dek();
    if (ret == PICOKEYS_OK) {
        memcpy(root, dek + IV_SIZE, OPENPGP_VAULT_KEY_SIZE);
    }
    release_dek();
    return ret;
}

bool openpgp_vault_is_enrolled(void) {
    return openpgp_vault_wrapper_available(OPENPGP_VAULT_APP_OPENPGP) || openpgp_vault_wrapper_available(OPENPGP_VAULT_APP_PIV);
}

bool openpgp_vault_wrapper_available(openpgp_vault_app_t app) {
    if (!openpgp_vault_app_valid(app) || openpgp_vault_sdk_init() != PICOKEYS_OK) {
        return false;
    }
    return openpgp_vault_app_authenticated(app) && picokeys_vault_wrap_available(app);
}

int openpgp_vault_load_kvault(openpgp_vault_app_t app, uint8_t kvault[OPENPGP_VAULT_KEY_SIZE]) {
    if (!kvault || !openpgp_vault_app_valid(app)) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (openpgp_vault_sdk_init() != PICOKEYS_OK) {
        return PICOKEYS_EXEC_ERROR;
    }
    uint8_t root[OPENPGP_VAULT_KEY_SIZE] = { 0 };
    int ret = openpgp_vault_load_root(app, root);
    if (ret == PICOKEYS_OK) {
        ret = picokeys_vault_get_kvault(app, root, kvault);
    }
    mbedtls_platform_zeroize(root, sizeof(root));
    return ret;
}

int openpgp_vault_store_kvault(openpgp_vault_app_t app, const uint8_t kvault[OPENPGP_VAULT_KEY_SIZE]) {
    if (!kvault || !openpgp_vault_app_valid(app)) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (openpgp_vault_sdk_init() != PICOKEYS_OK) {
        return PICOKEYS_EXEC_ERROR;
    }
    uint8_t root[OPENPGP_VAULT_KEY_SIZE] = { 0 };
    int ret = openpgp_vault_load_root(app, root);
    if (ret == PICOKEYS_OK) {
        ret = picokeys_vault_set_kvault(kvault, root, app);
    }
    mbedtls_platform_zeroize(root, sizeof(root));
    return ret;
}

int openpgp_vault_clear_openpgp(void) {
    if (openpgp_vault_sdk_init() != PICOKEYS_OK) {
        return PICOKEYS_EXEC_ERROR;
    }
    int ret = picokeys_vault_delete_kvault(OPENPGP_VAULT_APP_OPENPGP);
    return ret == PICOKEYS_ERR_FILE_NOT_FOUND ? PICOKEYS_OK : ret;
}

int openpgp_vault_clear_wrappers(void) {
    if (openpgp_vault_sdk_init() != PICOKEYS_OK) {
        return PICOKEYS_EXEC_ERROR;
    }
    int ret = PICOKEYS_OK;
    for (openpgp_vault_app_t app = OPENPGP_VAULT_APP_OPENPGP; app < OPENPGP_VAULT_APP_COUNT; app++) {
        if (openpgp_vault_app_authenticated(app)) {
            int current = picokeys_vault_delete_kvault(app);
            if (current != PICOKEYS_OK && current != PICOKEYS_ERR_FILE_NOT_FOUND) {
                ret = current;
            }
        }
    }
    return ret;
}

bool openpgp_vault_backup_authorized(openpgp_vault_app_t app) {
    uint8_t kvault[OPENPGP_VAULT_KEY_SIZE] = { 0 };
    int ret = openpgp_vault_load_kvault(app, kvault);
    mbedtls_platform_zeroize(kvault, sizeof(kvault));
    return ret == PICOKEYS_OK;
}

static int openpgp_vault_handle_fid(openpgp_vault_app_t app, uint8_t handle, uint16_t *fid) {
    if (!fid) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (app == OPENPGP_VAULT_APP_OPENPGP) {
        if (handle == OPENPGP_VAULT_HANDLE_SIGNATURE) {
            *fid = EF_PK_SIG;
        }
        else if (handle == OPENPGP_VAULT_HANDLE_DECRYPTION) {
            *fid = EF_PK_DEC;
        }
        else if (handle == OPENPGP_VAULT_HANDLE_AUTHENTICATION) {
            *fid = EF_PK_AUT;
        }
        else if (handle == OPENPGP_VAULT_HANDLE_AES) {
            *fid = EF_AES_KEY;
        }
        else {
            return PICOKEYS_WRONG_DATA;
        }
        return PICOKEYS_OK;
    }
    if (app != OPENPGP_VAULT_APP_PIV || handle == EF_PIV_KEY_CARDMGM || handle == 0x80 || handle == 0x81) {
        return PICOKEYS_WRONG_DATA;
    }
    if (handle == 0xF9) {
        *fid = EF_PIV_KEY_ATTESTATION;
    }
    else if (handle == 0x93) {
        *fid = EF_PIV_KEY_RETIRED18;
    }
    else {
        *fid = handle;
    }
    return openpgp_key_container_supported(*fid) ? PICOKEYS_OK : PICOKEYS_WRONG_DATA;
}

static void openpgp_vault_object_hash(openpgp_vault_app_t app, uint16_t fid, uint8_t hash[OPENPGP_VAULT_KEY_SIZE]) {
    uint8_t identity[3] = { app, (uint8_t)(fid >> 8), (uint8_t)fid };
    hash256(CONST_BYTE_ARRAY(identity, sizeof(identity)), hash);
}

static int openpgp_vault_encode_plaintext(openpgp_vault_app_t app, uint16_t fid, const uint8_t *private_data, size_t private_len, const uint8_t *public_data, size_t public_len, uint8_t *plain, size_t plain_capacity, size_t *plain_len) {
    if (!plain || !plain_len || private_len > OPENPGP_MAX_OBJECT_SIZE || public_len > OPENPGP_MAX_OBJECT_SIZE || (!private_data && private_len > 0) || (!public_data && public_len > 0)) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    size_t needed = 8u + private_len + public_len;
    if (private_len > UINT16_MAX || public_len > UINT16_MAX || needed > plain_capacity) {
        return PICOKEYS_ERR_NO_MEMORY;
    }
    plain[0] = 1;
    plain[1] = app;
    put_uint16_be(fid, plain + 2);
    put_uint16_be((uint16_t)private_len, plain + 4);
    memcpy(plain + 6, private_data, private_len);
    put_uint16_be((uint16_t)public_len, plain + 6 + private_len);
    memcpy(plain + 8 + private_len, public_data, public_len);
    *plain_len = needed;
    return PICOKEYS_OK;
}

static int openpgp_vault_decode_plaintext(const uint8_t *plain, size_t plain_len, openpgp_vault_plaintext_t *output) {
    if (!plain || !output) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (plain_len < 8u || plain[0] != 1 || plain[1] >= OPENPGP_VAULT_APP_COUNT) {
        return PICOKEYS_WRONG_DATA;
    }
    uint16_t private_len = get_uint16_be(plain + 4);
    if ((size_t)private_len + 8u > plain_len) {
        return PICOKEYS_WRONG_DATA;
    }
    size_t public_length_offset = 6u + private_len;
    if (public_length_offset + 2u > plain_len) {
        return PICOKEYS_WRONG_DATA;
    }
    uint16_t public_len = get_uint16_be(plain + public_length_offset);
    if (public_length_offset + 2u + public_len != plain_len || private_len > OPENPGP_MAX_OBJECT_SIZE || public_len > OPENPGP_MAX_OBJECT_SIZE || private_len == 0) {
        return PICOKEYS_WRONG_DATA;
    }
    memset(output, 0, sizeof(*output));
    output->app = plain[1];
    output->fid = get_uint16_be(plain + 2);
    output->private_len = private_len;
    output->public_len = public_len;
    memcpy(output->private_data, plain + 6, private_len);
    memcpy(output->public_data, plain + public_length_offset + 2, public_len);
    return PICOKEYS_OK;
}

static int openpgp_vault_load_keys(openpgp_vault_app_t app, uint8_t kvault[OPENPGP_VAULT_KEY_SIZE], uint8_t vault_id[OPENPGP_VAULT_KEY_SIZE], const uint8_t object_hash[OPENPGP_VAULT_KEY_SIZE], uint8_t algorithm, uint8_t keys[2][OPENPGP_VAULT_KEY_SIZE]) {
    if (openpgp_vault_load_kvault(app, kvault) != PICOKEYS_OK || picokeys_vault_hash_kvault(kvault, vault_id) != PICOKEYS_OK) {
        return PICOKEYS_NO_LOGIN;
    }
    size_t layers = picokeys_vault_algorithm_layers(algorithm);
    for (size_t layer = 0; layer < layers; layer++) {
        if (picokeys_vault_layer_key(kvault, vault_id, object_hash, algorithm, (uint8_t)layer, keys[layer]) != PICOKEYS_OK) {
            return PICOKEYS_EXEC_ERROR;
        }
    }
    return PICOKEYS_OK;
}

static int openpgp_vault_export(openpgp_vault_app_t app, uint16_t fid, uint8_t algorithm, uint8_t *blob, size_t blob_capacity, size_t *blob_len) {
    if (!blob || !blob_len || !picokeys_vault_algorithm_valid(algorithm)) {
        return PICOKEYS_WRONG_DATA;
    }
    uint8_t private_data[OPENPGP_MAX_OBJECT_SIZE] = { 0 };
    uint8_t public_data[OPENPGP_MAX_OBJECT_SIZE] = { 0 };
    byte_buffer_t private_output = BYTE_BUFFER(private_data, sizeof(private_data));
    byte_buffer_t public_output = BYTE_BUFFER(public_data, sizeof(public_data));
    int ret = openpgp_key_container_read_private(fid, FILE_OBJECT_OPERATION_EXPORT, true, &private_output);
    if (ret != PICOKEYS_OK) {
        goto cleanup;
    }
    ret = openpgp_key_container_read_public(fid, &public_output);
    if (ret == PICOKEYS_ERR_FILE_NOT_FOUND) {
        ret = PICOKEYS_OK;
    }
    if (ret != PICOKEYS_OK) {
        goto cleanup;
    }
    uint8_t plain[OPENPGP_VAULT_PLAIN_MAX] = { 0 };
    size_t plain_len = 0;
    ret = openpgp_vault_encode_plaintext(app, fid, private_data, private_output.len, public_data, public_output.len, plain, sizeof(plain), &plain_len);
    if (ret != PICOKEYS_OK) {
        goto cleanup_plain;
    }
    size_t layers = picokeys_vault_algorithm_layers(algorithm);
    size_t nonce_len = layers * PICOKEYS_VAULT_BLOB_NONCE_SIZE;
    size_t total_len = OPENPGP_VAULT_BLOB_HEADER_SIZE + nonce_len + plain_len + layers * PICOKEYS_VAULT_BLOB_TAG_SIZE;
    if (total_len > blob_capacity) {
        ret = PICOKEYS_ERR_NO_MEMORY;
        goto cleanup_plain;
    }
    uint8_t kvault[OPENPGP_VAULT_KEY_SIZE] = { 0 };
    uint8_t vault_id[OPENPGP_VAULT_KEY_SIZE] = { 0 };
    uint8_t object_hash[OPENPGP_VAULT_KEY_SIZE] = { 0 };
    uint8_t keys[2][OPENPGP_VAULT_KEY_SIZE] = { 0 };
    openpgp_vault_object_hash(app, fid, object_hash);
    ret = openpgp_vault_load_keys(app, kvault, vault_id, object_hash, algorithm, keys);
    if (ret != PICOKEYS_OK) {
        goto cleanup_keys;
    }
    memcpy(blob, openpgp_vault_blob_magic, sizeof(openpgp_vault_blob_magic));
    memcpy(blob + 4, vault_id, sizeof(vault_id));
    memcpy(blob + 36, object_hash, sizeof(object_hash));
    blob[OPENPGP_VAULT_BLOB_SERIAL_LENGTH_OFFSET] = sizeof(pico_serial.id) <= OPENPGP_VAULT_BLOB_SERIAL_MAX ? sizeof(pico_serial.id) : OPENPGP_VAULT_BLOB_SERIAL_MAX;
    memcpy(blob + OPENPGP_VAULT_BLOB_SERIAL_OFFSET, pico_serial.id, blob[OPENPGP_VAULT_BLOB_SERIAL_LENGTH_OFFSET]);
    blob[OPENPGP_VAULT_BLOB_ALGORITHM_OFFSET] = algorithm;
    random_fill_buffer(BYTE_ARRAY(blob + OPENPGP_VAULT_BLOB_HEADER_SIZE, nonce_len));
    if (layers == 1) {
        ret = picokeys_vault_encrypt_layer(algorithm, keys[0], blob + OPENPGP_VAULT_BLOB_HEADER_SIZE, blob, OPENPGP_VAULT_BLOB_HEADER_SIZE, plain, plain_len, blob + OPENPGP_VAULT_BLOB_HEADER_SIZE + nonce_len, blob + total_len - PICOKEYS_VAULT_BLOB_TAG_SIZE);
    }
    else {
        uint8_t intermediate[OPENPGP_VAULT_PLAIN_MAX + PICOKEYS_VAULT_BLOB_TAG_SIZE] = { 0 };
        ret = picokeys_vault_encrypt_layer(picokeys_vault_algorithm_layer(algorithm, 0), keys[0], blob + OPENPGP_VAULT_BLOB_HEADER_SIZE, blob, OPENPGP_VAULT_BLOB_HEADER_SIZE, plain, plain_len, intermediate, intermediate + plain_len);
        if (ret == PICOKEYS_OK) {
            ret = picokeys_vault_encrypt_layer(picokeys_vault_algorithm_layer(algorithm, 1), keys[1], blob + OPENPGP_VAULT_BLOB_HEADER_SIZE + PICOKEYS_VAULT_BLOB_NONCE_SIZE, blob, OPENPGP_VAULT_BLOB_HEADER_SIZE, intermediate, plain_len + PICOKEYS_VAULT_BLOB_TAG_SIZE, blob + OPENPGP_VAULT_BLOB_HEADER_SIZE + nonce_len, blob + total_len - PICOKEYS_VAULT_BLOB_TAG_SIZE);
        }
        mbedtls_platform_zeroize(intermediate, sizeof(intermediate));
    }
    if (ret == PICOKEYS_OK) {
        *blob_len = total_len;
    }
cleanup_keys:
    mbedtls_platform_zeroize(keys, sizeof(keys));
    mbedtls_platform_zeroize(object_hash, sizeof(object_hash));
    mbedtls_platform_zeroize(vault_id, sizeof(vault_id));
    mbedtls_platform_zeroize(kvault, sizeof(kvault));
cleanup_plain:
    mbedtls_platform_zeroize(plain, sizeof(plain));
cleanup:
    mbedtls_platform_zeroize(private_data, sizeof(private_data));
    mbedtls_platform_zeroize(public_data, sizeof(public_data));
    return ret;
}

static int openpgp_vault_import(openpgp_vault_app_t app, uint16_t target_fid, const uint8_t *blob, size_t blob_len) {
    if (!blob || blob_len < OPENPGP_VAULT_BLOB_HEADER_SIZE + PICOKEYS_VAULT_BLOB_NONCE_SIZE + PICOKEYS_VAULT_BLOB_TAG_SIZE || memcmp(blob, openpgp_vault_blob_magic, sizeof(openpgp_vault_blob_magic)) != 0 || blob[OPENPGP_VAULT_BLOB_SERIAL_LENGTH_OFFSET] > OPENPGP_VAULT_BLOB_SERIAL_MAX) {
        return PICOKEYS_WRONG_DATA;
    }
    uint8_t algorithm = blob[OPENPGP_VAULT_BLOB_ALGORITHM_OFFSET];
    if (!picokeys_vault_algorithm_valid(algorithm)) {
        return PICOKEYS_WRONG_DATA;
    }
    size_t layers = picokeys_vault_algorithm_layers(algorithm);
    size_t nonce_len = layers * PICOKEYS_VAULT_BLOB_NONCE_SIZE;
    if (blob_len < OPENPGP_VAULT_BLOB_HEADER_SIZE + nonce_len + layers * PICOKEYS_VAULT_BLOB_TAG_SIZE) {
        return PICOKEYS_WRONG_LENGTH;
    }
    size_t encrypted_len = blob_len - OPENPGP_VAULT_BLOB_HEADER_SIZE - nonce_len;
    size_t plain_len = encrypted_len - layers * PICOKEYS_VAULT_BLOB_TAG_SIZE;
    if (plain_len == 0 || plain_len > OPENPGP_VAULT_PLAIN_MAX) {
        return PICOKEYS_WRONG_LENGTH;
    }
    uint8_t kvault[OPENPGP_VAULT_KEY_SIZE] = { 0 };
    uint8_t vault_id[OPENPGP_VAULT_KEY_SIZE] = { 0 };
    uint8_t object_hash[OPENPGP_VAULT_KEY_SIZE] = { 0 };
    uint8_t keys[2][OPENPGP_VAULT_KEY_SIZE] = { 0 };
    memcpy(object_hash, blob + 36, sizeof(object_hash));
    int ret = openpgp_vault_load_keys(app, kvault, vault_id, object_hash, algorithm, keys);
    if (ret != PICOKEYS_OK) {
        goto cleanup;
    }
    if (mbedtls_ct_memcmp(vault_id, blob + 4, sizeof(vault_id)) != 0) {
        ret = PICOKEYS_VERIFICATION_FAILED;
        goto cleanup;
    }
    uint8_t plain[OPENPGP_VAULT_PLAIN_MAX] = { 0 };
    if (layers == 1) {
        ret = picokeys_vault_decrypt_layer(algorithm, keys[0], blob + OPENPGP_VAULT_BLOB_HEADER_SIZE, blob, OPENPGP_VAULT_BLOB_HEADER_SIZE, blob + OPENPGP_VAULT_BLOB_HEADER_SIZE + nonce_len, plain_len, blob + blob_len - PICOKEYS_VAULT_BLOB_TAG_SIZE, plain);
    }
    else {
        uint8_t intermediate[OPENPGP_VAULT_PLAIN_MAX + PICOKEYS_VAULT_BLOB_TAG_SIZE] = { 0 };
        ret = picokeys_vault_decrypt_layer(picokeys_vault_algorithm_layer(algorithm, 1), keys[1], blob + OPENPGP_VAULT_BLOB_HEADER_SIZE + PICOKEYS_VAULT_BLOB_NONCE_SIZE, blob, OPENPGP_VAULT_BLOB_HEADER_SIZE, blob + OPENPGP_VAULT_BLOB_HEADER_SIZE + nonce_len, plain_len + PICOKEYS_VAULT_BLOB_TAG_SIZE, blob + blob_len - PICOKEYS_VAULT_BLOB_TAG_SIZE, intermediate);
        if (ret == PICOKEYS_OK) {
            ret = picokeys_vault_decrypt_layer(picokeys_vault_algorithm_layer(algorithm, 0), keys[0], blob + OPENPGP_VAULT_BLOB_HEADER_SIZE, blob, OPENPGP_VAULT_BLOB_HEADER_SIZE, intermediate, plain_len, intermediate + plain_len, plain);
        }
        mbedtls_platform_zeroize(intermediate, sizeof(intermediate));
    }
    if (ret != PICOKEYS_OK) {
        ret = PICOKEYS_VERIFICATION_FAILED;
        mbedtls_platform_zeroize(plain, sizeof(plain));
        goto cleanup;
    }
    openpgp_vault_plaintext_t decoded;
    ret = openpgp_vault_decode_plaintext(plain, plain_len, &decoded);
    if (ret == PICOKEYS_OK && decoded.app != app) {
        ret = PICOKEYS_WRONG_DATA;
    }
    if (ret == PICOKEYS_OK) {
        uint8_t expected_hash[OPENPGP_VAULT_KEY_SIZE] = { 0 };
        openpgp_vault_object_hash(decoded.app, decoded.fid, expected_hash);
        if (mbedtls_ct_memcmp(expected_hash, blob + 36, sizeof(expected_hash)) != 0) {
            ret = PICOKEYS_VERIFICATION_FAILED;
        }
        mbedtls_platform_zeroize(expected_hash, sizeof(expected_hash));
    }
    if (ret == PICOKEYS_OK) {
        uint8_t current_private[OPENPGP_MAX_OBJECT_SIZE] = { 0 };
        uint8_t current_public[OPENPGP_MAX_OBJECT_SIZE] = { 0 };
        byte_buffer_t current_private_output = BYTE_BUFFER(current_private, sizeof(current_private));
        byte_buffer_t current_public_output = BYTE_BUFFER(current_public, sizeof(current_public));
        int current_ret = openpgp_key_container_read_private(target_fid, FILE_OBJECT_OPERATION_UPDATE, true, &current_private_output);
        if (current_ret == PICOKEYS_OK && decoded.public_len > 0) {
            current_ret = openpgp_key_container_read_public(target_fid, &current_public_output);
        }
        if (current_ret == PICOKEYS_OK && current_private_output.len == decoded.private_len && current_public_output.len == decoded.public_len && memcmp(current_private, decoded.private_data, decoded.private_len) == 0 && memcmp(current_public, decoded.public_data, decoded.public_len) == 0) {
            ret = PICOKEYS_OK;
        }
        else {
            ret = openpgp_key_container_store(target_fid, decoded.private_data, decoded.private_len, decoded.public_len ? decoded.public_data : NULL, decoded.public_len, true);
        }
        mbedtls_platform_zeroize(current_private, sizeof(current_private));
        mbedtls_platform_zeroize(current_public, sizeof(current_public));
    }
    mbedtls_platform_zeroize(&decoded, sizeof(decoded));
    mbedtls_platform_zeroize(plain, sizeof(plain));
cleanup:
    mbedtls_platform_zeroize(keys, sizeof(keys));
    mbedtls_platform_zeroize(object_hash, sizeof(object_hash));
    mbedtls_platform_zeroize(vault_id, sizeof(vault_id));
    mbedtls_platform_zeroize(kvault, sizeof(kvault));
    return ret;
}

static int openpgp_vault_get_label(uint8_t *label, size_t capacity, size_t *length) {
    if (!label || !length || openpgp_vault_sdk_init() != PICOKEYS_OK) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    byte_buffer_t output = BYTE_BUFFER(label, capacity);
    int ret = picokeys_vault_get_label(&output);
    *length = output.len;
    return ret;
}

int openpgp_vault_command(openpgp_vault_app_t app) {
    if (!openpgp_vault_app_valid(app)) {
        return SW_INCORRECT_P1P2();
    }
    if (P1(apdu) == OPENPGP_VAULT_SUBCOMMAND_STATUS) {
        if (P2(apdu) != 0 || apdu.nc != 0) {
            return SW_INCORRECT_P1P2();
        }
        uint8_t kvault[OPENPGP_VAULT_KEY_SIZE] = { 0 };
        uint8_t vault_id[OPENPGP_VAULT_KEY_SIZE] = { 0 };
        uint8_t label[64] = { 0 };
        size_t label_len = 0;
        bool stored = openpgp_vault_wrapper_available(app);
        bool enrolled = stored && openpgp_vault_load_kvault(app, kvault) == PICOKEYS_OK && picokeys_vault_hash_kvault(kvault, vault_id) == PICOKEYS_OK;
        if (stored) {
            openpgp_vault_get_label(label, sizeof(label), &label_len);
        }
        res_APDU[0] = 1;
        res_APDU[1] = stored;
        res_APDU[2] = picokeys_vault_enrollment_button_ready();
        res_APDU[3] = enrolled ? sizeof(vault_id) : 0;
        memcpy(res_APDU + 4, vault_id, sizeof(vault_id));
        res_APDU[36] = label_len;
        memcpy(res_APDU + 37, label, label_len);
        res_APDU_size = 37 + label_len;
        mbedtls_platform_zeroize(kvault, sizeof(kvault));
        mbedtls_platform_zeroize(vault_id, sizeof(vault_id));
        mbedtls_platform_zeroize(label, sizeof(label));
        return SW_OK();
    }
    if (P1(apdu) == OPENPGP_VAULT_SUBCOMMAND_START_ENROLLMENT) {
        if (P2(apdu) != 0 || apdu.nc != 0) {
            return SW_INCORRECT_P1P2();
        }
        if (!openpgp_vault_app_authenticated(app)) {
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
        if (!picokeys_vault_enrollment_button_ready()) {
            return SW_CONDITIONS_NOT_SATISFIED();
        }
        uint8_t public_key[PICOKEYS_VAULT_X448_BYTES] = { 0 };
        uint8_t challenge[PICOKEYS_VAULT_ENROLL_CHALLENGE_BYTES] = { 0 };
        if (picokeys_vault_enrollment_start(public_key, challenge) != PICOKEYS_OK) {
            return SW_EXEC_ERROR();
        }
        memcpy(res_APDU, public_key, sizeof(public_key));
        memcpy(res_APDU + sizeof(public_key), challenge, sizeof(challenge));
        res_APDU_size = sizeof(public_key) + sizeof(challenge);
        return SW_OK();
    }
    if (P1(apdu) == OPENPGP_VAULT_SUBCOMMAND_FINISH_ENROLLMENT) {
        if (P2(apdu) != 0 || apdu.nc == 0) {
            return SW_INCORRECT_P1P2();
        }
        if (!openpgp_vault_app_authenticated(app)) {
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
        uint8_t kvault[OPENPGP_VAULT_KEY_SIZE] = { 0 };
        uint8_t label[64] = { 0 };
        size_t label_len = 0;
        int ret = picokeys_vault_enrollment_decode(apdu.data, apdu.nc, kvault, label, sizeof(label), &label_len);
        if (ret == PICOKEYS_OK) {
            ret = openpgp_vault_store_kvault(app, kvault);
        }
        if (ret == PICOKEYS_OK) {
            ret = openpgp_vault_sdk_init();
        }
        if (ret == PICOKEYS_OK) {
            ret = picokeys_vault_set_label(CONST_BYTE_ARRAY(label, label_len));
        }
        uint8_t vault_id[OPENPGP_VAULT_KEY_SIZE] = { 0 };
        if (ret == PICOKEYS_OK) {
            ret = picokeys_vault_hash_kvault(kvault, vault_id);
        }
        mbedtls_platform_zeroize(kvault, sizeof(kvault));
        mbedtls_platform_zeroize(label, sizeof(label));
        if (ret != PICOKEYS_OK) {
            picokeys_vault_enrollment_reset();
            return SW_DATA_INVALID();
        }
        memcpy(res_APDU, vault_id, sizeof(vault_id));
        res_APDU_size = sizeof(vault_id);
        mbedtls_platform_zeroize(vault_id, sizeof(vault_id));
        return SW_OK();
    }
    if (P1(apdu) == OPENPGP_VAULT_SUBCOMMAND_EXPORT) {
        uint16_t fid = 0;
        if (apdu.nc > 1 || openpgp_vault_handle_fid(app, P2(apdu), &fid) != PICOKEYS_OK) {
            return SW_INCORRECT_P1P2();
        }
        uint8_t algorithm = apdu.nc == 1 ? apdu.data[0] : PICOKEYS_VAULT_ALGORITHM_CHACHAPOLY;
        uint8_t blob[OPENPGP_VAULT_BLOB_MAX] = { 0 };
        size_t blob_len = 0;
        int ret = openpgp_vault_export(app, fid, algorithm, blob, sizeof(blob), &blob_len);
        if (ret != PICOKEYS_OK) {
            mbedtls_platform_zeroize(blob, sizeof(blob));
            return ret == PICOKEYS_NO_LOGIN ? SW_SECURITY_STATUS_NOT_SATISFIED() : ret == PICOKEYS_ERR_NO_MEMORY ? SW_MEMORY_FAILURE() : SW_REFERENCE_NOT_FOUND();
        }
        memcpy(res_APDU, blob, blob_len);
        res_APDU_size = blob_len;
        mbedtls_platform_zeroize(blob, sizeof(blob));
        return SW_OK();
    }
    if (P1(apdu) == OPENPGP_VAULT_SUBCOMMAND_IMPORT) {
        uint16_t fid = 0;
        if (apdu.nc == 0 || openpgp_vault_handle_fid(app, P2(apdu), &fid) != PICOKEYS_OK) {
            return SW_INCORRECT_P1P2();
        }
        int ret = openpgp_vault_import(app, fid, apdu.data, apdu.nc);
        return ret == PICOKEYS_OK ? SW_OK() : ret == PICOKEYS_NO_LOGIN ? SW_SECURITY_STATUS_NOT_SATISFIED() : ret == PICOKEYS_ERR_NO_MEMORY || ret == PICOKEYS_ERR_MEMORY_FATAL ? SW_MEMORY_FAILURE() : SW_DATA_INVALID();
    }
    if (P1(apdu) == OPENPGP_VAULT_SUBCOMMAND_UNENROLL) {
        if (P2(apdu) != 0 || apdu.nc != 0) {
            return SW_INCORRECT_P1P2();
        }
        if (!openpgp_vault_app_authenticated(app) || openpgp_vault_sdk_init() != PICOKEYS_OK) {
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
        int ret = picokeys_vault_delete_kvault(app);
        return ret == PICOKEYS_OK || ret == PICOKEYS_ERR_FILE_NOT_FOUND ? SW_OK() : SW_EXEC_ERROR();
    }
    return SW_INCORRECT_P1P2();
}

int cmd_openpgp_vault(void) {
    return openpgp_vault_command(OPENPGP_VAULT_APP_OPENPGP);
}

int cmd_piv_vault(void) {
    return openpgp_vault_command(OPENPGP_VAULT_APP_PIV);
}
