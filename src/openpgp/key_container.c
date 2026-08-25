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

#include "picokeys.h"
#include "key_container.h"
#include "object_container_store.h"
#include "object_provider.h"
#include "openpgp.h"

#define OPENPGP_KEY_MANIFEST_SLOT_0_PREFIX 0xd0u
#define OPENPGP_KEY_MANIFEST_SLOT_1_PREFIX 0xd1u
#define OPENPGP_KEY_PRIVATE_SLOT_0_PREFIX 0xd2u
#define OPENPGP_KEY_PUBLIC_SLOT_0_PREFIX 0xd3u
#define OPENPGP_KEY_PRIVATE_SLOT_1_PREFIX 0xd4u
#define OPENPGP_KEY_PUBLIC_SLOT_1_PREFIX 0xd5u
#define OPENPGP_KEY_CONTAINER_COMMIT_TIMEOUT_MS 5000u
#define OPENPGP_KEY_CONTAINER_POLICY_ID 0x0500u
#define OPENPGP_KEY_CONTAINER_MARKER_SIZE 10u
#define OPENPGP_KEY_MARKER_VERSION_OFFSET 4u
#define OPENPGP_KEY_MARKER_FID_OFFSET 5u
#define OPENPGP_KEY_MARKER_RESERVED_OFFSET 7u
#define OPENPGP_KEY_MARKER_RESERVED_SIZE 3u
#define OPENPGP_KEY_MARKER_VERSION 1u

static const uint8_t openpgp_key_container_marker_magic[4] = { 'P', 'K', 'G', '1' };
static const uint8_t openpgp_key_container_marker_reserved[OPENPGP_KEY_MARKER_RESERVED_SIZE] = { 0 };
static const uint8_t openpgp_key_internal_policy[] = {
    FILE_OBJECT_POLICY_FORMAT_VERSION, 1,
    0x1f, 0xff, 0x00, 0x00, 0x04, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00
};

static uint32_t openpgp_key_container_id(uint16_t fid) {
    return fid & UINT8_MAX;
}

static uint16_t openpgp_key_manifest_fid(uint16_t fid, uint8_t slot) {
    uint8_t prefix = slot == 0 ? OPENPGP_KEY_MANIFEST_SLOT_0_PREFIX : OPENPGP_KEY_MANIFEST_SLOT_1_PREFIX;
    return (uint16_t)((prefix << 8) | openpgp_key_container_id(fid));
}

static uint16_t openpgp_key_record_fid(uint16_t fid, uint8_t slot, uint16_t object_type) {
    uint8_t prefix = slot == 0 ? OPENPGP_KEY_PRIVATE_SLOT_0_PREFIX : OPENPGP_KEY_PRIVATE_SLOT_1_PREFIX;
    if (object_type == OPENPGP_KEY_OBJECT_PUBLIC) {
        prefix++;
    }
    return (uint16_t)((prefix << 8) | openpgp_key_container_id(fid));
}

bool openpgp_key_container_is_piv(uint16_t fid) {
    bool retired_range = fid >= EF_PIV_KEY_RETIRED1 && fid <= EF_PIV_KEY_RETIRED17;
    bool retired_reserved_gap = fid == EF_PIV_KEY_RETIRED19 || fid == EF_PIV_KEY_RETIRED20 || fid == EF_PIV_KEY_RETIRED18;
    bool active = fid >= EF_PIV_KEY_AUTHENTICATION && fid <= EF_PIV_KEY_CARDAUTH;
    return retired_range || retired_reserved_gap || active || fid == EF_PIV_KEY_ATTESTATION;
}

bool openpgp_key_container_supported(uint16_t fid) {
    return fid == EF_PK_SIG || fid == EF_PK_DEC || fid == EF_PK_AUT || fid == EF_AES_KEY || openpgp_key_container_is_piv(fid);
}

static bool openpgp_key_object_type_valid(uint16_t object_type) {
    return object_type == OPENPGP_KEY_OBJECT_PRIVATE || object_type == OPENPGP_KEY_OBJECT_PUBLIC;
}

bool openpgp_key_container_is_marker(const file_t *file) {
    if (!file_has_data(file) || file_get_size(file) != OPENPGP_KEY_CONTAINER_MARKER_SIZE) {
        return false;
    }

    const uint8_t *data = file_get_data(file);
    return memcmp(data, openpgp_key_container_marker_magic, sizeof(openpgp_key_container_marker_magic)) == 0 &&
           data[OPENPGP_KEY_MARKER_VERSION_OFFSET] == OPENPGP_KEY_MARKER_VERSION &&
           get_uint16_be(data + OPENPGP_KEY_MARKER_FID_OFFSET) == file->fid &&
           memcmp(data + OPENPGP_KEY_MARKER_RESERVED_OFFSET, openpgp_key_container_marker_reserved, sizeof(openpgp_key_container_marker_reserved)) == 0;
}

static bool openpgp_key_file_magic(uint16_t fid, const uint8_t magic[4]) {
    file_t *file = file_search(fid);
    return file_has_data(file) && file_get_size(file) >= 4 && memcmp(file_get_data(file), magic, 4) == 0;
}

bool openpgp_key_container_physical_fid(uint16_t fid) {
    static const uint8_t manifest_magic[4] = { 'P', 'K', 'O', 'C' };
    static const uint8_t record_magic[4] = { 'P', 'K', 'O', 'R' };
    uint8_t prefix = fid >> 8;

    if (prefix == OPENPGP_KEY_MANIFEST_SLOT_0_PREFIX || prefix == OPENPGP_KEY_MANIFEST_SLOT_1_PREFIX) {
        return openpgp_key_file_magic(fid, manifest_magic);
    }
    if (prefix >= OPENPGP_KEY_PRIVATE_SLOT_0_PREFIX && prefix <= OPENPGP_KEY_PUBLIC_SLOT_1_PREFIX) {
        return openpgp_key_file_magic(fid, record_magic);
    }
    return false;
}

static int openpgp_key_policy_hash(void *ctx, uint16_t policy_id, uint8_t hash[FILE_OBJECT_POLICY_HASH_SIZE]) {
    (void)ctx;

    if (policy_id != OPENPGP_KEY_CONTAINER_POLICY_ID) {
        return PICOKEYS_WRONG_DATA;
    }
    return file_object_policy_hash(CONST_BYTE_ARRAY(openpgp_key_internal_policy, sizeof(openpgp_key_internal_policy)), hash);
}

static uint16_t openpgp_key_layout_manifest_fid(void *ctx, uint32_t container_id, uint8_t slot) {
    (void)ctx;

    return openpgp_key_manifest_fid((uint16_t)container_id, slot);
}

static bool openpgp_key_record_id_valid(uint16_t fid, const file_object_descriptor_t *object) {
    if (!openpgp_key_object_type_valid(object->object_type) || object->record_id > UINT16_MAX) {
        return false;
    }

    uint16_t record_fid = (uint16_t)object->record_id;
    return record_fid == openpgp_key_record_fid(fid, 0, object->object_type) || record_fid == openpgp_key_record_fid(fid, 1, object->object_type);
}

static int openpgp_key_layout_record_fid(void *ctx, uint32_t container_id, const file_object_descriptor_t *object, uint16_t *fid) {
    (void)ctx;

    if (!object || !fid || !openpgp_key_record_id_valid((uint16_t)container_id, object)) {
        return PICOKEYS_WRONG_DATA;
    }
    *fid = (uint16_t)object->record_id;
    return PICOKEYS_OK;
}

static int openpgp_key_layout_record_allocate(void *ctx, uint32_t container_id, uint8_t target_slot, const file_object_container_write_t *write, const file_object_authenticator_t *auth, uint64_t *record_id, uint16_t *fid) {
    (void)ctx;
    (void)auth;

    if (!write || !record_id || !fid || !openpgp_key_object_type_valid(write->object_type)) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    *fid = openpgp_key_record_fid((uint16_t)container_id, target_slot, write->object_type);
    *record_id = *fid;
    return PICOKEYS_OK;
}

static bool openpgp_key_layout_write_valid(void *ctx, const file_object_container_write_t *write) {
    (void)ctx;

    if (!openpgp_key_object_type_valid(write->object_type) || write->object_tag != 0 || write->policy_id != OPENPGP_KEY_CONTAINER_POLICY_ID || write->key_domain > 1) {
        return false;
    }
    if (write->object_type == OPENPGP_KEY_OBJECT_PRIVATE) {
        return write->protection == FILE_OBJECT_PROTECTION_AEAD_SECRET && write->flags == (FILE_OBJECT_FLAG_MUTABLE | FILE_OBJECT_FLAG_NON_EXPORTABLE);
    }
    return write->protection == FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC && write->flags == (FILE_OBJECT_FLAG_MUTABLE | FILE_OBJECT_FLAG_GENERIC_READABLE);
}

static bool openpgp_key_layout_descriptor_valid(void *ctx, uint32_t container_id, const file_object_descriptor_t *object) {
    (void)ctx;

    uint8_t key_domain = openpgp_key_container_is_piv((uint16_t)container_id) ? 1u : 0u;
    return object->object_tag == 0 && object->key_domain == key_domain && openpgp_key_record_id_valid((uint16_t)container_id, object);
}

static int openpgp_key_marker_write(uint16_t fid) {
    file_t *file = file_search_by_fid(fid, NULL, SPECIFY_EF);
    if (!file) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }

    uint8_t marker[OPENPGP_KEY_CONTAINER_MARKER_SIZE] = { 0 };
    memcpy(marker, openpgp_key_container_marker_magic, sizeof(openpgp_key_container_marker_magic));
    marker[OPENPGP_KEY_MARKER_VERSION_OFFSET] = OPENPGP_KEY_MARKER_VERSION;
    put_uint16_be(fid, marker + OPENPGP_KEY_MARKER_FID_OFFSET);
    int r = file_put_data(file, CONST_BYTE_ARRAY(marker, sizeof(marker)));
    if (r != PICOKEYS_OK) {
        return r;
    }
    return flash_commit_sync(OPENPGP_KEY_CONTAINER_COMMIT_TIMEOUT_MS) ? PICOKEYS_OK : PICOKEYS_ERR_MEMORY_FATAL;
}

static int openpgp_key_layout_activate(void *ctx, uint32_t container_id) {
    (void)ctx;

    uint16_t fid = (uint16_t)container_id;
    if (openpgp_key_container_is_marker(file_search_by_fid(fid, NULL, SPECIFY_EF))) {
        return PICOKEYS_OK;
    }
    return openpgp_key_marker_write(fid);
}

static int openpgp_key_layout_deactivate(void *ctx, uint32_t container_id) {
    (void)ctx;

    file_t *marker = file_search_by_fid((uint16_t)container_id, NULL, SPECIFY_EF);
    if (!marker) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    return file_put_data(marker, CONST_BYTE_ARRAY(NULL, 0));
}

static const file_object_container_layout_t openpgp_key_container_layout = {
    .namespace_id = OPENPGP_OBJECT_NAMESPACE,
    .container_kind = OPENPGP_KEY_CONTAINER_KIND,
    .commit_timeout_ms = OPENPGP_KEY_CONTAINER_COMMIT_TIMEOUT_MS,
    .manifest_fid = openpgp_key_layout_manifest_fid,
    .record_fid = openpgp_key_layout_record_fid,
    .record_allocate = openpgp_key_layout_record_allocate,
    .policy_hash = openpgp_key_policy_hash,
    .write_valid = openpgp_key_layout_write_valid,
    .descriptor_valid = openpgp_key_layout_descriptor_valid,
    .activate = openpgp_key_layout_activate,
    .deactivate = openpgp_key_layout_deactivate,
    .rollback_new_records = true
};

static bool openpgp_key_crypto(uint16_t fid, file_object_container_crypto_t *crypto) {
    if (openpgp_key_container_is_piv(fid)) {
        crypto->auth = openpgp_piv_object_manifest_authenticator();
        crypto->protector = openpgp_piv_object_record_protector();
    }
    else {
        crypto->auth = openpgp_object_manifest_authenticator();
        crypto->protector = openpgp_object_record_protector();
    }
    return crypto->auth && crypto->protector;
}

bool openpgp_key_container_can_create(uint16_t fid) {
    if (!openpgp_key_container_supported(fid)) {
        return false;
    }

    bool manifest_present = false;
    for (uint8_t slot = 0; slot < FILE_OBJECT_CONTAINER_SLOT_COUNT; slot++) {
        manifest_present |= file_has_data(file_search(openpgp_key_manifest_fid(fid, slot)));
    }
    if (manifest_present) {
        file_object_container_crypto_t crypto;
        file_object_container_state_t state;
        if (!openpgp_key_crypto(fid, &crypto) || file_object_container_load(&openpgp_key_container_layout, fid, &crypto, NULL, &state) != PICOKEYS_OK) {
            return false;
        }
        return file_object_container_validate(&openpgp_key_container_layout, fid, &state.candidates[state.current_slot], state.crypto.protector) == PICOKEYS_OK;
    }

    static const uint8_t record_magic[4] = { 'P', 'K', 'O', 'R' };
    for (uint8_t slot = 0; slot < FILE_OBJECT_CONTAINER_SLOT_COUNT; slot++) {
        for (uint16_t object_type = OPENPGP_KEY_OBJECT_PRIVATE; object_type <= OPENPGP_KEY_OBJECT_PUBLIC; object_type++) {
            file_t *record = file_search(openpgp_key_record_fid(fid, slot, object_type));
            if (record && (!file_has_data(record) || file_get_size(record) < sizeof(record_magic) || memcmp(file_get_data(record), record_magic, sizeof(record_magic)) != 0)) {
                return false;
            }
        }
    }
    return true;
}

int openpgp_key_container_store(uint16_t fid, const uint8_t *private_data, uint32_t private_size, const uint8_t *public_data, uint32_t public_size, bool internal_firmware) {
    if (!openpgp_key_container_supported(fid) || !private_data || private_size == 0 || (!public_data && public_size > 0)) {
        return PICOKEYS_WRONG_DATA;
    }
    if ((!openpgp_key_container_is_piv(fid) && !has_pw3) || (openpgp_key_container_is_piv(fid) && !piv_key_operation_authorized(FILE_OBJECT_OPERATION_UPDATE, internal_firmware))) {
        return PICOKEYS_NO_LOGIN;
    }

    file_object_container_crypto_t crypto;
    if (!openpgp_key_crypto(fid, &crypto)) {
        return PICOKEYS_EXEC_ERROR;
    }
    if (!file_has_data(file_search(openpgp_key_manifest_fid(fid, 0))) && !file_has_data(file_search(openpgp_key_manifest_fid(fid, 1))) && !openpgp_key_container_can_create(fid)) {
        return PICOKEYS_WRONG_DATA;
    }

    file_object_container_write_t writes[2] = {
        {
            .object_type = OPENPGP_KEY_OBJECT_PRIVATE,
            .data = CONST_BYTE_ARRAY(private_data, private_size),
            .policy_id = OPENPGP_KEY_CONTAINER_POLICY_ID,
            .key_domain = openpgp_key_container_is_piv(fid) ? 1u : 0u,
            .protection = FILE_OBJECT_PROTECTION_AEAD_SECRET,
            .flags = FILE_OBJECT_FLAG_MUTABLE | FILE_OBJECT_FLAG_NON_EXPORTABLE
        },
        {
            .object_type = OPENPGP_KEY_OBJECT_PUBLIC,
            .data = CONST_BYTE_ARRAY(public_data, public_size),
            .policy_id = OPENPGP_KEY_CONTAINER_POLICY_ID,
            .key_domain = openpgp_key_container_is_piv(fid) ? 1u : 0u,
            .protection = FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC,
            .flags = FILE_OBJECT_FLAG_MUTABLE | FILE_OBJECT_FLAG_GENERIC_READABLE
        }
    };
    size_t write_count = public_data || public_size > 0 ? 2u : 1u;
    return file_object_container_update(&openpgp_key_container_layout, fid, writes, write_count, &crypto, NULL);
}

static bool openpgp_key_private_operation_authorized(uint16_t fid, uint16_t operation, bool internal_firmware) {
    if (openpgp_key_container_is_piv(fid)) {
        if (operation == FILE_OBJECT_OPERATION_EXPORT) {
            return internal_firmware && openpgp_vault_backup_authorized(OPENPGP_VAULT_APP_PIV);
        }
        return piv_key_operation_authorized(operation, internal_firmware);
    }
    if (operation == FILE_OBJECT_OPERATION_EXPORT) {
        return openpgp_vault_backup_authorized(OPENPGP_VAULT_APP_OPENPGP);
    }
    if (operation == FILE_OBJECT_OPERATION_UPDATE || operation == FILE_OBJECT_OPERATION_DELETE || operation == FILE_OBJECT_OPERATION_CHANGE_POLICY) {
        return has_pw3;
    }
    if (fid == EF_PK_SIG && operation == FILE_OBJECT_OPERATION_SIGN) {
        return has_pw1 || has_pw3;
    }
    if ((fid == EF_PK_DEC || fid == EF_AES_KEY) && (operation == FILE_OBJECT_OPERATION_DECRYPT || operation == FILE_OBJECT_OPERATION_DERIVE || operation == FILE_OBJECT_OPERATION_USE)) {
        return has_pw2 || has_pw3;
    }
    if (fid == EF_PK_AUT && (operation == FILE_OBJECT_OPERATION_SIGN || operation == FILE_OBJECT_OPERATION_DECRYPT || operation == FILE_OBJECT_OPERATION_DERIVE || operation == FILE_OBJECT_OPERATION_USE)) {
        return has_pw2 || has_pw3;
    }
    return false;
}

typedef struct openpgp_key_access_context {
    uint16_t fid;
    uint16_t operation;
    bool internal_firmware;
} openpgp_key_access_context_t;

static int openpgp_key_object_access(void *ctx, const file_object_descriptor_t *object) {
    const openpgp_key_access_context_t *access = (const openpgp_key_access_context_t *)ctx;
    if (object->object_type == OPENPGP_KEY_OBJECT_PRIVATE) {
        return openpgp_key_private_operation_authorized(access->fid, access->operation, access->internal_firmware) ? PICOKEYS_OK : PICOKEYS_NO_LOGIN;
    }
    bool readable = access->operation == FILE_OBJECT_OPERATION_READ && object->protection == FILE_OBJECT_PROTECTION_AUTHENTICATED_PUBLIC && (object->flags & FILE_OBJECT_FLAG_GENERIC_READABLE) != 0;
    return readable ? PICOKEYS_OK : PICOKEYS_NO_LOGIN;
}

int openpgp_key_container_read_private(uint16_t fid, uint16_t operation, bool internal_firmware, byte_buffer_t *data) {
    if (!openpgp_key_container_supported(fid)) {
        return PICOKEYS_WRONG_DATA;
    }

    file_object_container_crypto_t crypto;
    if (!openpgp_key_crypto(fid, &crypto)) {
        return PICOKEYS_EXEC_ERROR;
    }
    openpgp_key_access_context_t access = {
        .fid = fid,
        .operation = operation,
        .internal_firmware = internal_firmware
    };
    return file_object_container_read(&openpgp_key_container_layout, fid, OPENPGP_KEY_OBJECT_PRIVATE, 0, &crypto, NULL, openpgp_key_object_access, &access, data);
}

int openpgp_key_container_read_public(uint16_t fid, byte_buffer_t *data) {
    if (!openpgp_key_container_supported(fid)) {
        return PICOKEYS_WRONG_DATA;
    }

    file_object_container_crypto_t crypto;
    if (!openpgp_key_crypto(fid, &crypto)) {
        return PICOKEYS_EXEC_ERROR;
    }
    openpgp_key_access_context_t access = {
        .fid = fid,
        .operation = FILE_OBJECT_OPERATION_READ
    };
    return file_object_container_read(&openpgp_key_container_layout, fid, OPENPGP_KEY_OBJECT_PUBLIC, 0, &crypto, NULL, openpgp_key_object_access, &access, data);
}

int openpgp_key_container_public_size(uint16_t fid, uint32_t *object_size) {
    if (!openpgp_key_container_supported(fid)) {
        return PICOKEYS_WRONG_DATA;
    }

    file_object_container_crypto_t crypto;
    if (!openpgp_key_crypto(fid, &crypto)) {
        return PICOKEYS_EXEC_ERROR;
    }
    openpgp_key_access_context_t access = {
        .fid = fid,
        .operation = FILE_OBJECT_OPERATION_READ
    };
    return file_object_container_object_size(&openpgp_key_container_layout, fid, OPENPGP_KEY_OBJECT_PUBLIC, 0, &crypto, NULL, openpgp_key_object_access, &access, object_size);
}

int openpgp_key_container_delete(uint16_t fid, bool internal_firmware) {
    if (!openpgp_key_container_supported(fid)) {
        return PICOKEYS_WRONG_DATA;
    }
    if ((!openpgp_key_container_is_piv(fid) && !has_pw3) || (openpgp_key_container_is_piv(fid) && !piv_key_operation_authorized(FILE_OBJECT_OPERATION_DELETE, internal_firmware))) {
        return PICOKEYS_NO_LOGIN;
    }

    file_object_container_crypto_t crypto;
    if (!openpgp_key_crypto(fid, &crypto)) {
        return PICOKEYS_EXEC_ERROR;
    }
    return file_object_container_delete(&openpgp_key_container_layout, fid, &crypto, NULL);
}
