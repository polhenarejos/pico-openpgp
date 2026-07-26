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
#include "object_provider.h"
#include "openpgp.h"

#include <assert.h>
#include <setjmp.h>
#include <stdio.h>

#define TEST_FILE_COUNT 32u
#define TEST_FILE_CAPACITY 2048u

typedef struct test_file {
    file_t file;
    uint8_t storage[TEST_FILE_CAPACITY];
    uint32_t size;
    bool allocated;
} test_file_t;

typedef struct test_file_image {
    uint8_t storage[TEST_FILE_CAPACITY];
    uint32_t size;
    uint16_t fid;
    bool allocated;
} test_file_image_t;

typedef struct test_auth_context {
    uint32_t state[4];
    bool active;
} test_auth_context_t;

typedef struct test_protector_context {
    uint8_t key;
} test_protector_context_t;

static test_file_t test_files[TEST_FILE_COUNT];
static test_file_image_t test_durable_files[TEST_FILE_COUNT];
static test_auth_context_t test_auth_context;
static test_protector_context_t test_protector_context = { .key = 0x5a };
static jmp_buf test_power_loss_env;
static size_t test_power_loss_event;
static size_t test_power_loss_at = SIZE_MAX;
static bool test_power_loss_armed;

bool has_pw1;
bool has_pw2;
bool has_pw3;
bool has_rc;
uint8_t session_pw1[32];
uint8_t session_rc[32];
uint8_t session_pw3[32];
uint8_t dek[IV_SIZE + 32];

static test_file_t *test_file_from_handle(const file_t *file) {
    for (size_t i = 0; i < TEST_FILE_COUNT; i++) {
        if (&test_files[i].file == file) {
            return &test_files[i];
        }
    }
    return NULL;
}

static void test_persist(void) {
    for (size_t i = 0; i < TEST_FILE_COUNT; i++) {
        memcpy(test_durable_files[i].storage, test_files[i].storage, sizeof(test_durable_files[i].storage));
        test_durable_files[i].size = test_files[i].size;
        test_durable_files[i].fid = test_files[i].file.fid;
        test_durable_files[i].allocated = test_files[i].allocated;
    }
}

static void test_reboot(void) {
    memset(test_files, 0, sizeof(test_files));
    for (size_t i = 0; i < TEST_FILE_COUNT; i++) {
        memcpy(test_files[i].storage, test_durable_files[i].storage, sizeof(test_files[i].storage));
        test_files[i].size = test_durable_files[i].size;
        test_files[i].file.fid = test_durable_files[i].fid;
        test_files[i].allocated = test_durable_files[i].allocated;
        test_files[i].file.data = test_files[i].size > 0 ? test_files[i].storage : NULL;
    }
    test_power_loss_armed = false;
}

file_t *file_search(uint16_t fid) {
    for (size_t i = 0; i < TEST_FILE_COUNT; i++) {
        if (test_files[i].allocated && test_files[i].file.fid == fid) {
            return &test_files[i].file;
        }
    }
    return NULL;
}

file_t *file_new(uint16_t fid) {
    file_t *existing = file_search(fid);
    if (existing) {
        return existing;
    }
    for (size_t i = 0; i < TEST_FILE_COUNT; i++) {
        if (!test_files[i].allocated) {
            test_files[i].allocated = true;
            test_files[i].file.fid = fid;
            return &test_files[i].file;
        }
    }
    return NULL;
}

file_t *file_search_by_fid(const uint16_t fid, const file_t *parent, const uint8_t sp) {
    (void)parent;
    (void)sp;
    return file_search(fid);
}

bool file_has_data(const file_t *file) {
    const test_file_t *test_file = test_file_from_handle(file);
    return test_file && test_file->allocated && test_file->file.data && test_file->size > 0;
}

uint8_t *file_get_data(const file_t *file) {
    test_file_t *test_file = test_file_from_handle(file);
    return file_has_data(file) ? test_file->storage : NULL;
}

uint32_t file_get_size(const file_t *file) {
    const test_file_t *test_file = test_file_from_handle(file);
    return test_file ? test_file->size : 0;
}

int file_read_at(const file_t *file, uint32_t offset, uint8_t *data, size_t len) {
    const test_file_t *test_file = test_file_from_handle(file);
    if (!test_file || (!data && len > 0) || offset > test_file->size || len > test_file->size - offset) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    if (len > 0) {
        memcpy(data, test_file->storage + offset, len);
    }
    return PICOKEYS_OK;
}

int file_put_data(file_t *file, const uint8_t *data, uint32_t len) {
    test_file_t *test_file = test_file_from_handle(file);
    if (!test_file || (!data && len > 0) || len > sizeof(test_file->storage)) {
        return PICOKEYS_ERR_NO_MEMORY;
    }
    if (len > 0) {
        memcpy(test_file->storage, data, len);
    }
    else {
        memset(test_file->storage, 0, sizeof(test_file->storage));
    }
    test_file->size = len;
    test_file->file.data = len > 0 ? test_file->storage : NULL;
    return PICOKEYS_OK;
}

int file_delete_no_commit(file_t *file) {
    return file_put_data(file, NULL, 0);
}

static void test_power_loss_point(void) {
    test_power_loss_event++;
    if (test_power_loss_armed && test_power_loss_event == test_power_loss_at) {
        test_power_loss_armed = false;
        longjmp(test_power_loss_env, 1);
    }
    test_persist();
}

void flash_commit(void) {
    test_power_loss_point();
}

bool flash_commit_sync(uint32_t timeout_ms) {
    (void)timeout_ms;
    test_power_loss_point();
    return true;
}

static int test_auth_start(void *ctx) {
    test_auth_context_t *auth = (test_auth_context_t *)ctx;
    auth->state[0] = 0x811c9dc5u;
    auth->state[1] = 0x9e3779b9u;
    auth->state[2] = 0x85ebca6bu;
    auth->state[3] = 0xc2b2ae35u;
    auth->active = true;
    return PICOKEYS_OK;
}

static int test_auth_update(void *ctx, const uint8_t *data, size_t len) {
    test_auth_context_t *auth = (test_auth_context_t *)ctx;
    if (!auth->active || (!data && len > 0)) {
        return PICOKEYS_EXEC_ERROR;
    }
    for (size_t i = 0; i < len; i++) {
        for (size_t word = 0; word < 4; word++) {
            auth->state[word] ^= data[i] + (uint8_t)word;
            auth->state[word] *= 0x01000193u + (uint32_t)(word * 2u);
            auth->state[word] = (auth->state[word] << 5) | (auth->state[word] >> 27);
        }
    }
    return PICOKEYS_OK;
}

static int test_auth_finish(void *ctx, uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE]) {
    test_auth_context_t *auth = (test_auth_context_t *)ctx;
    if (!auth->active || !tag) {
        return PICOKEYS_EXEC_ERROR;
    }
    for (size_t i = 0; i < 4; i++) {
        put_uint32_be(auth->state[i], tag + i * sizeof(uint32_t));
    }
    memset(auth, 0, sizeof(*auth));
    return PICOKEYS_OK;
}

static void test_auth_abort(void *ctx) {
    memset(ctx, 0, sizeof(test_auth_context_t));
}

static const file_object_authenticator_t test_auth = {
    .ctx = &test_auth_context,
    .start = test_auth_start,
    .update = test_auth_update,
    .finish = test_auth_finish,
    .abort = test_auth_abort
};

static int test_record_tag(const uint8_t nonce[FILE_OBJECT_RECORD_NONCE_SIZE], const uint8_t aad[FILE_OBJECT_RECORD_AAD_SIZE], const uint8_t *stored, size_t len, uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE]) {
    int r = test_auth_start(&test_auth_context);
    if (r == PICOKEYS_OK) {
        r = test_auth_update(&test_auth_context, &test_protector_context.key, sizeof(test_protector_context.key));
    }
    if (r == PICOKEYS_OK) {
        r = test_auth_update(&test_auth_context, nonce, FILE_OBJECT_RECORD_NONCE_SIZE);
    }
    if (r == PICOKEYS_OK) {
        r = test_auth_update(&test_auth_context, aad, FILE_OBJECT_RECORD_AAD_SIZE);
    }
    if (r == PICOKEYS_OK) {
        r = test_auth_update(&test_auth_context, stored, len);
    }
    if (r == PICOKEYS_OK) {
        r = test_auth_finish(&test_auth_context, tag);
    }
    return r;
}

static int test_record_seal(void *ctx, const file_object_record_identity_t *identity, const uint8_t nonce[FILE_OBJECT_RECORD_NONCE_SIZE], const uint8_t aad[FILE_OBJECT_RECORD_AAD_SIZE], const uint8_t *plaintext, size_t len, uint8_t *stored, uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE]) {
    const test_protector_context_t *protector = (const test_protector_context_t *)ctx;
    for (size_t i = 0; i < len; i++) {
        stored[i] = identity->protection == FILE_OBJECT_PROTECTION_AEAD_SECRET ? plaintext[i] ^ protector->key ^ nonce[i % FILE_OBJECT_RECORD_NONCE_SIZE] : plaintext[i];
    }
    return test_record_tag(nonce, aad, stored, len, tag);
}

static int test_record_unseal(void *ctx, const file_object_record_identity_t *identity, const uint8_t nonce[FILE_OBJECT_RECORD_NONCE_SIZE], const uint8_t aad[FILE_OBJECT_RECORD_AAD_SIZE], const uint8_t *stored, size_t len, const uint8_t tag[FILE_OBJECT_AUTH_TAG_SIZE], uint8_t *plaintext) {
    const test_protector_context_t *protector = (const test_protector_context_t *)ctx;
    uint8_t calculated[FILE_OBJECT_AUTH_TAG_SIZE];
    int r = test_record_tag(nonce, aad, stored, len, calculated);
    if (r == PICOKEYS_OK && memcmp(calculated, tag, sizeof(calculated)) != 0) {
        r = PICOKEYS_WRONG_SIGNATURE;
    }
    if (r == PICOKEYS_OK) {
        for (size_t i = 0; i < len; i++) {
            plaintext[i] = identity->protection == FILE_OBJECT_PROTECTION_AEAD_SECRET ? stored[i] ^ protector->key ^ nonce[i % FILE_OBJECT_RECORD_NONCE_SIZE] : stored[i];
        }
    }
    memset(calculated, 0, sizeof(calculated));
    return r;
}

static const file_object_record_protector_t test_protector = {
    .ctx = &test_protector_context,
    .seal = test_record_seal,
    .unseal = test_record_unseal
};

const file_object_authenticator_t *openpgp_object_manifest_authenticator(void) {
    return &test_auth;
}

const file_object_record_protector_t *openpgp_object_record_protector(void) {
    return &test_protector;
}

const file_object_authenticator_t *openpgp_piv_object_manifest_authenticator(void) {
    return &test_auth;
}

const file_object_record_protector_t *openpgp_piv_object_record_protector(void) {
    return &test_protector;
}

bool piv_key_operation_authorized(uint16_t operation, bool internal_firmware) {
    (void)operation;
    return internal_firmware;
}

static void test_reset(void) {
    memset(test_files, 0, sizeof(test_files));
    memset(test_durable_files, 0, sizeof(test_durable_files));
    memset(&test_auth_context, 0, sizeof(test_auth_context));
    test_power_loss_event = 0;
    test_power_loss_at = SIZE_MAX;
    test_power_loss_armed = false;
    has_pw1 = false;
    has_pw2 = false;
    has_pw3 = true;
    file_new(EF_PK_SIG);
    file_new(EF_PK_DEC);
    file_new(EF_PK_AUT);
    file_new(EF_AES_KEY);
    file_new(EF_PIV_KEY_AUTHENTICATION);
    test_persist();
}

static void test_read_pair(uint16_t fid, const uint8_t *private_data, size_t private_size, const uint8_t *public_data, size_t public_size) {
    uint8_t output[128] = { 0 };
    size_t written = 0;
    uint16_t operation = fid == EF_PK_SIG ? FILE_OBJECT_OPERATION_SIGN : FILE_OBJECT_OPERATION_USE;

    assert(private_size <= sizeof(output));
    assert(openpgp_key_container_read_private(fid, operation, false, output, sizeof(output), &written) == PICOKEYS_OK);
    assert(written == private_size);
    assert(memcmp(output, private_data, private_size) == 0);

    memset(output, 0, sizeof(output));
    written = 0;
    assert(public_size <= sizeof(output));
    assert(openpgp_key_container_read_public(fid, output, sizeof(output), &written) == PICOKEYS_OK);
    assert(written == public_size);
    assert(memcmp(output, public_data, public_size) == 0);
}

static void test_lifecycle_and_authorization(void) {
    static const uint8_t private_first[] = { 1, 2, 3, 4 };
    static const uint8_t public_first[] = { 0x7f, 0x49, 1, 2, 3 };
    static const uint8_t private_second[] = { 5, 6, 7 };
    static const uint8_t public_second[] = { 0x7f, 0x49, 4, 5 };
    uint8_t output[16];
    size_t written = 0;

    test_reset();
    has_pw3 = false;
    assert(openpgp_key_container_store(EF_PK_SIG, private_first, sizeof(private_first), public_first, sizeof(public_first), false) == PICOKEYS_NO_LOGIN);
    has_pw3 = true;
    assert(openpgp_key_container_store(EF_PK_SIG, private_first, sizeof(private_first), public_first, sizeof(public_first), false) == PICOKEYS_OK);
    assert(openpgp_key_container_is_marker(file_search(EF_PK_SIG)));
    test_read_pair(EF_PK_SIG, private_first, sizeof(private_first), public_first, sizeof(public_first));

    has_pw3 = false;
    assert(openpgp_key_container_read_private(EF_PK_SIG, FILE_OBJECT_OPERATION_SIGN, false, output, sizeof(output), &written) == PICOKEYS_NO_LOGIN);
    assert(openpgp_key_container_read_public(EF_PK_SIG, output, sizeof(output), &written) == PICOKEYS_OK);
    has_pw1 = true;
    assert(openpgp_key_container_read_private(EF_PK_SIG, FILE_OBJECT_OPERATION_SIGN, false, output, sizeof(output), &written) == PICOKEYS_OK);
    has_pw1 = false;
    has_pw3 = true;

    assert(openpgp_key_container_store(EF_PK_SIG, private_second, sizeof(private_second), public_second, sizeof(public_second), false) == PICOKEYS_OK);
    test_read_pair(EF_PK_SIG, private_second, sizeof(private_second), public_second, sizeof(public_second));
    test_reboot();
    test_read_pair(EF_PK_SIG, private_second, sizeof(private_second), public_second, sizeof(public_second));

    assert(openpgp_key_container_delete(EF_PK_SIG, false) == PICOKEYS_OK);
    assert(!file_has_data(file_search(EF_PK_SIG)));
    assert(openpgp_key_container_read_private(EF_PK_SIG, FILE_OBJECT_OPERATION_SIGN, false, output, sizeof(output), &written) == PICOKEYS_ERR_FILE_NOT_FOUND);
}

static void test_corruption_falls_back_to_previous_generation(void) {
    static const uint8_t private_first[] = { 0x11, 0x12, 0x13 };
    static const uint8_t public_first[] = { 0x21, 0x22, 0x23 };
    static const uint8_t private_second[] = { 0x31, 0x32, 0x33 };
    static const uint8_t public_second[] = { 0x41, 0x42, 0x43 };

    test_reset();
    assert(openpgp_key_container_store(EF_PK_DEC, private_first, sizeof(private_first), public_first, sizeof(public_first), false) == PICOKEYS_OK);
    assert(openpgp_key_container_store(EF_PK_DEC, private_second, sizeof(private_second), public_second, sizeof(public_second), false) == PICOKEYS_OK);

    file_t *current_private = file_search(0xd4d2u);
    assert(file_has_data(current_private));
    file_get_data(current_private)[FILE_OBJECT_RECORD_HEADER_SIZE] ^= 0x80;
    test_persist();
    test_reboot();

    uint8_t private_output[sizeof(private_first)] = { 0 };
    uint8_t public_output[sizeof(public_second)] = { 0 };
    size_t private_written = 0;
    size_t public_written = 0;
    assert(openpgp_key_container_read_private(EF_PK_DEC, FILE_OBJECT_OPERATION_USE, false, private_output, sizeof(private_output), &private_written) == PICOKEYS_OK);
    assert(openpgp_key_container_read_public(EF_PK_DEC, public_output, sizeof(public_output), &public_written) == PICOKEYS_OK);
    assert(private_written == sizeof(private_first));
    assert(public_written == sizeof(public_second));
    assert(memcmp(private_output, private_first, sizeof(private_first)) == 0);
    assert(memcmp(public_output, public_second, sizeof(public_second)) == 0);
}

static void test_collision_does_not_replace_legacy_key(void) {
    static const uint8_t legacy[] = { 0xaa, 0xbb, 0xcc };
    static const uint8_t collision[] = { 0xde, 0xad };
    static const uint8_t private_data[] = { 1, 2 };

    test_reset();
    assert(file_put_data(file_search(EF_PK_SIG), legacy, sizeof(legacy)) == PICOKEYS_OK);
    assert(file_put_data(file_new(0xd0d1u), collision, sizeof(collision)) == PICOKEYS_OK);
    test_persist();

    assert(!openpgp_key_container_can_create(EF_PK_SIG));
    assert(openpgp_key_container_store(EF_PK_SIG, private_data, sizeof(private_data), NULL, 0, false) != PICOKEYS_OK);
    assert(file_get_size(file_search(EF_PK_SIG)) == sizeof(legacy));
    assert(memcmp(file_get_data(file_search(EF_PK_SIG)), legacy, sizeof(legacy)) == 0);
    assert(!openpgp_key_container_physical_fid(0xd0d1u));
}

static void test_piv_internal_boundary(void) {
    static const uint8_t private_data[] = { 0x51, 0x52, 0x53, 0x54 };
    uint8_t output[sizeof(private_data)] = { 0 };
    size_t written = 0;

    test_reset();
    has_pw3 = false;
    assert(openpgp_key_container_store(EF_PIV_KEY_AUTHENTICATION, private_data, sizeof(private_data), NULL, 0, false) == PICOKEYS_NO_LOGIN);
    assert(openpgp_key_container_store(EF_PIV_KEY_AUTHENTICATION, private_data, sizeof(private_data), NULL, 0, true) == PICOKEYS_OK);
    assert(openpgp_key_container_is_marker(file_search(EF_PIV_KEY_AUTHENTICATION)));
    assert(openpgp_key_container_read_private(EF_PIV_KEY_AUTHENTICATION, FILE_OBJECT_OPERATION_USE, false, output, sizeof(output), &written) == PICOKEYS_NO_LOGIN);
    assert(openpgp_key_container_read_private(EF_PIV_KEY_AUTHENTICATION, FILE_OBJECT_OPERATION_USE, true, output, sizeof(output), &written) == PICOKEYS_OK);
    assert(written == sizeof(private_data));
    assert(memcmp(output, private_data, sizeof(private_data)) == 0);
    assert(openpgp_key_container_delete(EF_PIV_KEY_AUTHENTICATION, false) == PICOKEYS_NO_LOGIN);
    assert(openpgp_key_container_delete(EF_PIV_KEY_AUTHENTICATION, true) == PICOKEYS_OK);
}

static void test_power_loss_create(void) {
    static const uint8_t legacy[] = { 0x91, 0x92, 0x93 };
    static const uint8_t private_data[] = { 1, 3, 5, 7 };
    static const uint8_t public_data[] = { 2, 4, 6, 8 };

    for (size_t event = 1; event <= 3; event++) {
        test_reset();
        assert(file_put_data(file_search(EF_PK_AUT), legacy, sizeof(legacy)) == PICOKEYS_OK);
        test_persist();
        test_power_loss_event = 0;
        test_power_loss_at = event;
        test_power_loss_armed = true;
        if (setjmp(test_power_loss_env) == 0) {
            (void)openpgp_key_container_store(EF_PK_AUT, private_data, sizeof(private_data), public_data, sizeof(public_data), false);
        }
        test_reboot();

        if (openpgp_key_container_is_marker(file_search(EF_PK_AUT))) {
            test_read_pair(EF_PK_AUT, private_data, sizeof(private_data), public_data, sizeof(public_data));
        }
        else {
            assert(file_get_size(file_search(EF_PK_AUT)) == sizeof(legacy));
            assert(memcmp(file_get_data(file_search(EF_PK_AUT)), legacy, sizeof(legacy)) == 0);
            assert(openpgp_key_container_store(EF_PK_AUT, private_data, sizeof(private_data), public_data, sizeof(public_data), false) == PICOKEYS_OK);
            test_read_pair(EF_PK_AUT, private_data, sizeof(private_data), public_data, sizeof(public_data));
        }
    }
}

static void test_power_loss_update(void) {
    static const uint8_t private_first[] = { 1, 1, 1 };
    static const uint8_t public_first[] = { 2, 2, 2 };
    static const uint8_t private_second[] = { 3, 3, 3 };
    static const uint8_t public_second[] = { 4, 4, 4 };

    for (size_t event = 1; event <= 2; event++) {
        test_reset();
        assert(openpgp_key_container_store(EF_PK_SIG, private_first, sizeof(private_first), public_first, sizeof(public_first), false) == PICOKEYS_OK);
        test_power_loss_event = 0;
        test_power_loss_at = event;
        test_power_loss_armed = true;
        if (setjmp(test_power_loss_env) == 0) {
            (void)openpgp_key_container_store(EF_PK_SIG, private_second, sizeof(private_second), public_second, sizeof(public_second), false);
        }
        test_reboot();

        uint8_t private_output[sizeof(private_first)] = { 0 };
        uint8_t public_output[sizeof(public_first)] = { 0 };
        size_t private_written = 0;
        size_t public_written = 0;
        assert(openpgp_key_container_read_private(EF_PK_SIG, FILE_OBJECT_OPERATION_SIGN, false, private_output, sizeof(private_output), &private_written) == PICOKEYS_OK);
        assert(openpgp_key_container_read_public(EF_PK_SIG, public_output, sizeof(public_output), &public_written) == PICOKEYS_OK);
        bool old_pair = memcmp(private_output, private_first, sizeof(private_first)) == 0 && memcmp(public_output, public_first, sizeof(public_first)) == 0;
        bool new_pair = memcmp(private_output, private_second, sizeof(private_second)) == 0 && memcmp(public_output, public_second, sizeof(public_second)) == 0;
        assert(old_pair || new_pair);
    }
}

int main(void) {
    test_lifecycle_and_authorization();
    test_corruption_falls_back_to_previous_generation();
    test_collision_does_not_replace_legacy_key();
    test_piv_internal_boundary();
    test_power_loss_create();
    test_power_loss_update();
    puts("openpgp_key_container_test: ok");
    return 0;
}
