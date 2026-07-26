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
#include "crypto_utils.h"
#include "object_crypto_provider.h"
#include "object_provider.h"
#include "openpgp.h"

static file_object_crypto_provider_t openpgp_object_crypto_provider;
static file_object_crypto_provider_t openpgp_piv_object_crypto_provider;
static bool openpgp_object_crypto_provider_initialized;
static bool openpgp_piv_object_crypto_provider_initialized;

static int openpgp_object_root_load(void *ctx, uint8_t root[FILE_OBJECT_CRYPTO_ROOT_KEY_SIZE]) {
    (void)ctx;

    int r = load_dek();
    if (r == PICOKEYS_OK) {
        memcpy(root, dek + IV_SIZE, FILE_OBJECT_CRYPTO_ROOT_KEY_SIZE);
    }
    release_dek();
    return r;
}

static int openpgp_object_public_root_load(void *ctx, uint8_t root[FILE_OBJECT_CRYPTO_ROOT_KEY_SIZE]) {
    (void)ctx;

    derive_kbase(root);
    return PICOKEYS_OK;
}

static bool openpgp_object_identity_valid(void *ctx, const file_object_record_identity_t *identity) {
    (void)ctx;

    return identity->key_domain == 0;
}

static bool openpgp_piv_object_identity_valid(void *ctx, const file_object_record_identity_t *identity) {
    (void)ctx;

    return identity->key_domain == 1;
}

static int openpgp_object_crypto_provider_init(void) {
    if (openpgp_object_crypto_provider_initialized) {
        return PICOKEYS_OK;
    }

    const file_object_crypto_provider_config_t config = {
        .namespace_id = OPENPGP_OBJECT_NAMESPACE,
        .load_root = openpgp_object_root_load,
        .load_public_root = openpgp_object_public_root_load,
        .identity_valid = openpgp_object_identity_valid
    };
    int r = file_object_crypto_provider_init(&openpgp_object_crypto_provider, &config);
    if (r == PICOKEYS_OK) {
        openpgp_object_crypto_provider_initialized = true;
    }
    return r;
}

static int openpgp_piv_object_crypto_provider_init(void) {
    if (openpgp_piv_object_crypto_provider_initialized) {
        return PICOKEYS_OK;
    }

    const file_object_crypto_provider_config_t config = {
        .namespace_id = OPENPGP_OBJECT_NAMESPACE,
        .load_root = openpgp_object_public_root_load,
        .load_public_root = openpgp_object_public_root_load,
        .identity_valid = openpgp_piv_object_identity_valid
    };
    int r = file_object_crypto_provider_init(&openpgp_piv_object_crypto_provider, &config);
    if (r == PICOKEYS_OK) {
        openpgp_piv_object_crypto_provider_initialized = true;
    }
    return r;
}

const file_object_authenticator_t *openpgp_object_manifest_authenticator(void) {
    if (openpgp_object_crypto_provider_init() != PICOKEYS_OK) {
        return NULL;
    }
    return file_object_crypto_manifest_authenticator(&openpgp_object_crypto_provider);
}

const file_object_record_protector_t *openpgp_object_record_protector(void) {
    if (openpgp_object_crypto_provider_init() != PICOKEYS_OK) {
        return NULL;
    }
    return file_object_crypto_record_protector(&openpgp_object_crypto_provider);
}

const file_object_authenticator_t *openpgp_piv_object_manifest_authenticator(void) {
    if (openpgp_piv_object_crypto_provider_init() != PICOKEYS_OK) {
        return NULL;
    }
    return file_object_crypto_manifest_authenticator(&openpgp_piv_object_crypto_provider);
}

const file_object_record_protector_t *openpgp_piv_object_record_protector(void) {
    if (openpgp_piv_object_crypto_provider_init() != PICOKEYS_OK) {
        return NULL;
    }
    return file_object_crypto_record_protector(&openpgp_piv_object_crypto_provider);
}
