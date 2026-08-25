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

#include "openpgp.h"
#include "key_container.h"

static bool pw3_verifier_unusable(void) {
    file_t *pw3 = file_search_by_fid(EF_PW3, NULL, SPECIFY_EF);
    return !pw3 || !file_has_data(pw3) || file_get_size(pw3) < 3 || file_get_data(pw3)[0] == 0;
}

static bool openpgp_terminate_preserve_fid(uint16_t fid) {
    if (fid == EF_PW_PRIV || fid == EF_PW_RETRIES || fid == EF_DEK_PWPIV || fid == EF_META || fid == EF_VAULT_KEY) {
        return true;
    }
    if (openpgp_key_container_is_piv(fid)) {
        return true;
    }
    if (fid == EF_PIV_DISCOVERY || fid == EF_PIV_BITGT || (fid >= EF_PIV_ADMIN_DATA && fid <= EF_PIV_MSROOTS5) || (fid >= EF_PIV_CARD_AUTH && fid <= EF_PIV_PC_REF_DATA)) {
        return true;
    }
    return false;
}

static bool openpgp_terminate_preserve_file(const file_t *file) {
    if (!file) {
        return false;
    }
    if (openpgp_key_container_physical_fid(file->fid)) {
        return openpgp_key_container_is_piv(file->fid & UINT8_MAX);
    }
    return openpgp_terminate_preserve_fid(file->fid) || (file->fid >= 0xc400 && file->fid <= 0xc9ff);
}

static int openpgp_terminate_clear_file(file_t *file) {
    if (!file || !file->data) {
        return PICOKEYS_OK;
    }
    int r = meta_delete_no_commit(file->fid);
    if (r != PICOKEYS_OK && r != PICOKEYS_ERR_FILE_NOT_FOUND) {
        return r;
    }
    return flash_clear_file(file);
}

typedef struct openpgp_terminate_clear_context {
    int result;
} openpgp_terminate_clear_context_t;

static bool openpgp_terminate_clear_dynamic(file_t *file, void *ctx) {
    openpgp_terminate_clear_context_t *context = (openpgp_terminate_clear_context_t *)ctx;
    if (openpgp_terminate_preserve_file(file)) {
        return true;
    }
    context->result = openpgp_terminate_clear_file(file);
    return context->result == PICOKEYS_OK;
}

static int openpgp_terminate_clear_storage(void) {
    int r = openpgp_vault_clear_openpgp();
    if (r != PICOKEYS_OK) {
        return r;
    }

    for (file_entry_t *entry = file_entries; entry != file_last; entry++) {
        file_t *file = &entry->file;
        if (file->fid == 0 || openpgp_terminate_preserve_file(file) || !(file_get_type(file) & FILE_DATA_FLASH)) {
            continue;
        }
        r = openpgp_terminate_clear_file(file);
        if (r != PICOKEYS_OK) {
            return r;
        }
    }

    openpgp_terminate_clear_context_t context = { .result = PICOKEYS_OK };
    file_for_each_dynamic(openpgp_terminate_clear_dynamic, &context);
    if (context.result != PICOKEYS_OK) {
        return context.result;
    }

    flash_commit();
    file_initialize_flash(false);
    scan_files_openpgp();
    has_pw1 = false;
    has_pw2 = false;
    has_pw3 = false;
    has_rc = false;
    mbedtls_platform_zeroize(session_pw1, sizeof(session_pw1));
    mbedtls_platform_zeroize(session_rc, sizeof(session_rc));
    mbedtls_platform_zeroize(session_pw3, sizeof(session_pw3));
    mbedtls_platform_zeroize(dek, sizeof(dek));
    return PICOKEYS_OK;
}

int cmd_terminate_df(void) {
    if (P1(apdu) != 0x0 || P2(apdu) != 0x0) {
        return SW_INCORRECT_P1P2();
    }
    file_t *retries;
    if (!(retries = file_search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    bool pw3_unusable = pw3_verifier_unusable();
    if (!has_pw3 && !pw3_unusable) {
        if (file_get_size(retries) <= 6) {
            return SW_MEMORY_FAILURE();
        }
        if (file_get_data(retries)[6] > 0) {
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
    }
    if (apdu.nc != 0) {
        return SW_WRONG_LENGTH();
    }
    int r = openpgp_terminate_clear_storage();
    return r == PICOKEYS_OK ? SW_OK() : r == PICOKEYS_ERR_NO_MEMORY ? SW_MEMORY_FAILURE() : SW_EXEC_ERROR();
}
