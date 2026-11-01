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

static bool openpgp_terminate_defer_fid(uint16_t fid) {
    return fid == EF_PW1 || fid == EF_RC || fid == EF_PW3 || fid == EF_PW_PRIV || fid == EF_PW_RETRIES || fid == EF_UIF_SIG || fid == EF_UIF_DEC || fid == EF_UIF_AUT || fid == EF_KDF || fid == EF_SIG_COUNT || fid == EF_SEX;
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

typedef struct openpgp_terminate_clear_context {
    int value;
    int metadata;
    bool deferred;
} openpgp_terminate_clear_context_t;

static bool openpgp_terminate_clear_dynamic(file_t *file, void *ctx) {
    openpgp_terminate_clear_context_t *context = (openpgp_terminate_clear_context_t *)ctx;
    if (openpgp_terminate_preserve_file(file)) {
        return true;
    }
    if (openpgp_terminate_defer_fid(file->fid) != context->deferred) {
        return true;
    }
    file_delete_result_t result = file_delete_no_commit_parts(file);
    if (context->metadata == PICOKEYS_OK && result.metadata != PICOKEYS_OK) {
        context->metadata = result.metadata;
    }
    if (result.value != PICOKEYS_OK) {
        context->value = result.value;
        return false;
    }
    return true;
}

static int openpgp_terminate_clear_storage(void) {
    openpgp_terminate_clear_context_t context = {
        .value = PICOKEYS_OK,
        .metadata = PICOKEYS_OK,
        .deferred = false
    };
    int r = openpgp_vault_clear_openpgp();
    if (r != PICOKEYS_OK) {
        context.value = r;
    }
    else {
        for (uint8_t phase = 0; phase < 2 && context.value == PICOKEYS_OK; phase++) {
            context.deferred = phase != 0;
            for (file_entry_t *entry = file_entries; entry != file_last; entry++) {
                file_t *file = &entry->file;
                if (file->fid == 0 || openpgp_terminate_preserve_file(file) || openpgp_terminate_defer_fid(file->fid) != context.deferred || !(file_get_type(file) & FILE_DATA_FLASH)) {
                    continue;
                }
                file_delete_result_t result = file_delete_no_commit_parts(file);
                if (context.metadata == PICOKEYS_OK && result.metadata != PICOKEYS_OK) {
                    context.metadata = result.metadata;
                }
                if (result.value != PICOKEYS_OK) {
                    context.value = result.value;
                    break;
                }
            }
            if (context.value == PICOKEYS_OK) {
                file_for_each_dynamic(openpgp_terminate_clear_dynamic, &context);
            }
        }
    }

    /*
     * EF_PW_PRIV is kept because PIV shares it (bytes 7-8), but its OpenPGP retry counters
     * (bytes 4-6: PW1, RC, PW3) were left as they were. After the PIN blocking that precedes a
     * factory reset they were 0, so the OpenPGP card stayed blocked forever. Reset them to the
     * factory values (3, 0, 3) without touching the PIV ones.
     */
    if (context.value == PICOKEYS_OK) {
        file_t *pw_status = file_search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF);
        if (pw_status && file_has_data(pw_status) && file_get_size(pw_status) >= 7 && file_get_size(pw_status) <= 16) {
            uint8_t status[16];
            uint16_t status_len = file_get_size(pw_status);
            memcpy(status, file_get_data(pw_status), status_len);
            status[4] = 3;
            status[5] = 0;
            status[6] = 3;
            file_put_data(pw_status, CONST_BYTE_ARRAY(status, status_len));
        }
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
    return context.value != PICOKEYS_OK ? context.value : context.metadata;
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
