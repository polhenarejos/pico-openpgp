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

static bool pw3_verifier_unusable(void) {
    file_t *pw3 = file_search_by_fid(EF_PW3, NULL, SPECIFY_EF);
    return !pw3 || !file_has_data(pw3) || file_get_size(pw3) < 3 || file_get_data(pw3)[0] == 0;
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
    /* The flash reset is global; do not erase a provisioned PIV application. */
    file_t *piv_dek = file_search_by_fid(EF_DEK_PWPIV, NULL, SPECIFY_EF);
    if (piv_dek && file_has_data(piv_dek)) {
        return SW_FUNC_NOT_SUPPORTED();
    }
    file_initialize_flash(true);
    scan_files_openpgp();
    return SW_OK();
}
