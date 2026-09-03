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

#include "piv.h"


int cmd_piv_get_data(void) {
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
