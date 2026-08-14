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
#include "tlv.h"

extern bool is_gpg;

int cmd_get_data(void) {
    if (apdu.nc > 0) {
        return SW_WRONG_LENGTH();
    }
    res_APDU_size = 0;
    uint16_t fid = (P1(apdu) << 8) | P2(apdu);
    uint16_t requested_fid = fid;
    file_t *ef;
    if (!(ef = file_search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (fid == EF_PRIV_DO_3) {
        if (!has_pw2) {
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
    }
    else if (fid == EF_PRIV_DO_4) {
        if (!has_pw3) {
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
    }
    else if (!file_authenticate_action(ef, ACL_OP_READ_SEARCH)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (fid == EF_CH_CERT) {
        if (currentEF && currentEF->fid >= EF_CH_1 && currentEF->fid <= EF_CH_3) {
            ef = currentEF;
        }
        else if (!(ef = file_search_by_fid(EF_CH_1, NULL, SPECIFY_EF))) {
            return SW_REFERENCE_NOT_FOUND();
        }
    }
    else if (currentEF && currentEF->fid == fid) { // previously selected same EF
        ef = currentEF;
    }
    else {
        select_file(ef);
    }
    if (ef->data) {
        if (requested_fid == EF_PW_STATUS || requested_fid == EF_HIST_BYTES ||
            requested_fid == EF_FULL_AID || requested_fid == EF_SEC_TPL) {
            is_gpg = true;
        }
        uint16_t fids[] = { 1, ef->fid };
        uint16_t data_len = parse_do(fids, 1);
        data_len = MIN(data_len, res_APDU_size);
        if (!(file_get_type(ef) & FILE_DATA_FLASH)) {
            uint8_t *p = NULL;
            tlv_item_t item;
            tlv_ctx_t ctxi;
            tlv_ctx_init(BYTE_ARRAY(res_APDU, data_len), &ctxi);
            if (tlv_walk(&ctxi, &p, &item)) {
                uint8_t dec = 2;
                if ((item.tag & 0x1f) == 0x1f) {
                    dec++;
                }
                if ((res_APDU[dec - 1] & 0xF0) == 0x80) {
                    dec += (res_APDU[dec - 1] & 0x0F);
                }
                if (item.value.len + dec == data_len) {
                    memmove(res_APDU, res_APDU + dec, data_len - dec);
                    data_len -= dec;
                    res_APDU_size -= dec;
                }
            }
        }
        if (is_gpg == false) {
            uint8_t off = 2;
            if (P1(apdu) > 0x0) {
                off++;
            }
            if (data_len >= 128) {
                off++;
            }
            if (data_len >= 256) {
                off++;
            }
            data_len = MIN(data_len, OPENPGP_MAX_RESPONSE_SIZE - off);
            res_APDU_size = data_len;
            memmove(res_APDU + off, res_APDU, data_len);
            off = 0;
            if (P1(apdu) > 0x0) {
                res_APDU[off++] = P1(apdu);
                res_APDU[off++] = P2(apdu);
            }
            else {
                res_APDU[off++] = P2(apdu);
            }
            if (data_len >= 256) {
                res_APDU[off++] = 0x82;
                res_APDU[off++] = (data_len >> 8) & 0xff;
                res_APDU[off++] = data_len & 0xff;
            }
            else if (data_len >= 128) {
                res_APDU[off++] = 0x81;
                res_APDU[off++] = data_len;
            }
            else {
                res_APDU[off++] = data_len;
            }
            res_APDU_size += off;
        }
        // if (apdu.ne > data_len)
        //     apdu.ne = data_len;
    }
    return SW_OK();
}

int cmd_get_next_data(void) {
    file_t *ef = NULL;
    if (apdu.nc > 0) {
        return SW_WRONG_LENGTH();
    }
    if (!currentEF) {
        return SW_RECORD_NOT_FOUND();
    }
    uint16_t fid = (P1(apdu) << 8) | P2(apdu);
    if (!(ef = file_search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!file_authenticate_action(ef, ACL_OP_UPDATE_ERASE)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if ((currentEF->fid & 0x1FF0) != (fid & 0x1FF0)) {
        return SW_WRONG_P1P2();
    }
    fid = currentEF->fid + 1; //curentEF contains private DO. so, we select the next one
    if (!(ef = file_search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    select_file(ef);
    return cmd_get_data();
}

int cmd_get_bulk_data(void) {
    if (apdu.nc < 3) {
        return SW_WRONG_LENGTH();
    }
    return bulk_cmd(cmd_get_data);
}
