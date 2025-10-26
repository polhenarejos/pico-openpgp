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
#include "asn1.h"

int cmd_get_data() {
    if (apdu.nc > 0) {
        return SW_WRONG_LENGTH();
    }
    uint16_t fid = (P1(apdu) << 8) | P2(apdu);
    file_t *ef;
    if (!(ef = search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!authenticate_action(ef, ACL_OP_READ_SEARCH)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (currentEF && (currentEF->fid & 0x1FF0) == (fid & 0x1FF0)) { //previously selected
        ef = currentEF;
    }
    else {
        select_file(ef);
    }
    if (ef->data) {
        uint16_t fids[] = { 1, fid };
        uint16_t data_len = parse_do(fids, 1);
        uint8_t *p = NULL;
        uint16_t tg = 0;
        uint16_t tg_len = 0;
        asn1_ctx_t ctxi;
        asn1_ctx_init(res_APDU, data_len, &ctxi);
        if (walk_tlv(&ctxi, &p, &tg, &tg_len, NULL)) {
            uint8_t dec = 2;
            if ((tg & 0x1f) == 0x1f) {
                dec++;
            }
            if ((res_APDU[dec - 1] & 0xF0) == 0x80) {
                dec += (res_APDU[dec - 1] & 0x0F);
            }
            if (tg_len + dec == data_len) {
                memmove(res_APDU, res_APDU + dec, data_len - dec);
                data_len -= dec;
                res_APDU_size -= dec;
            }
        }
        //if (apdu.ne > data_len)
        //    apdu.ne = data_len;
    }
    return SW_OK();
}

int cmd_get_next_data() {
    file_t *ef = NULL;
    if (apdu.nc > 0) {
        return SW_WRONG_LENGTH();
    }
    if (!currentEF) {
        return SW_RECORD_NOT_FOUND();
    }
    uint16_t fid = (P1(apdu) << 8) | P2(apdu);
    if (!(ef = search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (!authenticate_action(ef, ACL_OP_UPDATE_ERASE)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if ((currentEF->fid & 0x1FF0) != (fid & 0x1FF0)) {
        return SW_WRONG_P1P2();
    }
    fid = currentEF->fid + 1; //curentEF contains private DO. so, we select the next one
    if (!(ef = search_by_fid(fid, NULL, SPECIFY_EF))) {
        return SW_REFERENCE_NOT_FOUND();
    }
    select_file(ef);
    return cmd_get_data();
}
