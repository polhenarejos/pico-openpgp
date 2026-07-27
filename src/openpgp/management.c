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

#include <stdio.h>
#include "picokeys.h"
#include "serial.h"
#include "apdu.h"
#include "version.h"
#include "files.h"
#include "tlv.h"
#include "management.h"

bool is_gpg = true;

static int man_process_apdu(void);
static int man_unload(void);

const uint8_t man_aid[] = {
    8,
    0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17
};

extern void init_piv(void);
static int man_select(app_t *a, uint8_t force) {
    (void) force;
    a->process_apdu = man_process_apdu;
    a->unload = man_unload;
    sprintf((char *) res_APDU, "%d.%d.0", PIV_VERSION_MAJOR, PIV_VERSION_MINOR);
    res_APDU_size = strlen((char *) res_APDU);
    apdu.ne = res_APDU_size;
    init_piv();
    is_gpg = false;
    return PICOKEYS_OK;
}

INITIALIZER( man_ctor ) {
    register_app(man_select, man_aid);
}

static int man_unload(void) {
    return PICOKEYS_OK;
}

bool cap_supported(uint16_t cap) {
    file_t *ef = file_search(EF_DEV_CONF);
    if (file_has_data(ef)) {
        uint8_t *p = NULL;
        tlv_item_t item;
        tlv_ctx_t ctxi;
        tlv_ctx_init(BYTE_ARRAY(file_get_data(ef), file_get_size(ef)), &ctxi);
        while (tlv_walk(&ctxi, &p, &item)) {
            if (item.tag == TAG_USB_ENABLED) {
                uint16_t ecaps = item.value.data[0];
                if (item.value.len == 2) {
                    ecaps = (item.value.data[0] << 8) | item.value.data[1];
                }
                return ecaps & cap;
            }
        }
    }
    return true;
}

int man_get_config(void) {
    file_t *ef = file_search(EF_DEV_CONF);
    res_APDU_size = 0;
    res_APDU[res_APDU_size++] = 0; // Overall length. Filled later
    res_APDU[res_APDU_size++] = TAG_USB_SUPPORTED;
    res_APDU[res_APDU_size++] = 1;
    res_APDU[res_APDU_size++] = CAP_PIV | CAP_OPENPGP;
    res_APDU[res_APDU_size++] = TAG_SERIAL;
    res_APDU[res_APDU_size++] = 4;
    memcpy(res_APDU + res_APDU_size, pico_serial.id, 4);
    res_APDU_size += 4;
    res_APDU[res_APDU_size++] = TAG_FORM_FACTOR;
    res_APDU[res_APDU_size++] = 1;
    res_APDU[res_APDU_size++] = 0x01;
    res_APDU[res_APDU_size++] = TAG_VERSION;
    res_APDU[res_APDU_size++] = 3;
    res_APDU[res_APDU_size++] = PIV_VERSION_MAJOR;
    res_APDU[res_APDU_size++] = PIV_VERSION_MINOR;
    res_APDU[res_APDU_size++] = 0;
    res_APDU[res_APDU_size++] = TAG_NFC_SUPPORTED;
    res_APDU[res_APDU_size++] = 1;
    res_APDU[res_APDU_size++] = 0x00;
    if (!file_has_data(ef)) {
        res_APDU[res_APDU_size++] = TAG_USB_ENABLED;
        res_APDU[res_APDU_size++] = 1;
        res_APDU[res_APDU_size++] = CAP_PIV | CAP_OPENPGP;
        res_APDU[res_APDU_size++] = TAG_DEVICE_FLAGS;
        res_APDU[res_APDU_size++] = 1;
        res_APDU[res_APDU_size++] = FLAG_EJECT;
        res_APDU[res_APDU_size++] = TAG_CONFIG_LOCK;
        res_APDU[res_APDU_size++] = 1;
        res_APDU[res_APDU_size++] = 0x00;
        res_APDU[res_APDU_size++] = TAG_NFC_ENABLED;
        res_APDU[res_APDU_size++] = 1;
        res_APDU[res_APDU_size++] = 0x00;
    }
    else {
        memcpy(res_APDU + res_APDU_size, file_get_data(ef), file_get_size(ef));
        res_APDU_size += file_get_size(ef);
    }
    res_APDU[0] = res_APDU_size - 1;
    return 0;
}

static int cmd_read_config(void) {
    man_get_config();
    return SW_OK();
}

static int cmd_write_config(void) {
    if (apdu.data[0] != apdu.nc - 1) {
        return SW_WRONG_DATA();
    }
    file_t *ef = file_new(EF_DEV_CONF);
    file_put_data(ef, CONST_BYTE_ARRAY(apdu.data + 1, apdu.nc - 1));
    flash_commit();
    return SW_OK();
}

#define INS_READ_CONFIG             0x1D
#define INS_WRITE_CONFIG            0x1C

static const cmd_t cmds[] = {
    { INS_READ_CONFIG, cmd_read_config },
    { INS_WRITE_CONFIG, cmd_write_config },
    { 0x00, 0x0 }
};

static int man_process_apdu(void) {
    if (CLA(apdu) != 0x00) {
        return SW_CLA_NOT_SUPPORTED();
    }
    for (const cmd_t *cmd = cmds; cmd->ins != 0x00; cmd++) {
        if (cmd->ins == INS(apdu)) {
            int r = cmd->cmd_handler();
            return r;
        }
    }
    return SW_INS_NOT_SUPPORTED();
}
