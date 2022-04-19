/* 
 * This file is part of the Pico OpenPGP distribution (https://github.com/polhenarejos/pico-openpgp).
 * Copyright (c) 2022 Pol Henarejos.
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "openpgp.h"
#include "version.h"
#include "eac.h"

const uint8_t openpgp_aid[] = {
    6, 
    0xD2,0x76,0x00,0x01,0x24,0x01
};

char atr_openpgp[] = { 
    21,
    0x3b,0xda,0x18,0xff,0x81,0xb1,0xfe,0x75,0x1f,0x03,0x00,0x31,0xf5,0x73,0xc0,0x01,0x60,0x00,0x90,0x00,0x1c
};

int openpgp_process_apdu();

void select_file(file_t *pe) {
    if (!pe)
    {
        currentDF = (file_t *)MF;
        currentEF = NULL;
    }
    else if (pe->type & FILE_TYPE_INTERNAL_EF) {
        currentEF = pe;
        currentDF = &file_entries[pe->parent];
    }
    else {
        currentDF = pe;
    }
    if (currentEF == file_openpgp) {
        selected_applet = currentEF;
        //sc_hsm_unload(); //reset auth status
    }
}

static int cmd_select() {
    uint8_t p1 = P1(apdu);
    uint8_t p2 = P2(apdu);
    file_t *pe = NULL;
    uint16_t fid = 0x0;
    
    // Only "first or only occurence" supported 
    //if ((p2 & 0xF3) != 0x00) {
    //    return SW_INCORRECT_P1P2();
    //}
    
    if (apdu.cmd_apdu_data_len >= 2)
        fid = get_uint16_t(apdu.cmd_apdu_data, 0);
        
    //if ((fid & 0xff00) == (KEY_PREFIX << 8))
    //    fid = (PRKD_PREFIX << 8) | (fid & 0xff);
    
    if (!pe) {
        if (p1 == 0x0) { //Select MF, DF or EF - File identifier or absent
            if (apdu.cmd_apdu_data_len == 0) {
            	pe = (file_t *)MF;
            	//ac_fini();
            }
            else if (apdu.cmd_apdu_data_len == 2) {
                if (!(pe = search_by_fid(fid, NULL, SPECIFY_ANY))) {
                    return SW_FILE_NOT_FOUND();
                }
            }
        }
        else if (p1 == 0x01) { //Select child DF - DF identifier
            if (!(pe = search_by_fid(fid, currentDF, SPECIFY_DF))) {
                return SW_FILE_NOT_FOUND();
            }
        }
        else if (p1 == 0x02) { //Select EF under the current DF - EF identifier
            if (!(pe = search_by_fid(fid, currentDF, SPECIFY_EF))) {
                return SW_FILE_NOT_FOUND();
            }
        }
        else if (p1 == 0x03) { //Select parent DF of the current DF - Absent
            if (apdu.cmd_apdu_data_len != 0)
                return SW_FILE_NOT_FOUND();
        }
        else if (p1 == 0x04) { //Select by DF name - e.g., [truncated] application identifier
            if (!(pe = search_by_name(apdu.cmd_apdu_data, apdu.cmd_apdu_data_len))) {
                return SW_FILE_NOT_FOUND();
            }
            if (card_terminated) {
                return set_res_sw (0x62, 0x85);
            }        
        }
        else if (p1 == 0x08) { //Select from the MF - Path without the MF identifier
            if (!(pe = search_by_path(apdu.cmd_apdu_data, apdu.cmd_apdu_data_len, MF))) {
                return SW_FILE_NOT_FOUND();
            }
        }
        else if (p1 == 0x09) { //Select from the current DF - Path without the current DF identifier
            if (!(pe = search_by_path(apdu.cmd_apdu_data, apdu.cmd_apdu_data_len, currentDF))) {
                return SW_FILE_NOT_FOUND();
            }
        }
    }
    if ((p2 & 0xfc) == 0x00 || (p2 & 0xfc) == 0x04) {
        process_fci(pe);
    }
    else
        return SW_INCORRECT_P1P2();
    select_file(pe);
    return SW_OK ();
}

void init_openpgp() {
    isUserAuthenticated = false;
    cmd_select();
}

int openpgp_unload() {
    isUserAuthenticated = false;
    return CCID_OK;
}

app_t *openpgp_select_aid(app_t *a) {
    printf("AIDS \r\n");
    DEBUG_PAYLOAD(apdu.cmd_apdu_data,apdu.cmd_apdu_data_len);
    DEBUG_PAYLOAD(openpgp_aid+1,openpgp_aid[0]);
    if (!memcmp(apdu.cmd_apdu_data, openpgp_aid+1, MIN(apdu.cmd_apdu_data_len,openpgp_aid[0]))) {
        printf("SELECTING OPENPGP\r\n");
        a->aid = openpgp_aid;
        a->process_apdu = openpgp_process_apdu;
        a->unload = openpgp_unload;
        init_openpgp();
        return a;
    }
    return NULL;
}

void __attribute__ ((constructor)) openpgp_ctor() { 
    ccid_atr = atr_openpgp;
    register_app(openpgp_select_aid);
}

typedef struct cmd
{
  uint8_t ins;
  int (*cmd_handler)();
} cmd_t;

static const cmd_t cmds[] = {
    { 0x00, 0x0}
};

int openpgp_process_apdu() {
    int r = sm_unwrap();
    for (const cmd_t *cmd = cmds; cmd->ins != 0x00; cmd++) {
        if (cmd->ins == INS(apdu)) {
            int r = cmd->cmd_handler();
            sm_wrap();
            return r;
        }
    }
    return SW_INS_NOT_SUPPORTED();
}