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
#include "files.h"
#include "eac.h"

uint8_t openpgp_aid[] = {
    6, 
    0xD2,0x76,0x00,0x01,0x24,0x01,
};

uint8_t openpgp_aid_full[] = {
    16,00, 
    0xD2,0x76,0x00,0x01,0x24,0x01,
    OPGP_VERSION_MAJOR,OPGP_VERSION_MINOR,0xff,0xfe,0xff,0xff,0xff,0xff,0x00,0x00
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

void scan_files() {
    file_t *ef;
    if ((ef = search_by_fid(EF_FULL_AID, NULL, SPECIFY_ANY))) {
        ef->data = openpgp_aid_full;
        pico_get_unique_board_id_string(ef->data+12, 4);
    }
}

void init_openpgp() {
    isUserAuthenticated = false;
    scan_files();
    cmd_select();
}

int openpgp_unload() {
    isUserAuthenticated = false;
    return CCID_OK;
}

app_t *openpgp_select_aid(app_t *a) {
    if (!memcmp(apdu.cmd_apdu_data, openpgp_aid+1, openpgp_aid[0])) {
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

int parse_do(uint16_t *fids, int mode) {
    int len = 0;
    file_t *ef;
    for (int i = 0; i < fids[0]; i++) {
        if ((ef = search_by_fid(fids[i+1], NULL, SPECIFY_EF)) && ef->data) {
            uint16_t data_len;
            if ((ef->type & FILE_DATA_FUNC) == FILE_DATA_FUNC) {
                data_len = ((int (*)(const file_t *, int))(ef->data))((const file_t *)ef, 1);
            }
            else {
                data_len = file_read_uint16(ef->data);
                if (mode == 1) {
                    if (fids[0] > 1) {
                        if (fids[i+1] < 0x0100) {
                            res_APDU[res_APDU_size++] = fids[i+1] & 0xff;
                        }
                        else {
                            res_APDU[res_APDU_size++] = fids[i+1] >> 8;
                            res_APDU[res_APDU_size++] = fids[i+1] & 0xff;
                        }
                        res_APDU_size += format_tlv_len(data_len, res_APDU);
                    }
                    memcpy(res_APDU+res_APDU_size, file_read(ef->data+2), data_len);
                    res_APDU_size += data_len;
                }
            }
            len += data_len;
        }
    }
    return len;
}

int parse_trium(uint16_t fid, uint8_t num, size_t size) {
    for (uint8_t i = 0; i < num; i++) {
        file_t *ef;
        if ((ef = search_by_fid(fid+i, NULL, SPECIFY_EF)) && ef->data) {
            uint16_t data_len = file_read_uint16(ef->data);
            memcpy(res_APDU+res_APDU_size, file_read(ef->data+2), data_len);
            res_APDU_size += data_len;
        }
        else {
            memset(res_APDU+res_APDU_size, 0, size);
            res_APDU_size += size;
        }
    }
    return num*size;
}

int parse_ch_data(const file_t *f, int mode) {
    uint16_t fids[] = {
        3,
        EF_CH_NAME, EF_LANG_PREF, EF_SEX
    };
    return parse_do(fids, mode);
}

int parse_sec_tpl(const file_t *f, int mode) {
    
}

int parse_ch_cert(const file_t *f, int mode) {
    
}

int parse_exlen_info(const file_t *f, int mode) {
    
}

int parse_gfm(const file_t *f, int mode) {
    
}

int parse_fp(const file_t *f, int mode) {
    return parse_trium(EF_FP_SIG, 3, 20);
}

int parse_cafp(const file_t *f, int mode) {
    return parse_trium(EF_FP_CA1, 3, 20);
}

int parse_ts(const file_t *f, int mode) {
    return parse_trium(EF_TS_SIG, 3, 4);    
}

int parse_keyinfo(const file_t *f, int mode) {
    
}

int parse_algoinfo(const file_t *f, int mode) {
    
}

int parse_app_data(const file_t *f, int mode) {
    uint16_t fids[] = {
        5,
        EF_FULL_AID, EF_HIST_BYTES, EF_EXLEN_INFO, EF_GFM, EF_DISCRETE_DO
    };
    return parse_do(fids, mode);
}

int parse_discrete_do(const file_t *f, int mode) {
    uint16_t fids[] = {
        11,
        EF_EXT_CAP, EF_ALGO_SIG, EF_ALGO_DEC, EF_ALGO_AUT, EF_PW_STATUS, EF_FP, EF_CA_FP, EF_TS_ALL, EF_UIF_SIG, EF_UIF_DEC, EF_UIF_AUT
    };
    return parse_do(fids, mode);
}


static int cmd_get_data() {
    if (apdu.cmd_apdu_data_len > 0)
        return SW_WRONG_LENGTH();
    uint16_t fid = (P1(apdu) << 8) | P2(apdu);
    file_t *ef;
    if (!(ef = search_by_fid(fid, NULL, SPECIFY_EF)))
        return SW_FILE_NOT_FOUND();
    if (!authenticate_action(ef, ACL_OP_READ_SEARCH)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (ef->data) {
        uint16_t fids[] = {1,fid};
        uint16_t data_len = parse_do(fids, 1);
        if (apdu.expected_res_size > data_len)
            apdu.expected_res_size = data_len;
    }

    return SW_OK();
}

typedef struct cmd
{
  uint8_t ins;
  int (*cmd_handler)();
} cmd_t;

#define INS_SELECT          0xA4
#define INS_GET_DATA        0xCA

static const cmd_t cmds[] = {
    { INS_GET_DATA, cmd_get_data },
    { INS_SELECT, cmd_select },
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