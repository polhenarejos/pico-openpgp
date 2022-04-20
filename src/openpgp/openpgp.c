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
#include "crypto_utils.h"

bool has_pw1 = false;
bool has_pw3 = false;

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
    scan_flash();
    file_t *ef;
    if ((ef = search_by_fid(EF_FULL_AID, NULL, SPECIFY_ANY))) {
        ef->data = openpgp_aid_full;
        pico_get_unique_board_id_string(ef->data+12, 4);
    }
    if ((ef = search_by_fid(EF_PW1, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            TU_LOG1("PW1 is empty. Initializing with default password\r\n");
            const uint8_t def[6] = { 0x31,0x32,0x33,0x34,0x35,0x36 };
            uint8_t dhash[33];
            dhash[0] = sizeof(def);
            double_hash_pin(def, sizeof(def), dhash+1);
            flash_write_data_to_file(ef, dhash, sizeof(dhash));
            
            ef = search_by_fid(EF_PW1_RETRIES, NULL, SPECIFY_ANY);
            if (ef && !ef->data) {
                const uint8_t retries = 3;
                flash_write_data_to_file(ef, &retries, sizeof(retries));
            }
        }
    }
    if ((ef = search_by_fid(EF_RC, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            TU_LOG1("RC is empty. Initializing with default password\r\n");
            
            const uint8_t def[8] = { 0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38 };
            uint8_t dhash[33];
            dhash[0] = sizeof(def);
            double_hash_pin(def, sizeof(def), dhash+1);
            flash_write_data_to_file(ef, dhash, sizeof(dhash));
            
            ef = search_by_fid(EF_RC_RETRIES, NULL, SPECIFY_ANY);
            if (ef && !ef->data) {
                const uint8_t retries = 3;
                flash_write_data_to_file(ef, &retries, sizeof(retries));
            }
        }
    }
    if ((ef = search_by_fid(EF_PW3, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            TU_LOG1("PW3 is empty. Initializing with default password\r\n");
            
            const uint8_t def[8] = { 0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38 };
            uint8_t dhash[33];
            dhash[0] = sizeof(def);
            double_hash_pin(def, sizeof(def), dhash+1);
            flash_write_data_to_file(ef, dhash, sizeof(dhash));
            
            ef = search_by_fid(EF_PW3_RETRIES, NULL, SPECIFY_ANY);
            if (ef && !ef->data) {
                const uint8_t retries = 3;
                flash_write_data_to_file(ef, &retries, sizeof(retries));
            }
        }
    }
    if ((ef = search_by_fid(EF_SIG_COUNT, NULL, SPECIFY_ANY))) {
        if (!ef->data) {
            TU_LOG1("SigCount is empty. Initializing to zero\r\n");
            const uint8_t def[3] = { 0 };
            flash_write_data_to_file(ef, def, sizeof(def));
        }
    }
    low_flash_available();
}

void init_openpgp() {
    isUserAuthenticated = false;
    has_pw1 = has_pw3 = false;
    scan_files();
    //cmd_select();
}

int openpgp_unload() {
    isUserAuthenticated = false;
    has_pw1 = has_pw3 = false;
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
        printf("FID %x\r\n",fids[i+1]);
        if ((ef = search_by_fid(fids[i+1], NULL, SPECIFY_EF))) {
            uint16_t data_len;
            if ((ef->type & FILE_DATA_FUNC) == FILE_DATA_FUNC) {
                data_len = ((int (*)(const file_t *, int))(ef->data))((const file_t *)ef, mode);
            }
            else {
                if (ef->data)
                    data_len = file_read_uint16(ef->data);
                else
                    data_len = 0;
                if (mode == 1) {
                    if (fids[0] > 1) {
                        if (fids[i+1] < 0x0100) {
                            res_APDU[res_APDU_size++] = fids[i+1] & 0xff;
                        }
                        else {
                            res_APDU[res_APDU_size++] = fids[i+1] >> 8;
                            res_APDU[res_APDU_size++] = fids[i+1] & 0xff;
                        }
                        res_APDU_size += format_tlv_len(data_len, res_APDU+res_APDU_size);
                    }
                    if (ef->data)
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
        EF_CH_NAME, EF_LANG_PREF, EF_SEX, 
    };
    res_APDU[res_APDU_size++] = EF_CH_DATA & 0xff;
    res_APDU[res_APDU_size++] = 0x82;
    uint8_t *lp = res_APDU+res_APDU_size;
    res_APDU_size += 2;
    uint16_t data_len = parse_do(fids, mode);
    uint16_t lpdif = res_APDU+res_APDU_size-lp-2;
    *lp++ = lpdif >> 8;
    *lp++ = lpdif & 0xff;
    return lpdif+4;
}

int parse_sec_tpl(const file_t *f, int mode) {
    res_APDU[res_APDU_size++] = EF_SEC_TPL & 0xff;
    res_APDU[res_APDU_size++] = 5;
    file_t *ef = search_by_fid(EF_SIG_COUNT, NULL, SPECIFY_ANY);
    if (ef && ef->data) {
        res_APDU[res_APDU_size++] = EF_SIG_COUNT & 0xff;
        res_APDU[res_APDU_size++] = 3;
        memcpy(res_APDU+res_APDU_size, file_read(ef->data+2), 3);
        res_APDU_size += 3;
    }
    return 5+2;
}

int parse_ch_cert(const file_t *f, int mode) {
    return 0;
}

int parse_fp(const file_t *f, int mode) {
    res_APDU[res_APDU_size++] = EF_FP & 0xff;
    res_APDU[res_APDU_size++] = 60;
    return parse_trium(EF_FP_SIG, 3, 20);
}

int parse_cafp(const file_t *f, int mode) {
    res_APDU[res_APDU_size++] = EF_CA_FP & 0xff;
    res_APDU[res_APDU_size++] = 60;
    return parse_trium(EF_FP_CA1, 3, 20);
}

int parse_ts(const file_t *f, int mode) {
    res_APDU[res_APDU_size++] = EF_TS_ALL & 0xff;
    res_APDU[res_APDU_size++] = 12;
    return parse_trium(EF_TS_SIG, 3, 4);    
}

int parse_keyinfo(const file_t *f, int mode) {
    int init_len = res_APDU_size;
    if (res_APDU_size > 0) {
        res_APDU[res_APDU_size++] = EF_KEY_INFO & 0xff;
        res_APDU[res_APDU_size++] = 6;
    }
    res_APDU[res_APDU_size++] = 0x00;
    res_APDU[res_APDU_size++] = 0x00;
    
    res_APDU[res_APDU_size++] = 0x01;
    res_APDU[res_APDU_size++] = 0x00;
    
    res_APDU[res_APDU_size++] = 0x02;
    res_APDU[res_APDU_size++] = 0x00;
    return res_APDU_size-init_len;
}

int parse_pw_status(const file_t *f, int mode) {
    file_t *ef;
    int init_len = res_APDU_size;
    if (res_APDU_size > 0) {
        res_APDU[res_APDU_size++] = EF_PW_STATUS & 0xff;
        res_APDU[res_APDU_size++] = 7;
    }
    res_APDU[res_APDU_size++] = 0x1;
    res_APDU[res_APDU_size++] = 127;
    res_APDU[res_APDU_size++] = 127;
    res_APDU[res_APDU_size++] = 127;
    ef = search_by_fid(EF_PW1_RETRIES, NULL, SPECIFY_ANY);
    if (ef && ef->data) {
        res_APDU[res_APDU_size++] = file_read_uint8(ef->data+2);
    }
    ef = search_by_fid(EF_RC_RETRIES, NULL, SPECIFY_ANY);
    if (ef && ef->data) {
        res_APDU[res_APDU_size++] = file_read_uint8(ef->data+2);
    }
    ef = search_by_fid(EF_PW3_RETRIES, NULL, SPECIFY_ANY);
    if (ef && ef->data) {
        res_APDU[res_APDU_size++] = file_read_uint8(ef->data+2);
    }
    return res_APDU_size-init_len;
}

#define ALGO_RSA   0x01
#define ALGO_ECDH  0x12
#define ALGO_ECDSA 0x13
#define ALGO_EDDSA 0x16

static const uint8_t algorithm_attr_ed448[] = {
  4,
  ALGO_EDDSA,
  /* OID of Ed448 */
  0x2b, 0x65, 0x71
};

static const uint8_t algorithm_attr_x448[] = {
  4,
  ALGO_ECDH,
  /* OID of X448 */
  0x2b, 0x65, 0x6f
};

static const uint8_t algorithm_attr_rsa2k[] = {
  6,
  ALGO_RSA,
  0x08, 0x00,	      /* Length modulus (in bit): 2048 */
  0x00, 0x20,	      /* Length exponent (in bit): 32  */
  0x00		      /* 0: Acceptable format is: P and Q */
};

static const uint8_t algorithm_attr_rsa4k[] = {
  6,
  ALGO_RSA,
  0x10, 0x00,	      /* Length modulus (in bit): 4096 */
  0x00, 0x20,	      /* Length exponent (in bit): 32  */
  0x00		      /* 0: Acceptable format is: P and Q */
};

static const uint8_t algorithm_attr_p256k1[] = {
  6,
  ALGO_ECDSA,
  0x2b, 0x81, 0x04, 0x00, 0x0a /* OID of curve secp256k1 */
};

static const uint8_t algorithm_attr_ed25519[] = {
  10,
  ALGO_EDDSA,
  /* OID of the curve Ed25519 */
  0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01
};

static const uint8_t algorithm_attr_cv25519[] = {
  11,
  ALGO_ECDH,
  /* OID of the curve Curve25519 */
  0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01
};

int parse_algo(const uint8_t *algo, uint16_t tag) {
    res_APDU[res_APDU_size++] = tag & 0xff;
    memcpy(res_APDU+res_APDU_size, algo, algo[0]+1);
    res_APDU_size += algo[0]+1;
    return algo[0]+2;
}

int parse_algoinfo(const file_t *f, int mode) {
    uint8_t *lp = NULL;
    uint8_t datalen = 0;
    if (f->fid == EF_ALGO_INFO) {
        res_APDU[res_APDU_size++] = EF_ALGO_INFO & 0xff;
        uint8_t *lp = res_APDU+res_APDU_size;
        res_APDU_size++;
    }
    if (f->fid == EF_ALGO_INFO || f->fid == EF_ALGO_SIG) {
        datalen += parse_algo(algorithm_attr_rsa2k, EF_ALGO_SIG);
        datalen += parse_algo(algorithm_attr_rsa4k, EF_ALGO_SIG);
        datalen += parse_algo(algorithm_attr_p256k1, EF_ALGO_SIG);
        datalen += parse_algo(algorithm_attr_ed25519, EF_ALGO_SIG);
        datalen += parse_algo(algorithm_attr_ed448, EF_ALGO_SIG);
    }
    if (f->fid == EF_ALGO_INFO || f->fid == EF_ALGO_DEC) {
        datalen += parse_algo(algorithm_attr_rsa2k, EF_ALGO_DEC);
        datalen += parse_algo(algorithm_attr_rsa4k, EF_ALGO_DEC);
        datalen += parse_algo(algorithm_attr_p256k1, EF_ALGO_DEC);
        datalen += parse_algo(algorithm_attr_cv25519, EF_ALGO_DEC);
        datalen += parse_algo(algorithm_attr_x448, EF_ALGO_DEC);
    }
    if (f->fid == EF_ALGO_INFO || f->fid == EF_ALGO_AUT) {
        datalen += parse_algo(algorithm_attr_rsa2k, EF_ALGO_AUT);
        datalen += parse_algo(algorithm_attr_rsa4k, EF_ALGO_AUT);
        datalen += parse_algo(algorithm_attr_p256k1, EF_ALGO_AUT);
        datalen += parse_algo(algorithm_attr_ed25519, EF_ALGO_AUT);
        datalen += parse_algo(algorithm_attr_ed448, EF_ALGO_AUT);
    }
    if (lp)
        *lp = res_APDU+res_APDU_size-lp-1;
    return lp ? *lp+2 : datalen;
}

int parse_app_data(const file_t *f, int mode) {
    uint16_t fids[] = {
        6,
        EF_FULL_AID, EF_HIST_BYTES, EF_EXLEN_INFO, EF_GFM, EF_DISCRETE_DO, EF_KEY_INFO
    };
    res_APDU[res_APDU_size++] = EF_APP_DATA & 0xff;
    res_APDU[res_APDU_size++] = 0x82;
    uint8_t *lp = res_APDU+res_APDU_size;
    res_APDU_size += 2;
    uint16_t data_len = parse_do(fids, mode);
    uint16_t lpdif = res_APDU+res_APDU_size-lp-2;
    *lp++ = lpdif >> 8;
    *lp++ = lpdif & 0xff;
    return lpdif+4;
}

int parse_discrete_do(const file_t *f, int mode) {
    uint16_t fids[] = {
        8,
        EF_EXT_CAP, EF_ALGO_SIG, EF_ALGO_DEC, EF_ALGO_AUT, EF_PW_STATUS, EF_FP, EF_CA_FP, EF_TS_ALL, //EF_UIF_SIG, EF_UIF_DEC, EF_UIF_AUT
    };
    res_APDU[res_APDU_size++] = EF_DISCRETE_DO & 0xff;
    res_APDU[res_APDU_size++] = 0x82;
    uint8_t *lp = res_APDU+res_APDU_size;
    res_APDU_size += 2;
    uint16_t data_len = parse_do(fids, mode);
    uint16_t lpdif = res_APDU+res_APDU_size-lp-2;
    *lp++ = lpdif >> 8;
    *lp++ = lpdif & 0xff;
    return lpdif+4;
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

int pin_reset_retries(const file_t *pin, bool force) {
    if (!pin)
        return CCID_ERR_NULL_PARAM; 
    const file_t *act = search_by_fid(pin->fid+3, NULL, SPECIFY_EF);
    if (!act)
        return CCID_ERR_FILE_NOT_FOUND;
    uint8_t retries = file_read_uint8(act->data+2);
    if (retries == 0 && force == false) //blocked
        return CCID_ERR_BLOCKED;
    retries = 3;
    int r = flash_write_data_to_file((file_t *)act, &retries, sizeof(retries));
    low_flash_available();
    return r;
}

int pin_wrong_retry(const file_t *pin) {
    if (!pin)
        return CCID_ERR_NULL_PARAM; 
    const file_t *act = search_by_fid(pin->fid+3, NULL, SPECIFY_EF);
    if (!act)
        return CCID_ERR_FILE_NOT_FOUND;
    uint8_t retries = file_read_uint8(act->data+2);
    if (retries > 0) {
        retries -= 1;
        int r = flash_write_data_to_file((file_t *)act, &retries, sizeof(retries));
        if (r != CCID_OK)
            return r;
        low_flash_available();
        if (retries == 0)
            return CCID_ERR_BLOCKED;
        return retries;
    }
    return CCID_ERR_BLOCKED;
}

int check_pin(const file_t *pin, const uint8_t *data, size_t len) {
    if (!pin)
        return SW_REFERENCE_NOT_FOUND();
    if (!pin->data) {
        return SW_REFERENCE_NOT_FOUND();
    }
    isUserAuthenticated = false;
    has_pw1 = has_pw3 = false;

    uint8_t dhash[32];
    double_hash_pin(data, len, dhash);
    if (sizeof(dhash) != file_read_uint16(pin->data)-1) //1 byte for pin len
        return SW_CONDITIONS_NOT_SATISFIED();
    if (memcmp(file_read(pin->data+3), dhash, sizeof(dhash)) != 0) {
        uint8_t retries;
        if ((retries = pin_wrong_retry(pin)) < CCID_OK)
            return SW_PIN_BLOCKED();
        return set_res_sw(0x63, 0xc0 | retries);
    }

    int r = pin_reset_retries(pin, false);
    if (r == CCID_ERR_BLOCKED)
        return SW_PIN_BLOCKED();
    if (r != CCID_OK)
        return SW_MEMORY_FAILURE();
    isUserAuthenticated = true;
    //hash_multi(data, len, session_pin);
    if (pin->fid == EF_PW1)
        has_pw1 = true;
    else if (pin->fid == EF_PW3)
        has_pw3 = true;
    return SW_OK();
}

static int cmd_verify() {
    uint8_t p1 = P1(apdu);
    uint8_t p2 = P2(apdu);
    
    if (p1 != 0x0 || (p2 & 0x60) != 0x0)
        return SW_WRONG_P1P2();
    uint8_t qualifier = p2&0x1f;
    uint16_t fid = 0x1000 | p2;
    file_t *pw, *retries;
    if (!(pw = search_by_fid(fid, NULL, SPECIFY_EF)))
        return SW_REFERENCE_NOT_FOUND();
    if (!(retries = search_by_fid(fid+3, NULL, SPECIFY_EF)))
        return SW_REFERENCE_NOT_FOUND();
    if (file_read_uint8(pw->data+2) == 0) //not initialized
        return SW_REFERENCE_NOT_FOUND();
    if (apdu.cmd_apdu_data_len > 0) {
        return check_pin(pw, apdu.cmd_apdu_data, apdu.cmd_apdu_data_len);
    }
    if (file_read_uint8(retries->data+2) == 0)
        return SW_PIN_BLOCKED();
    return set_res_sw(0x63, 0xc0 | file_read_uint8(retries->data+2));
}

static int cmd_put_data() {
    uint16_t fid = (P1(apdu) << 8) | P2(apdu);
    file_t *ef;
    if (fid == EF_RESET_CODE)
        fid = EF_RC;
    if (!(ef = search_by_fid(fid, NULL, SPECIFY_EF)))
        return SW_FILE_NOT_FOUND();
    if (!authenticate_action(ef, ACL_OP_UPDATE_ERASE)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (apdu.cmd_apdu_data_len > 0) {
        int r = flash_write_data_to_file(ef, apdu.cmd_apdu_data, apdu.cmd_apdu_data_len);
        if (r != CCID_OK)
            return SW_MEMORY_FAILURE();
        low_flash_available();
    }
    return SW_OK();
}

static int cmd_change_pin() {
    if (P1(apdu) != 0x0)
        return SW_WRONG_P1P2();
    uint16_t fid = 0x1000 | P2(apdu);
    file_t *pw;
    if (!(pw = search_by_fid(fid, NULL, SPECIFY_EF)))
        return SW_REFERENCE_NOT_FOUND();
    uint8_t pin_len = file_read_uint8(pw->data+2);
    uint16_t r = check_pin(pw, apdu.cmd_apdu_data, pin_len);
    if (r != 0x9000)
        return r;
    uint8_t dhash[33];
    dhash[0] = apdu.cmd_apdu_data_len-pin_len;
    double_hash_pin(apdu.cmd_apdu_data+pin_len, apdu.cmd_apdu_data_len-pin_len, dhash+1);
    flash_write_data_to_file(pw, dhash, sizeof(dhash));
    low_flash_available();
    return SW_OK();
}

static int cmd_reset_retry() {
    if (P2(apdu) != 0x81)
        return SW_REFERENCE_NOT_FOUND();
    if (P1(apdu) == 0x0 || P1(apdu) == 0x2) {
        int newpin_len = 0;
        file_t *pw = NULL;
        if (!(pw = search_by_fid(EF_PW1, NULL, SPECIFY_EF)))
            return SW_REFERENCE_NOT_FOUND();
        if (P1(apdu) == 0x0) {
            file_t *rc, *pw;
            if (!(rc = search_by_fid(EF_RC, NULL, SPECIFY_EF)))
                return SW_REFERENCE_NOT_FOUND();
            uint8_t pin_len = file_read_uint8(rc->data+2);
            if (apdu.cmd_apdu_data_len <= pin_len)
                return SW_WRONG_LENGTH();
            uint16_t r = check_pin(rc, apdu.cmd_apdu_data, pin_len);
            if (r != 0x9000)
                return r;
            newpin_len = apdu.cmd_apdu_data_len-pin_len;
        }
        else if (P1(apdu) == 0x2) {    
            if (!has_pw3)
                return SW_CONDITIONS_NOT_SATISFIED();
            newpin_len = apdu.cmd_apdu_data_len;
        }
        uint8_t dhash[33];
        dhash[0] = newpin_len;
        double_hash_pin(apdu.cmd_apdu_data+(apdu.cmd_apdu_data_len-newpin_len), newpin_len, dhash+1);
        flash_write_data_to_file(pw, dhash, sizeof(dhash));
        if (pin_reset_retries(pw, true) != CCID_OK)
            return SW_MEMORY_FAILURE();
        low_flash_available();
        return SW_OK();
    }
    return SW_INCORRECT_P1P2();
}

typedef struct cmd
{
  uint8_t ins;
  int (*cmd_handler)();
} cmd_t;

#define INS_VERIFY          0x20
#define INS_CHANGE_PIN      0x24
#define INS_RESET_RETRY     0x2C
#define INS_SELECT          0xA4
#define INS_GET_DATA        0xCA
#define INS_PUT_DATA        0xDA

static const cmd_t cmds[] = {
    { INS_GET_DATA, cmd_get_data },
    { INS_SELECT, cmd_select },
    { INS_VERIFY, cmd_verify },
    { INS_PUT_DATA, cmd_put_data },
    { INS_CHANGE_PIN, cmd_change_pin },
    { INS_RESET_RETRY, cmd_reset_retry },
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