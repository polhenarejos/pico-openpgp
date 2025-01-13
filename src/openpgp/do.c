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
#include "asn1.h"

int parse_do(uint16_t *fids, int mode) {
    int len = 0;
    file_t *ef;
    for (int i = 0; i < fids[0]; i++) {
        if ((ef = search_by_fid(fids[i + 1], NULL, SPECIFY_EF))) {
            uint16_t data_len;
            if ((ef->type & FILE_DATA_FUNC) == FILE_DATA_FUNC) {
                data_len = ((int (*)(const file_t *, int))(ef->data))((const file_t *) ef, mode);
            }
            else {
                if (ef->data) {
                    data_len = file_get_size(ef);
                }
                else {
                    data_len = 0;
                }
                if (mode == 1) {
                    if (fids[0] > 1 && res_APDU_size > 0) {
                        if (fids[i + 1] < 0x0100) {
                            res_APDU[res_APDU_size++] = fids[i + 1] & 0xff;
                        }
                        else {
                            res_APDU[res_APDU_size++] = fids[i + 1] >> 8;
                            res_APDU[res_APDU_size++] = fids[i + 1] & 0xff;
                        }
                        res_APDU_size += format_tlv_len(data_len, res_APDU + res_APDU_size);
                    }
                    if (ef->data) {
                        memcpy(res_APDU + res_APDU_size, file_get_data(ef), data_len);
                    }
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
        if ((ef = search_by_fid(fid + i, NULL, SPECIFY_EF)) && ef->data) {
            uint16_t data_len = file_get_size(ef);
            memcpy(res_APDU + res_APDU_size, file_get_data(ef), data_len);
            res_APDU_size += data_len;
        }
        else {
            memset(res_APDU + res_APDU_size, 0, size);
            res_APDU_size += size;
        }
    }
    return num * size;
}

int parse_ch_data(const file_t *f, int mode) {
    uint16_t fids[] = {
        3,
        EF_CH_NAME, EF_LANG_PREF, EF_SEX,
    };
    res_APDU[res_APDU_size++] = EF_CH_DATA & 0xff;
    res_APDU[res_APDU_size++] = 0x82;
    uint8_t *lp = res_APDU + res_APDU_size;
    res_APDU_size += 2;
    parse_do(fids, mode);
    uint16_t lpdif = res_APDU + res_APDU_size - lp - 2;
    *lp++ = lpdif >> 8;
    *lp++ = lpdif & 0xff;
    return lpdif + 4;
}

int parse_sec_tpl(const file_t *f, int mode) {
    res_APDU[res_APDU_size++] = EF_SEC_TPL & 0xff;
    res_APDU[res_APDU_size++] = 5;
    file_t *ef = search_by_fid(EF_SIG_COUNT, NULL, SPECIFY_ANY);
    if (ef && ef->data) {
        res_APDU[res_APDU_size++] = EF_SIG_COUNT & 0xff;
        res_APDU[res_APDU_size++] = 3;
        memcpy(res_APDU + res_APDU_size, file_get_data(ef), 3);
        res_APDU_size += 3;
    }
    return 5 + 2;
}

int parse_ch_cert(const file_t *f, int mode) {
    return 0;
}

int parse_fp(const file_t *f, int mode) {
    res_APDU[res_APDU_size++] = EF_FP & 0xff;
    res_APDU[res_APDU_size++] = 60;
    return parse_trium(EF_FP_SIG, 3, 20) + 2;
}

int parse_cafp(const file_t *f, int mode) {
    res_APDU[res_APDU_size++] = EF_CA_FP & 0xff;
    res_APDU[res_APDU_size++] = 60;
    return parse_trium(EF_FP_CA1, 3, 20) + 2;
}

int parse_ts(const file_t *f, int mode) {
    res_APDU[res_APDU_size++] = EF_TS_ALL & 0xff;
    res_APDU[res_APDU_size++] = 12;
    return parse_trium(EF_TS_SIG, 3, 4) + 2;
}

int parse_keyinfo(const file_t *f, int mode) {
    int init_len = res_APDU_size;
    if (res_APDU_size > 0) {
        res_APDU[res_APDU_size++] = EF_KEY_INFO & 0xff;
        res_APDU[res_APDU_size++] = 6;
    }
    file_t *ef = search_by_fid(EF_PK_SIG, NULL, SPECIFY_ANY);
    res_APDU[res_APDU_size++] = 0x00;
    if (ef && ef->data) {
        res_APDU[res_APDU_size++] = 0x01;
    }
    else {
        res_APDU[res_APDU_size++] = 0x00;
    }

    ef = search_by_fid(EF_PK_DEC, NULL, SPECIFY_ANY);
    res_APDU[res_APDU_size++] = 0x01;
    if (ef && ef->data) {
        res_APDU[res_APDU_size++] = 0x01;
    }
    else {
        res_APDU[res_APDU_size++] = 0x00;
    }

    ef = search_by_fid(EF_PK_AUT, NULL, SPECIFY_ANY);
    res_APDU[res_APDU_size++] = 0x02;
    if (ef && ef->data) {
        res_APDU[res_APDU_size++] = 0x01;
    }
    else {
        res_APDU[res_APDU_size++] = 0x00;
    }
    return res_APDU_size - init_len;
}

int parse_pw_status(const file_t *f, int mode) {
    file_t *ef;
    int init_len = res_APDU_size;
    if (res_APDU_size > 0) {
        res_APDU[res_APDU_size++] = EF_PW_STATUS & 0xff;
        res_APDU[res_APDU_size++] = 7;
    }
    ef = search_by_fid(EF_PW_PRIV, NULL, SPECIFY_ANY);
    if (ef && ef->data) {
        memcpy(res_APDU + res_APDU_size, file_get_data(ef), 7);
        res_APDU_size += 7;
    }
    return res_APDU_size - init_len;
}

#define ALGO_RSA_1K     0
#define ALGO_RSA_2k     1
#define ALGO_RSA_3K     2
#define ALGO_RSA_4K     3
#define ALGO_X448       4
#define ALGO_P256K1     5
#define ALGO_P256R1     6
#define ALGO_P384R1     7
#define ALGO_P521R1     8
#define ALGO_BP256R1    9
#define ALGO_BP384R1    10
#define ALGO_BP512R1    11
#define ALGO_CV22519    12

const uint8_t algorithm_attr_x448[] = {
    4,
    ALGO_ECDH,
    /* OID of X448 */
    0x2b, 0x65, 0x6f
};

const uint8_t algorithm_attr_rsa1k[] = {
    6,
    ALGO_RSA,
    0x04, 0x00,       /* Length modulus (in bit): 1024 */
    0x00, 0x20,       /* Length exponent (in bit): 32  */
    0x00          /* 0: Acceptable format is: P and Q */
};

const uint8_t algorithm_attr_rsa2k[] = {
    6,
    ALGO_RSA,
    0x08, 0x00,       /* Length modulus (in bit): 2048 */
    0x00, 0x20,       /* Length exponent (in bit): 32  */
    0x00          /* 0: Acceptable format is: P and Q */
};

const uint8_t algorithm_attr_rsa3k[] = {
    6,
    ALGO_RSA,
    0x0C, 0x00,       /* Length modulus (in bit): 3072 */
    0x00, 0x20,       /* Length exponent (in bit): 32  */
    0x00          /* 0: Acceptable format is: P and Q */
};

const uint8_t algorithm_attr_rsa4k[] = {
    6,
    ALGO_RSA,
    0x10, 0x00,       /* Length modulus (in bit): 4096 */
    0x00, 0x20,       /* Length exponent (in bit): 32  */
    0x00          /* 0: Acceptable format is: P and Q */
};

const uint8_t algorithm_attr_p256k1[] = {
    6,
    ALGO_ECDSA,
    0x2b, 0x81, 0x04, 0x00, 0x0a
};

const uint8_t algorithm_attr_p256r1[] = {
    9,
    ALGO_ECDSA,
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
};

const uint8_t algorithm_attr_p384r1[] = {
    6,
    ALGO_ECDSA,
    0x2B, 0x81, 0x04, 0x00, 0x22
};

const uint8_t algorithm_attr_p521r1[] = {
    6,
    ALGO_ECDSA,
    0x2B, 0x81, 0x04, 0x00, 0x23
};

const uint8_t algorithm_attr_bp256r1[] = {
    10,
    ALGO_ECDSA,
    0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07
};

const uint8_t algorithm_attr_bp384r1[] = {
    10,
    ALGO_ECDSA,
    0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B
};

const uint8_t algorithm_attr_bp512r1[] = {
    10,
    ALGO_ECDSA,
    0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D
};

const uint8_t algorithm_attr_cv25519[] = {
    11,
    ALGO_ECDH,
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01
};

const uint8_t algorithm_attr_ed25519[] = {
    10,
    ALGO_EDDSA,
    0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01
    };


int parse_algo(const uint8_t *algo, uint16_t tag) {
    res_APDU[res_APDU_size++] = tag & 0xff;
    memcpy(res_APDU + res_APDU_size, algo, algo[0] + 1);
    res_APDU_size += algo[0] + 1;
    return algo[0] + 2;
}

int parse_algoinfo(const file_t *f, int mode) {
    int datalen = 0;
    if (f->fid == EF_ALGO_INFO) {
        res_APDU[res_APDU_size++] = EF_ALGO_INFO & 0xff;
        res_APDU[res_APDU_size++] = 0x82;
        uint8_t *lp = res_APDU + res_APDU_size;
        res_APDU_size += 2;
        datalen += parse_algo(algorithm_attr_rsa1k, EF_ALGO_SIG);
        datalen += parse_algo(algorithm_attr_rsa2k, EF_ALGO_SIG);
        datalen += parse_algo(algorithm_attr_rsa3k, EF_ALGO_SIG);
        datalen += parse_algo(algorithm_attr_rsa4k, EF_ALGO_SIG);
        datalen += parse_algo(algorithm_attr_p256k1, EF_ALGO_SIG);
        datalen += parse_algo(algorithm_attr_p256r1, EF_ALGO_SIG);
        datalen += parse_algo(algorithm_attr_p384r1, EF_ALGO_SIG);
        datalen += parse_algo(algorithm_attr_p521r1, EF_ALGO_SIG);
        datalen += parse_algo(algorithm_attr_bp256r1, EF_ALGO_SIG);
        datalen += parse_algo(algorithm_attr_bp384r1, EF_ALGO_SIG);
        datalen += parse_algo(algorithm_attr_bp512r1, EF_ALGO_SIG);
        datalen += parse_algo(algorithm_attr_ed25519, EF_ALGO_SIG);

        datalen += parse_algo(algorithm_attr_rsa1k, EF_ALGO_DEC);
        datalen += parse_algo(algorithm_attr_rsa2k, EF_ALGO_DEC);
        datalen += parse_algo(algorithm_attr_rsa3k, EF_ALGO_DEC);
        datalen += parse_algo(algorithm_attr_rsa4k, EF_ALGO_DEC);
        datalen += parse_algo(algorithm_attr_p256k1, EF_ALGO_DEC);
        datalen += parse_algo(algorithm_attr_p256r1, EF_ALGO_DEC);
        datalen += parse_algo(algorithm_attr_p384r1, EF_ALGO_DEC);
        datalen += parse_algo(algorithm_attr_p521r1, EF_ALGO_DEC);
        datalen += parse_algo(algorithm_attr_bp256r1, EF_ALGO_DEC);
        datalen += parse_algo(algorithm_attr_bp384r1, EF_ALGO_DEC);
        datalen += parse_algo(algorithm_attr_bp512r1, EF_ALGO_DEC);
        datalen += parse_algo(algorithm_attr_cv25519, EF_ALGO_DEC);
        datalen += parse_algo(algorithm_attr_x448, EF_ALGO_DEC);

        datalen += parse_algo(algorithm_attr_rsa1k, EF_ALGO_AUT);
        datalen += parse_algo(algorithm_attr_rsa2k, EF_ALGO_AUT);
        datalen += parse_algo(algorithm_attr_rsa3k, EF_ALGO_AUT);
        datalen += parse_algo(algorithm_attr_rsa4k, EF_ALGO_AUT);
        datalen += parse_algo(algorithm_attr_p256k1, EF_ALGO_AUT);
        datalen += parse_algo(algorithm_attr_p256r1, EF_ALGO_AUT);
        datalen += parse_algo(algorithm_attr_p384r1, EF_ALGO_AUT);
        datalen += parse_algo(algorithm_attr_p521r1, EF_ALGO_AUT);
        datalen += parse_algo(algorithm_attr_bp256r1, EF_ALGO_AUT);
        datalen += parse_algo(algorithm_attr_bp384r1, EF_ALGO_AUT);
        datalen += parse_algo(algorithm_attr_bp512r1, EF_ALGO_AUT);
        datalen += parse_algo(algorithm_attr_ed25519, EF_ALGO_AUT);
        uint16_t lpdif = res_APDU + res_APDU_size - lp - 2;
        *lp++ = lpdif >> 8;
        *lp++ = lpdif & 0xff;
        datalen = lpdif + 4;
    }
    else if (f->fid == EF_ALGO_SIG || f->fid == EF_ALGO_DEC || f->fid == EF_ALGO_AUT) {
        uint16_t fid = 0x1000 | f->fid;
        file_t *ef;
        if (!(ef = search_by_fid(fid, NULL, SPECIFY_EF)) || !ef->data) {
            datalen += parse_algo(algorithm_attr_rsa2k, f->fid);
        }
        else {
            uint16_t len = file_get_size(ef);
            if (res_APDU_size > 0) {
                res_APDU[res_APDU_size++] = f->fid & 0xff;
                res_APDU[res_APDU_size++] = len & 0xff;
                datalen += 2;
            }
            memcpy(res_APDU + res_APDU_size, file_get_data(ef), len);
            res_APDU_size += len;
            datalen += len;
        }
    }
    return datalen;
}

int parse_app_data(const file_t *f, int mode) {
    uint16_t fids[] = {
        6,
        EF_FULL_AID, EF_HIST_BYTES, EF_EXLEN_INFO, EF_GFM, EF_DISCRETE_DO, EF_KEY_INFO
    };
    res_APDU[res_APDU_size++] = EF_APP_DATA & 0xff;
    res_APDU[res_APDU_size++] = 0x82;
    uint8_t *lp = res_APDU + res_APDU_size;
    res_APDU_size += 2;
    parse_do(fids, mode);
    uint16_t lpdif = res_APDU + res_APDU_size - lp - 2;
    *lp++ = lpdif >> 8;
    *lp++ = lpdif & 0xff;
    return lpdif + 4;
}

int parse_discrete_do(const file_t *f, int mode) {
    uint16_t fids[] = {
        11,
        EF_EXT_CAP, EF_ALGO_SIG, EF_ALGO_DEC, EF_ALGO_AUT, EF_PW_STATUS, EF_FP, EF_CA_FP, EF_TS_ALL,
        EF_UIF_SIG, EF_UIF_DEC, EF_UIF_AUT
    };
    res_APDU[res_APDU_size++] = EF_DISCRETE_DO & 0xff;
    res_APDU[res_APDU_size++] = 0x82;
    uint8_t *lp = res_APDU + res_APDU_size;
    res_APDU_size += 2;
    parse_do(fids, mode);
    uint16_t lpdif = res_APDU + res_APDU_size - lp - 2;
    *lp++ = lpdif >> 8;
    *lp++ = lpdif & 0xff;
    return lpdif + 4;
}
