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


#ifndef _FILES_H_
#define _FILES_H_

#include "file.h"

#define EF_PW1          0x1081
#define EF_RC           0x1082
#define EF_PW3          0x1083
#define EF_ALGO_PRIV1   0x10c1
#define EF_ALGO_PRIV2   0x10c2
#define EF_ALGO_PRIV3   0x10c3
#define EF_PW_PRIV      0x10c4
#define EF_PW_RETRIES   0x10c5
#define EF_PK_SIG       0x10d1
#define EF_PK_DEC       0x10d2
#define EF_PK_AUT       0x10d3
#define EF_PB_SIG       0x10d4
#define EF_PB_DEC       0x10d5
#define EF_PB_AUT       0x10d6
#define EF_DEK          0x1099
#define EF_CH_1         0x1f21
#define EF_CH_2         0x1f22
#define EF_CH_3         0x1f23

#define EF_EXT_HEADER   0x004d //C
#define EF_FULL_AID     0x004f //S
#define EF_CH_NAME      0x005b //S
#define EF_LOGIN_DATA   0x005e //S
#define EF_CH_DATA      0x0065 //C
#define EF_APP_DATA     0x006e //C
#define EF_DISCRETE_DO  0x0073 //C
#define EF_SEC_TPL      0x007a //C
#define EF_SIG_COUNT    0x0093 //S
#define EF_EXT_CAP      0x00c0 //S
#define EF_ALGO_SIG     0x00c1 //S
#define EF_ALGO_DEC     0x00c2 //S
#define EF_ALGO_AUT     0x00c3 //S
#define EF_PW_STATUS    0x00c4 //S
#define EF_FP           0x00c5 //S
#define EF_CA_FP        0x00c6 //S
#define EF_FP_SIG       0x00c7 //S
#define EF_FP_DEC       0x00c8 //S
#define EF_FP_AUT       0x00c9 //S
#define EF_FP_CA1       0x00ca //S
#define EF_FP_CA2       0x00cb //S
#define EF_FP_CA3       0x00cc //S
#define EF_TS_ALL       0x00cd //S
#define EF_TS_SIG       0x00ce //S
#define EF_TS_DEC       0x00cf //S
#define EF_TS_AUT       0x00d0 //S
#define EF_RESET_CODE   0x00d3 //S
#define EF_AES_KEY      0x00d5 //S
#define EF_UIF_SIG      0x00d6 //S
#define EF_UIF_DEC      0x00d7 //S
#define EF_UIF_AUT      0x00d8 //S
#define EF_KEY_INFO     0x00de //S
#define EF_KDF          0x00f9 //C
#define EF_ALGO_INFO    0x00fa //C
#define EF_LANG_PREF    0x5f2d //S
#define EF_SEX          0x5f35 //S
#define EF_URI_URL      0x5f50 //S
#define EF_HIST_BYTES   0x5f52 //S
#define EF_CH_CERT      0x7f21 //C
#define EF_EXLEN_INFO   0x7f66 //C
#define EF_GFM          0x7f74 //C

// PIV

#define EF_PIV_PIN  0x1184
#define EF_PIV_PUK  0x1185

#define EF_PIV_ADMIN_DATA  0xff00
#define EF_PIV_ATTESTATION 0xff01
#define	EF_PIV_MSCMAP      0xff10
#define	EF_PIV_MSROOTS1    0xff11
#define EF_PIV_MSROOTS2    0xff12
#define EF_PIV_MSROOTS3    0xff13
#define EF_PIV_MSROOTS4    0xff14
#define EF_PIV_MSROOTS5    0xff15

#define EF_PIV_KEY_AUTHENTICATION   0x009a
#define EF_PIV_KEY_CARDMGM          0x009b
#define EF_PIV_KEY_SIGNATURE        0x009c
#define EF_PIV_KEY_KEYMGM           0x009d
#define EF_PIV_KEY_CARDAUTH         0x009e
#define EF_PIV_KEY_RETIRED1         0x0082
#define EF_PIV_KEY_RETIRED2         0x0083
#define EF_PIV_KEY_RETIRED3         0x0084
#define EF_PIV_KEY_RETIRED4         0x0085
#define EF_PIV_KEY_RETIRED5         0x0086
#define EF_PIV_KEY_RETIRED6         0x0087
#define EF_PIV_KEY_RETIRED7         0x0088
#define EF_PIV_KEY_RETIRED8         0x0089
#define EF_PIV_KEY_RETIRED9         0x008a
#define EF_PIV_KEY_RETIRED10        0x008b
#define EF_PIV_KEY_RETIRED11        0x008c
#define EF_PIV_KEY_RETIRED12        0x008d
#define EF_PIV_KEY_RETIRED13        0x008e
#define EF_PIV_KEY_RETIRED14        0x008f
#define EF_PIV_KEY_RETIRED15        0x0090
#define EF_PIV_KEY_RETIRED16        0x0091
#define EF_PIV_KEY_RETIRED17        0x0092
#define EF_PIV_KEY_RETIRED18        0x0096 // It's 0x93 but assigned to EF_SIG_COUNT
#define EF_PIV_KEY_RETIRED19        0x0094
#define EF_PIV_KEY_RETIRED20        0x0095
#define EF_PIV_KEY_ATTESTATION      0x00fb // It's 0xf9 but assigned to EF_KDF

#define EF_PIV_CAPABILITY       0xc107
#define EF_PIV_CHUID            0xc102
#define EF_PIV_AUTHENTICATION   0xc105 /* cert for 9a key */
#define EF_PIV_FINGERPRINTS     0xc103
#define EF_PIV_SECURITY         0xc106
#define EF_PIV_FACIAL           0xc108
#define EF_PIV_PRINTED          0xc109
#define EF_PIV_SIGNATURE        0xc10a /* cert for 9c key */
#define EF_PIV_KEY_MANAGEMENT   0xc10b /* cert for 9d key */
#define EF_PIV_CARD_AUTH        0xc101 /* cert for 9e key */
#define EF_PIV_DISCOVERY        0x007e
#define EF_PIV_KEY_HISTORY      0xc10c
#define EF_PIV_IRIS             0xc121
#define EF_PIV_BITGT            0x7f61
#define EF_PIV_SM_SIGNER        0xc122
#define EF_PIV_PC_REF_DATA      0xc123

#define EF_PIV_RETIRED1  0xc10d
#define EF_PIV_RETIRED2  0xc10e
#define EF_PIV_RETIRED3  0xc10f
#define EF_PIV_RETIRED4  0xc110
#define EF_PIV_RETIRED5  0xc111
#define EF_PIV_RETIRED6  0xc112
#define EF_PIV_RETIRED7  0xc113
#define EF_PIV_RETIRED8  0xc114
#define EF_PIV_RETIRED9  0xc115
#define EF_PIV_RETIRED10 0xc116
#define EF_PIV_RETIRED11 0xc117
#define EF_PIV_RETIRED12 0xc118
#define EF_PIV_RETIRED13 0xc119
#define EF_PIV_RETIRED14 0xc11a
#define EF_PIV_RETIRED15 0xc11b
#define EF_PIV_RETIRED16 0xc11c
#define EF_PIV_RETIRED17 0xc11d
#define EF_PIV_RETIRED18 0xc11e
#define EF_PIV_RETIRED19 0xc11f
#define EF_PIV_RETIRED20 0xc120

#define EF_DEV_CONF     0x1122

#endif
