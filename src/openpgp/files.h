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
#define EF_PK_SIG       0x10d1
#define EF_PK_DEC       0x10d2
#define EF_PK_AUT       0x10d3
#define EF_PB_SIG       0x10d4
#define EF_PB_DEC       0x10d5
#define EF_PB_AUT       0x10d6

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
#define EF_UIF_SIG      0x00d6 //S
#define EF_UIF_DEC      0x00d7 //S
#define EF_UIF_AUT      0x00d8 //S
#define EF_KEY_INFO     0x00de //S
#define EF_ALGO_INFO    0x00fa //C
#define EF_LANG_PREF    0x5f2d //S
#define EF_SEX          0x5f35 //S
#define EF_URI_URL      0x5f50 //S
#define EF_HIST_BYTES   0x5f52 //S
#define EF_CH_CERT      0x7f21 //C
#define EF_EXLEN_INFO   0x7f66 //C
#define EF_GFM          0x7f74 //C

#endif
