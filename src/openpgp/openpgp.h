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

#ifndef __OPENPGP_H_
#define __OPENPGP_H_

#include "stdlib.h"
#ifndef ENABLE_EMULATION
#include <pico/stdlib.h>
#endif

#include "pico_keys.h"
#include "apdu.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ecdsa.h"

extern bool has_pw1;
extern bool has_pw3;

extern int store_keys(void *key_ctx, int type, uint16_t key_id);
extern void make_rsa_response(mbedtls_rsa_context *rsa);
extern void make_ecdsa_response(mbedtls_ecdsa_context *ecdsa);

#define ALGO_RSA        0x01
#define ALGO_ECDH       0x12
#define ALGO_ECDSA      0x13
#define ALGO_AES        0x70
#define ALGO_AES_128    0x71
#define ALGO_AES_192    0x72
#define ALGO_AES_256    0x74

#endif
