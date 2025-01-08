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
#if !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
#include <pico/stdlib.h>
#endif

#include "pico_keys.h"
#include "apdu.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ecdsa.h"
#include "crypto_utils.h"
#include "files.h"

extern bool has_pw1;
extern bool has_pw2;
extern bool has_pw3;
extern bool has_rc;
extern uint8_t session_pw1[32];
extern uint8_t session_rc[32];
extern uint8_t session_pw3[32];
extern uint8_t dek[IV_SIZE + 32];

extern int store_keys(void *key_ctx, int type, uint16_t key_id, bool use_kek);
extern void make_rsa_response(mbedtls_rsa_context *rsa);
extern void make_ecdsa_response(mbedtls_ecdsa_context *ecdsa);
extern int ecdsa_sign(mbedtls_ecdsa_context *ctx,
                      const uint8_t *data,
                      size_t data_len,
                      uint8_t *out,
                      size_t *out_len);
extern int rsa_sign(mbedtls_rsa_context *ctx,
                    const uint8_t *data,
                    size_t data_len,
                    uint8_t *out,
                    size_t *out_len);
extern int load_private_key_rsa(mbedtls_rsa_context *ctx, file_t *fkey, bool use_dek);
extern int load_private_key_ecdsa(mbedtls_ecdsa_context *ctx, file_t *fkey, bool use_dek);
extern int pin_reset_retries(const file_t *pin, bool force);

#define ALGO_RSA        0x01
#define ALGO_ECDH       0x12
#define ALGO_ECDSA      0x13
#define ALGO_AES        0x70
#define ALGO_AES_128    0x71
#define ALGO_AES_192    0x72
#define ALGO_AES_256    0x74

extern void select_file(file_t *pe);
extern int parse_do(uint16_t *fids, int mode);
extern int load_dek();
extern int check_pin(const file_t *pin, const uint8_t *data, size_t len);
extern mbedtls_ecp_group_id get_ec_group_id_from_attr(const uint8_t *algo, size_t algo_len);
extern int reset_sig_count();
extern uint16_t algo_dec, algo_aut, pk_dec, pk_aut;
extern bool wait_button_pressed(uint16_t fid);
extern void scan_files();
extern int load_aes_key(uint8_t *aes_key, file_t *fkey);
extern int inc_sig_count();
extern int dek_encrypt(uint8_t *data, size_t len);
extern int dek_decrypt(uint8_t *data, size_t len);

#endif
