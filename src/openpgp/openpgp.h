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

#ifndef __OPENPGP_H_
#define __OPENPGP_H_

#include "stdlib.h"
#if !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
#include <pico/stdlib.h>
#endif

#include "picokeys.h"
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
extern int store_keypair(void *key_ctx, int type, uint16_t key_id, const uint8_t *public_data, size_t public_size);
extern void make_rsa_response(mbedtls_rsa_context *rsa);
extern void make_ecdsa_response(mbedtls_ecdsa_context *ecdsa);
extern int ecdsa_sign(mbedtls_ecdsa_context *ctx, const uint8_t *data, size_t data_len, uint8_t *out, size_t *out_len);
extern int rsa_sign(mbedtls_rsa_context *ctx, const uint8_t *data, size_t data_len, uint8_t *out, size_t *out_len);
extern int load_private_key_rsa(mbedtls_rsa_context *ctx, file_t *fkey, bool use_dek);
extern int load_private_key_ecdsa(mbedtls_ecdsa_context *ctx, file_t *fkey, bool use_dek);
extern int pin_reset_retries(const file_t *pin, bool force);
extern int pin_spend_retry(const file_t *pin, uint8_t *remaining);
extern int pin_check_verifier(const file_t *pin, const uint8_t *data, size_t len, uint8_t offset, bool *mismatch);

#define ALGO_RSA        0x01
#define ALGO_ECDH       0x12
#define ALGO_ECDSA      0x13
#define ALGO_EDDSA      0x16
#define ALGO_AES        0x70
#define ALGO_AES_128    0x71
#define ALGO_AES_192    0x72
#define ALGO_AES_256    0x74

extern void select_file(file_t *pe);
extern int parse_do(uint16_t *fids, int mode);
extern int load_dek(void);
extern void release_dek(void);
extern bool piv_key_operation_authorized(uint16_t operation, bool internal_firmware);
extern int check_pin(const file_t *pin, const uint8_t *data, size_t len);
extern int check_pin_len(uint16_t fid, size_t len);
extern int openpgp_reset_code_deactivate(void);
#ifdef ENABLE_ADMINLESS_MODE
extern bool openpgp_adminless_is_pending(void);
extern bool openpgp_adminless_is_active(void);
extern int openpgp_adminless_begin_kdf_migration(void);
extern int openpgp_adminless_sync_pw3(const uint8_t *pin, size_t pin_len, const uint8_t verifier[34]);
extern int openpgp_adminless_enable(void);
extern int openpgp_adminless_disable(void);
extern int openpgp_adminless_reset(void);
#endif
extern mbedtls_ecp_group_id get_ec_group_id_from_attr(const uint8_t *algo, size_t algo_len);
extern bool openpgp_algorithm_attr_supported(const uint8_t *algo, size_t algo_len);
extern int reset_sig_count(void);
extern uint16_t algo_dec, algo_aut, pk_dec, pk_aut;
extern bool wait_button_pressed_fid(uint16_t fid);
extern void signal_private_key_use(uint16_t uif_fid);
extern void scan_files_openpgp(void);
extern int load_aes_key(uint8_t *aes_key, size_t *key_size, file_t *fkey);
extern int load_key_data(file_t *fkey, byte_buffer_t *out, bool use_dek);
extern int pin_txn_stage(uint16_t fid, const uint8_t verifier[34], const uint8_t *session);
extern int pin_txn_delete(uint16_t fid);
extern int inc_sig_count(void);
int cmd_select(void);
int cmd_get_data(void);
int cmd_get_next_data(void);
int cmd_put_data(void);
int cmd_verify(void);
int cmd_select_data(void);
int cmd_version_openpgp(void);
int cmd_import_data(void);
int cmd_change_pin(void);
int cmd_mse(void);
int cmd_internal_aut(void);
int cmd_challenge(void);
int cmd_activate_file(void);
int cmd_terminate_df(void);
int cmd_pso(void);
int cmd_keypair_gen(void);
int cmd_reset_retry(void);
int cmd_get_bulk_data(void);

#define DEK_SIZE        (IV_SIZE + 32)
#define DEK_AAD_SIZE    (PIN_KDF_SIZE(DEK_SIZE))
#define DEK_FILE_SIZE   (1 + DEK_AAD_SIZE)

#define DEK_FILE_SIZE_OLD (IV_SIZE + 32 + 32 + 32 + 32)

#define OPENPGP_MAX_ALGORITHM_ATTR_SIZE 16u
#define OPENPGP_MAX_OBJECT_SIZE         2048u
#define OPENPGP_MAX_RESPONSE_SIZE       2048u

#endif
