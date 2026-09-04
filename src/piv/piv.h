/*
 * This file is part of the Pico OpenPGP distribution (https://github.com/polhenarejos/pico-openpgp).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef __PIV_H_
#define __PIV_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "openpgp.h"
#include "key_container.h"
#include "random.h"
#include "tlv.h"
#include "version.h"
#include "mbedtls/aes.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/des.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/x509_crt.h"

#define PIV_ALGO_3DES   0x03
#define PIV_ALGO_AES128 0x08
#define PIV_ALGO_AES192 0x0a
#define PIV_ALGO_AES256 0x0c
#define PIV_ALGO_RSA1024 0x06
#define PIV_ALGO_RSA2048 0x07
#define PIV_ALGO_RSA3072 0x05
#define PIV_ALGO_RSA4096 0x16
#define PIV_ALGO_ECCP256 0x11
#define PIV_ALGO_ECCP384 0x14
#define PIV_ALGO_X25519 0xE1
#define PIV_ALGO_PIN    0xFF
#define PIV_DATA_ADMIN_ID 0x5FFF00u
#define PIV_DATA_ATTESTATION_ID 0x5FFF01u

#define PINPOLICY_DEFAULT 0
#define PINPOLICY_NEVER 1
#define PINPOLICY_ONCE 2
#define PINPOLICY_ALWAYS 3
#define MGM_PIN_POLICY PINPOLICY_DEFAULT
#define PIV_PIN_WIRE_SIZE 8u
#define PIV_MAX_RETRIES 10u

#define TOUCHPOLICY_DEFAULT 0
#define TOUCHPOLICY_NEVER 1
#define TOUCHPOLICY_ALWAYS 2
#define TOUCHPOLICY_CACHED 3
#define TOUCHPOLICY_AUTO 0xFF
#define PIV_DEFAULT_TOUCH_POLICY TOUCHPOLICY_NEVER

#define ORIGIN_GENERATED 0x01
#define ORIGIN_IMPORTED 0x02
#define PIV_MANAGEMENT_KEY_DEFAULT_SIZE 24u
#define PIV_FLASH_COMMIT_TIMEOUT_MS 5000u

#define IS_RETIRED(x) ((x) >= EF_PIV_KEY_RETIRED1 && (x) <= EF_PIV_KEY_RETIRED20)
#define IS_ACTIVE(x) ((x) >= EF_PIV_KEY_AUTHENTICATION && (x) <= EF_PIV_KEY_CARDAUTH)
#define IS_KEY(x) ((IS_ACTIVE((x))) || (IS_RETIRED((x))))

#define INS_VERIFY          0x20
#define INS_VERSION         0xFD
#define INS_SELECT          0xA4
#define INS_YK_SERIAL       0xF8
#define INS_GET_DATA        0xCB
#define INS_GET_METADATA    0xF7
#define INS_AUTHENTICATE    0x87
#define INS_ASYM_KEYGEN     0x47
#define INS_PUT_DATA        0xDB
#define INS_SET_MGMKEY      0xFF
#define INS_MOVE_KEY        0xF6
#define INS_CHANGE_PIN      0x24
#define INS_RESET_RETRY     0x2C
#define INS_SET_RETRIES     0xFA
#define INS_RESET            0xFB
#define INS_ATTESTATION     0xF9
#define INS_IMPORT_ASYM     0xFE
#define INS_VAULT            0xF2

typedef enum {
    MGM_CHALLENGE_NONE = 0,
    MGM_CHALLENGE_MUTUAL,
    MGM_CHALLENGE_SINGLE,
} mgm_challenge_kind_t;

extern uint8_t piv_aid[];
extern uint8_t yk_aid[];
extern bool has_mgm;
extern uint8_t mgm_challenge[16];
extern mgm_challenge_kind_t mgm_challenge_kind;
extern uint8_t mgm_challenge_algo;
extern const uint8_t piv_management_key_default[PIV_MANAGEMENT_KEY_DEFAULT_SIZE];

int piv_process_apdu(void);
void init_piv(void);
int piv_parse_discovery(const file_t *ef);
void clear_mgm_challenge(void);
bool piv_button_wait(void);
size_t piv_rsa_modulus_size(uint8_t algo);
uint8_t piv_default_pin_policy(uint8_t key_ref);
bool piv_resolve_policies(uint8_t key_ref, bool has_pin, const tlv_ctx_t *pin, bool has_touch, const tlv_ctx_t *touch, uint8_t *pin_policy, uint8_t *touch_policy);
bool piv_reference_pair(const uint8_t **old_ref, const uint8_t **new_ref);
int get_serial(void);
int x509_create_cert(void *pk_ctx, uint8_t algo, uint8_t slot, bool attestation, uint8_t *buffer, size_t buffer_size);
bool piv_validate_certificate_object(uint8_t *data, uint16_t data_len);
int piv_format_certificate_object(const uint8_t *certificate, uint16_t certificate_len, uint8_t *object, uint16_t object_size);
void select_piv_aid(void);
int authenticate_mgm(uint8_t algo, file_t *ef_mgm, uint8_t chal_len, const tlv_ctx_t *a80, const tlv_ctx_t *a81, const tlv_ctx_t *a82);
bool piv_first_auth_operation(const tlv_ctx_t *ctx, uint16_t *tag, tlv_ctx_t *value);
int piv_ecdh(file_t *ef_key, uint8_t algo, const tlv_ctx_t *peer_key);

int cmd_version(void);
int cmd_piv_select(void);
int cmd_get_serial(void);
int cmd_piv_verify(void);
int cmd_piv_get_data(void);
int cmd_get_metadata(void);
int cmd_piv_authenticate(void);
int cmd_asym_keygen(void);
int cmd_piv_put_data(void);
int cmd_set_mgmkey(void);
int cmd_move_key(void);
int cmd_piv_change_pin(void);
int cmd_piv_reset_retry(void);
int cmd_set_retries(void);
int cmd_reset(void);
int cmd_attestation(void);
int cmd_import_asym(void);

#endif
