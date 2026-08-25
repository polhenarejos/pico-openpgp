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

#ifndef _OPENPGP_VAULT_H_
#define _OPENPGP_VAULT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "crypto_utils.h"
#include "vault_container.h"

#define OPENPGP_VAULT_KEY_SIZE PICOKEYS_VAULT_KEY_SIZE
#define OPENPGP_VAULT_RECORD_SIZE PICOKEYS_VAULT_RECORD_SIZE
typedef uint8_t openpgp_vault_app_t;

#define OPENPGP_VAULT_APP_FIDO 0u
#define OPENPGP_VAULT_APP_OPENPGP 1u
#define OPENPGP_VAULT_APP_PIV 2u
#define OPENPGP_VAULT_APP_COUNT 3u

bool openpgp_vault_is_enrolled(void);
bool openpgp_vault_wrapper_available(openpgp_vault_app_t app);
int openpgp_vault_load_kvault(openpgp_vault_app_t app, uint8_t kvault[OPENPGP_VAULT_KEY_SIZE]);
int openpgp_vault_store_kvault(openpgp_vault_app_t app, const uint8_t kvault[OPENPGP_VAULT_KEY_SIZE]);
int openpgp_vault_clear_wrappers(void);
bool openpgp_vault_backup_authorized(openpgp_vault_app_t app);
int openpgp_vault_command(openpgp_vault_app_t app);

#endif // _OPENPGP_VAULT_H_
