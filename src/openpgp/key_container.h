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

#ifndef _OPENPGP_KEY_CONTAINER_H_
#define _OPENPGP_KEY_CONTAINER_H_

#include "object_policy.h"

#define OPENPGP_KEY_CONTAINER_KIND 0x0001u
#define OPENPGP_KEY_OBJECT_PRIVATE 0x0001u
#define OPENPGP_KEY_OBJECT_PUBLIC 0x0002u

bool openpgp_key_container_supported(uint16_t fid);
bool openpgp_key_container_is_marker(const file_t *file);
bool openpgp_key_container_physical_fid(uint16_t fid);
bool openpgp_key_container_can_create(uint16_t fid);
int openpgp_key_container_store(uint16_t fid, const uint8_t *private_data, uint32_t private_size, const uint8_t *public_data, uint32_t public_size, bool internal_firmware);
int openpgp_key_container_read_private(uint16_t fid, uint16_t operation, bool internal_firmware, byte_buffer_t *data);
int openpgp_key_container_read_public(uint16_t fid, byte_buffer_t *data);
int openpgp_key_container_public_size(uint16_t fid, uint32_t *object_size);
int openpgp_key_container_delete(uint16_t fid, bool internal_firmware);

#endif // _OPENPGP_KEY_CONTAINER_H_
