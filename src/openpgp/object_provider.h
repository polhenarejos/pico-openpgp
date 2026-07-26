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

#ifndef _OPENPGP_OBJECT_PROVIDER_H_
#define _OPENPGP_OBJECT_PROVIDER_H_

#include "object_container.h"

#define OPENPGP_OBJECT_NAMESPACE 0x0005u

const file_object_authenticator_t *openpgp_object_manifest_authenticator(void);
const file_object_record_protector_t *openpgp_object_record_protector(void);
const file_object_authenticator_t *openpgp_piv_object_manifest_authenticator(void);
const file_object_record_protector_t *openpgp_piv_object_record_protector(void);

#endif // _OPENPGP_OBJECT_PROVIDER_H_
