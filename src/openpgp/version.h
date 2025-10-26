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

#ifndef __VERSION_H_
#define __VERSION_H_

#define OPGP_VERSION 0x0304

#define OPGP_VERSION_MAJOR ((OPGP_VERSION >> 8) & 0xff)
#define OPGP_VERSION_MINOR (OPGP_VERSION & 0xff)

#define PIV_VERSION 0x0507

#define PIV_VERSION_MAJOR ((PIV_VERSION >> 8) & 0xff)
#define PIV_VERSION_MINOR (PIV_VERSION & 0xff)


#define PIPGP_VERSION 0x0306

#define PIPGP_VERSION_MAJOR ((PIPGP_VERSION >> 8) & 0xff)
#define PIPGP_VERSION_MINOR (PIPGP_VERSION & 0xff)

#endif
