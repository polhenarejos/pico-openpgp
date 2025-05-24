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

#include "openpgp.h"
#include "version.h"

int cmd_version_openpgp() {
    res_APDU[res_APDU_size++] = PIPGP_VERSION_MAJOR;
    res_APDU[res_APDU_size++] = PIPGP_VERSION_MINOR;
    res_APDU[res_APDU_size++] = 0x0;
    return SW_OK();
}