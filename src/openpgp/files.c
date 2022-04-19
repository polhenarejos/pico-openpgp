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

#include "files.h"

extern const uint8_t openpgp_aid[];

file_t file_entries[] = {
    { .fid = 0x0000, .parent = 0, .name = openpgp_aid, .type = FILE_TYPE_WORKING_EF, .data = NULL, .ef_structure = FILE_EF_TRANSPARENT, .acl = {0} },
    /* 25 */ { .fid = 0x0000, .parent = 0xff, .name = NULL, .type = FILE_TYPE_UNKNOWN, .data = NULL, .ef_structure = 0, .acl = {0} } //end
};

const file_t *MF = &file_entries[0];
const file_t *file_openpgp = &file_entries[sizeof(file_entries)/sizeof(file_t)-2];
const file_t *file_last = &file_entries[sizeof(file_entries)/sizeof(file_t)-1];