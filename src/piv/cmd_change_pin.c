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

#include "piv.h"


int cmd_piv_change_pin(void) {
    uint8_t pin_ref = P2(apdu);
    if (P1(apdu) != 0x0 || (pin_ref != 0x80 && pin_ref != 0x81)) {
        return SW_REFERENCE_NOT_FOUND();
    }
    const uint8_t *old_pin = NULL, *new_pin = NULL;
    if (!piv_reference_pair(&old_pin, &new_pin)) {
        return SW_INCORRECT_PARAMS();
    }
    file_t *ef = file_search_by_fid(pin_ref == 0x80 ? EF_PIV_PIN : EF_PIV_PUK, NULL, SPECIFY_ANY);
    if (!ef) {
        return SW_MEMORY_FAILURE();
    }
    uint16_t ret = pin_check_verifier(ef, old_pin, PIV_PIN_WIRE_SIZE, 2, NULL);
    if (ret != 0x9000) {
        return ret;
    }

    uint8_t dhash[34];
    dhash[0] = PIV_PIN_WIRE_SIZE;
    dhash[1] = 0x1; // Format
    pin_derive_verifier(CONST_BYTE_ARRAY(new_pin, PIV_PIN_WIRE_SIZE), dhash + 2);
    file_put_data(ef, CONST_BYTE_ARRAY(dhash, sizeof(dhash)));
    flash_commit();
    return SW_OK();
}
