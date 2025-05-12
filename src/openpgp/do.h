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

extern const uint8_t algorithm_attr_p256k1[];
extern const uint8_t algorithm_attr_p256r1[];
extern const uint8_t algorithm_attr_p384r1[];
extern const uint8_t algorithm_attr_p521r1[];
extern const uint8_t algorithm_attr_bp256r1[];
extern const uint8_t algorithm_attr_bp384r1[];
extern const uint8_t algorithm_attr_bp512r1[];
extern const uint8_t algorithm_attr_cv25519[];
extern const uint8_t algorithm_attr_x448[];
extern const uint8_t algorithm_attr_rsa2k[];
extern const uint8_t algorithm_attr_rsa4096[];
#ifdef MBEDTLS_EDDSA_C
extern const uint8_t algorithm_attr_ed25519[];
extern const uint8_t algorithm_attr_ed448[];
#endif
