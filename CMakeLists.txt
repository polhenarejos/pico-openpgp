 #
 # This file is part of the Pico OpenPGP distribution (https://github.com/polhenarejos/pico-openpgp).
 # Copyright (c) 2022 Pol Henarejos.
 #
 # This program is free software: you can redistribute it and/or modify
 # it under the terms of the GNU General Public License as published by
 # the Free Software Foundation, version 3.
 #
 # This program is distributed in the hope that it will be useful, but
 # WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 # General Public License for more details.
 #
 # You should have received a copy of the GNU General Public License
 # along with this program. If not, see <http://www.gnu.org/licenses/>.
 #

cmake_minimum_required(VERSION 3.13)

include(pico_sdk_import.cmake)

project(pico_openpgp C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

pico_sdk_init()

add_executable(pico_openpgp)

if (NOT DEFINED USB_VID)
    set(USB_VID 0xFEFF)
endif()
add_definitions(-DUSB_VID=${USB_VID})
if (NOT DEFINED USB_PID)
    set(USB_PID 0xFCFD)
endif()
add_definitions(-DUSB_PID=${USB_PID})
if (NOT DEFINED DEBUG_APDU)
    set(DEBUG_APDU 0)
endif()
add_definitions(-DDEBUG_APDU=${DEBUG_APDU})

configure_file(${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/config/mbedtls_config.h ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/mbedtls/include/mbedtls COPYONLY)

target_sources(pico_openpgp PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/src/usb/usb.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/src/usb/ccid/usb_descriptors.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/src/usb/ccid/ccid.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/src/main.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/src/asn1.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/src/fs/file.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/src/fs/flash.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/src/fs/low_flash.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/src/rng/random.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/src/rng/hwrng.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/src/crypto_utils.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/src/eac.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/src/apdu.c
        ${CMAKE_CURRENT_LIST_DIR}/src/openpgp/openpgp.c
        ${CMAKE_CURRENT_LIST_DIR}/src/openpgp/files.c

        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/mbedtls/library/aes.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/mbedtls/library/asn1parse.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/mbedtls/library/bignum.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/mbedtls/library/cmac.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/mbedtls/library/cipher.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/mbedtls/library/cipher_wrap.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/mbedtls/library/constant_time.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/mbedtls/library/ecdsa.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/mbedtls/library/ecdh.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/mbedtls/library/ecp.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/mbedtls/library/ecp_curves.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/mbedtls/library/md.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/mbedtls/library/md5.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/mbedtls/library/oid.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/mbedtls/library/platform_util.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/mbedtls/library/ripemd160.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/mbedtls/library/rsa.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/mbedtls/library/rsa_alt_helpers.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/mbedtls/library/sha1.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/mbedtls/library/sha256.c
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/mbedtls/library/sha512.c
        )

target_include_directories(pico_openpgp PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/src/fs
        ${CMAKE_CURRENT_LIST_DIR}/src/openpgp
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/src/usb/ccid
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/src/rng
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/src/usb
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/src
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/mbedtls/include
        ${CMAKE_CURRENT_LIST_DIR}/pico-hsm-sdk/mbedtls/library
        )

target_compile_options(pico_openpgp PUBLIC
    -Wall
    -Werror
)

pico_add_extra_outputs(pico_openpgp)

#target_compile_definitions(pico_openpgp PRIVATE MBEDTLS_ECDSA_DETERMINISTIC=1)

target_link_libraries(pico_openpgp PRIVATE pico_stdlib tinyusb_device tinyusb_board pico_multicore hardware_flash hardware_sync hardware_adc pico_unique_id hardware_rtc)
