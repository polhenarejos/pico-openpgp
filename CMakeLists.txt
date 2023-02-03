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

target_sources(pico_openpgp PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/src/openpgp/openpgp.c
        ${CMAKE_CURRENT_LIST_DIR}/src/openpgp/files.c
        )

target_include_directories(pico_openpgp PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/src/openpgp
        )

set(USB_ITF_CCID 1)
include(pico-hsm-sdk/pico_hsm_sdk_import.cmake)

target_compile_options(pico_openpgp PUBLIC
    -Wall
    -Werror
)

pico_add_extra_outputs(pico_openpgp)

#target_compile_definitions(pico_openpgp PRIVATE MBEDTLS_ECDSA_DETERMINISTIC=1)

target_link_libraries(pico_openpgp PRIVATE pico_hsm_sdk pico_stdlib tinyusb_device tinyusb_board pico_multicore hardware_flash hardware_sync hardware_adc pico_unique_id hardware_rtc)
