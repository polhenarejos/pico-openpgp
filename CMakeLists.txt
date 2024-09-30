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

if(ENABLE_EMULATION)
else()
include(pico_sdk_import.cmake)
endif()

project(pico_openpgp C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

if(ENABLE_EMULATION)
else()
pico_sdk_init()
endif()

add_executable(pico_openpgp)

set(SOURCES ${SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/src/openpgp/openpgp.c
        ${CMAKE_CURRENT_LIST_DIR}/src/openpgp/files.c
        )

set(INCLUDES ${INCLUDES}
        ${CMAKE_CURRENT_LIST_DIR}/src/openpgp
        )

set(USB_ITF_CCID 1)
include(pico-keys-sdk/pico_keys_sdk_import.cmake)

target_sources(pico_openpgp PUBLIC ${SOURCES})
target_include_directories(pico_openpgp PUBLIC ${INCLUDES})

target_compile_options(pico_openpgp PUBLIC
    -Wall
    -Werror
)

if(ENABLE_EMULATION)

target_compile_options(pico_openpgp PUBLIC
        -fdata-sections
        -ffunction-sections
        )
if(APPLE)
target_link_options(pico_openpgp PUBLIC
        -Wl,-dead_strip
        )
else()
target_link_options(pico_openpgp PUBLIC
        -Wl,--gc-sections
        )
endif (APPLE)
else()

pico_add_extra_outputs(pico_openpgp)

#target_compile_definitions(pico_openpgp PRIVATE MBEDTLS_ECDSA_DETERMINISTIC=1)

target_link_libraries(pico_openpgp PRIVATE pico_hsm_sdk pico_stdlib tinyusb_device tinyusb_board pico_multicore hardware_flash hardware_sync hardware_adc pico_unique_id hardware_rtc)
endif()
