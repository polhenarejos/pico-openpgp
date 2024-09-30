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

if(ESP_PLATFORM)
    set(EXTRA_COMPONENT_DIRS src pico-keys-sdk/src)
    include($ENV{IDF_PATH}/tools/cmake/project.cmake)
else()
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
endif()

set(SOURCES ${SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/src/openpgp/openpgp.c
    ${CMAKE_CURRENT_LIST_DIR}/src/openpgp/files.c
    ${CMAKE_CURRENT_LIST_DIR}/src/openpgp/piv.c
    ${CMAKE_CURRENT_LIST_DIR}/src/openpgp/management.c
)

set(USB_ITF_CCID 1)
set(USB_ITF_WCID 1)
include(pico-keys-sdk/pico_keys_sdk_import.cmake)
if(ESP_PLATFORM)
    project(pico_openpgp)
endif()

set(INCLUDES ${INCLUDES}
    ${CMAKE_CURRENT_LIST_DIR}/src/openpgp
)
if(NOT ESP_PLATFORM)
    target_sources(pico_openpgp PUBLIC ${SOURCES})
    target_include_directories(pico_openpgp PUBLIC ${INCLUDES})

    target_compile_options(pico_openpgp PUBLIC
            -Wall
    )
    if(NOT MSVC)
        target_compile_options(pico_openpgp PUBLIC
            -Werror
        )
    endif()

    if(ENABLE_EMULATION)
        if(NOT MSVC)
            target_compile_options(pico_openpgp PUBLIC
                -fdata-sections
                -ffunction-sections
            )
        endif()
        if(APPLE)
            target_link_options(pico_openpgp PUBLIC
                -Wl,-dead_strip
            )
        elseif(MSVC)
            target_compile_options(pico_openpgp PUBLIC
                -WX
            )

            target_link_libraries(pico_openpgp PUBLIC wsock32 ws2_32 Bcrypt)
        else()
            target_link_options(pico_openpgp PUBLIC
                -Wl,--gc-sections
            )
        endif(APPLE)
        target_link_libraries(pico_openpgp PRIVATE pthread m)
    endif()
endif()

