# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.13)

project(SEALSBOX VERSION 3.7.1 LANGUAGES CXX)

# If not called from root CMakeLists.txt
if(NOT DEFINED SEAL_BUILD_SBOX)
    set(SEAL_BUILD_SBOX ON)

    # Import Microsoft SEAL
    find_package(SEAL 3.7.1 EXACT REQUIRED)

    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
endif()

if(SEAL_BUILD_SBOX)
    add_executable(sealsbox)

    target_sources(sealsbox
        PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/test.cpp
    )

    if(TARGET SEAL::seal)
        target_link_libraries(sealsbox PRIVATE SEAL::seal)
    elseif(TARGET SEAL::seal_shared)
        target_link_libraries(sealsbox PRIVATE SEAL::seal_shared)
    else()
        message(FATAL_ERROR "Cannot find target SEAL::seal or SEAL::seal_shared")
    endif()
endif()
