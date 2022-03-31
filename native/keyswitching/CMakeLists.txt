# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.13)

project(SEALKEYSWITCHING VERSION 3.7.1 LANGUAGES CXX)

# If not called from root CMakeLists.txt
if(NOT DEFINED SEAL_BUILD_KEYSWITCHING)
    set(SEAL_BUILD_KEYSWITCHING ON)

    # Import Microsoft SEAL
    find_package(SEAL 3.7.1 EXACT REQUIRED)
    set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
    set(THREADS_PREFER_PTHREAD_FLAG TRUE)
    find_package(Threads REQUIRED)

    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
endif()

if(SEAL_BUILD_KEYSWITCHING)
    add_executable(sealkeyswitching)

    target_sources(sealkeyswitching
        PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/test.cpp
            ${CMAKE_CURRENT_LIST_DIR}/aes_he.cpp
            ${CMAKE_CURRENT_LIST_DIR}/sbox.cpp
            ${CMAKE_CURRENT_LIST_DIR}/GF256.cpp
    )

    find_package(OpenMP)
    if(OpenMP_CXX_FOUND)
        target_link_libraries(sealkeyswitching PUBLIC OpenMP::OpenMP_CXX)
    endif()

    if(TARGET SEAL::seal)
    #target_compile_options(sealsbox PRIVATE -fsanitize=address)
    #target_link_options(sealsbox PRIVATE -fsanitize=address)

        target_link_libraries(sealkeyswitching PRIVATE SEAL::seal)
    elseif(TARGET SEAL::seal_shared)
        target_link_libraries(sealkeyswitching PRIVATE SEAL::seal_shared)
    else()
        message(FATAL_ERROR "Cannot find target SEAL::seal or SEAL::seal_shared")
    endif()
endif()
