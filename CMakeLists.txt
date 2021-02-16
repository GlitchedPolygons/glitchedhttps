#  Copyright 2019 Raphael Beck
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

cmake_minimum_required(VERSION 3.1)
project(glitchedhttps C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake" ${CMAKE_MODULE_PATH})

option(GLITCHEDHTTPS_ENABLE_TESTS "Build GlitchedHTTPS tests." OFF)
option(GLITCHEDHTTPS_ENABLE_EXAMPLES "Build GlitchedHTTPS example programs." OFF)

option(ENABLE_TESTING "Build MbedTLS tests." OFF)
option(ENABLE_PROGRAMS "Build MbedTLS example programs." OFF)

if (NOT TARGET mbedtls)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/mbedtls mbedtls)
endif ()

set(glitchedhttps_headers
        ${CMAKE_CURRENT_LIST_DIR}/lib/chillbuff/include/chillbuff.h
        ${CMAKE_CURRENT_LIST_DIR}/include/glitchedhttps_exitcodes.h
        ${CMAKE_CURRENT_LIST_DIR}/include/glitchedhttps_cacerts.h
        ${CMAKE_CURRENT_LIST_DIR}/include/glitchedhttps_strutil.h
        ${CMAKE_CURRENT_LIST_DIR}/include/glitchedhttps_debug.h
        ${CMAKE_CURRENT_LIST_DIR}/include/glitchedhttps_guid.h
        ${CMAKE_CURRENT_LIST_DIR}/include/glitchedhttps_method.h
        ${CMAKE_CURRENT_LIST_DIR}/include/glitchedhttps_header.h
        ${CMAKE_CURRENT_LIST_DIR}/include/glitchedhttps_request.h
        ${CMAKE_CURRENT_LIST_DIR}/include/glitchedhttps_response.h
        ${CMAKE_CURRENT_LIST_DIR}/include/glitchedhttps.h
        )

set(glitchedhttps_sources
        ${CMAKE_CURRENT_LIST_DIR}/src/glitchedhttps.c
        ${CMAKE_CURRENT_LIST_DIR}/src/glitchedhttps_debug.c
        ${CMAKE_CURRENT_LIST_DIR}/src/glitchedhttps_guid.c
        ${CMAKE_CURRENT_LIST_DIR}/src/glitchedhttps_method.c
        ${CMAKE_CURRENT_LIST_DIR}/src/glitchedhttps_header.c
        ${CMAKE_CURRENT_LIST_DIR}/src/glitchedhttps_cacerts.c
        ${CMAKE_CURRENT_LIST_DIR}/src/glitchedhttps_response.c
        )

add_library(glitchedhttps ${glitchedhttps_headers} ${glitchedhttps_sources})

target_include_directories(glitchedhttps PUBLIC include)
target_include_directories(glitchedhttps PRIVATE ${CMAKE_CURRENT_LIST_DIR}lib/mbedtls/include)
target_include_directories(glitchedhttps PRIVATE ${CMAKE_CURRENT_LIST_DIR}lib/chillbuff/include)

if (UNIX AND NOT APPLE)
    target_link_libraries(glitchedhttps PRIVATE -luuid -lm)
endif ()

target_link_libraries(glitchedhttps PRIVATE mbedtls mbedx509 mbedcrypto)

if (GLITCHEDHTTPS_ENABLE_EXAMPLES)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/examples)
endif ()

if (GLITCHEDHTTPS_ENABLE_TESTS)

    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--wrap=malloc,--wrap=calloc")

    if (WIN32 AND BUILD_SHARED_LIBS)
        set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
    endif ()

    find_package(cmocka)

    if (NOT ${cmocka_FOUND})
        message(STATUS "cmocka not found; using included version inside tests/ folder...")
        add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/tests/cmocka cmocka)
    else ()
        message(STATUS "Found cmocka!")
    endif ()

    set(TESTS ${CMAKE_CURRENT_LIST_DIR}/tests/tests.c)

    add_executable(run_tests ${TESTS})

    target_include_directories(run_tests PUBLIC ${cmocka_INCLUDE_DIR})
    target_link_libraries(run_tests PUBLIC glitchedhttps cmocka)

    if (ENABLE_COVERAGE)
        if (GLITCHEDHTTPS_ENABLE_EXAMPLES)
            message(FATAL_ERROR "ENABLE_COVERAGE and GLITCHEDHTTPS_ENABLE_EXAMPLES are MUTUALLY EXCLUSIVE! Please enable either one or the other, but not both at the same time!")
        else ()
            find_package(codecov)
            add_coverage(glitchedhttps)
            add_coverage(run_tests)
            coverage_evaluate()
        endif ()
    endif ()
endif ()
