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

cmake_minimum_required(VERSION 3.12)
project(glitchedhttps C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake" ${CMAKE_MODULE_PATH})

set(${PROJECT_NAME}_MAJOR 0)
set(${PROJECT_NAME}_MINOR 9)
set(${PROJECT_NAME}_PATCH 2)
set(${PROJECT_NAME}_VERSION_STRING "${${PROJECT_NAME}_MAJOR}.${${PROJECT_NAME}_MINOR}.${${PROJECT_NAME}_PATCH}")

option(${PROJECT_NAME}_ENABLE_EXAMPLES "Build GlitchedHTTPS example programs." OFF)
option(${PROJECT_NAME}_DLL "Use as a DLL." OFF)
option(${PROJECT_NAME}_BUILD_DLL "Build as a DLL." OFF)
option(${PROJECT_NAME}_PACKAGE "Build the library and package it into a .tar.gz after successfully building." OFF)

option(ENABLE_TESTING "Build MbedTLS tests." OFF)
option(ENABLE_PROGRAMS "Build MbedTLS example programs." OFF)


if (${${PROJECT_NAME}_BUILD_DLL})
    add_compile_definitions("GLITCHEDHTTPS_BUILD_DLL=1")
    set(${PROJECT_NAME}_DLL ON)
endif ()

if (${${PROJECT_NAME}_DLL})
    add_compile_definitions("GLITCHEDHTTPS_DLL=1")
endif ()

set(${PROJECT_NAME}_INCLUDE_DIR
        ${CMAKE_CURRENT_LIST_DIR}/include
        )

set(${PROJECT_NAME}_headers
        ${CMAKE_CURRENT_LIST_DIR}/lib/chillbuff/include/chillbuff.h
        ${CMAKE_CURRENT_LIST_DIR}/include/glitchedhttps_api.h
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

set(${PROJECT_NAME}_sources
        ${CMAKE_CURRENT_LIST_DIR}/src/glitchedhttps.c
        ${CMAKE_CURRENT_LIST_DIR}/src/glitchedhttps_debug.c
        ${CMAKE_CURRENT_LIST_DIR}/src/glitchedhttps_guid.c
        ${CMAKE_CURRENT_LIST_DIR}/src/glitchedhttps_method.c
        ${CMAKE_CURRENT_LIST_DIR}/src/glitchedhttps_header.c
        ${CMAKE_CURRENT_LIST_DIR}/src/glitchedhttps_cacerts.c
        ${CMAKE_CURRENT_LIST_DIR}/src/glitchedhttps_response.c
        )

add_library(${PROJECT_NAME}
        ${${PROJECT_NAME}_headers}
        ${${PROJECT_NAME}_sources}
        )

if (NOT TARGET mbedtls)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/mbedtls mbedtls)
endif ()

if (${${PROJECT_NAME}_BUILD_DLL} OR BUILD_SHARED_LIBS)
    set_property(TARGET mbedtls PROPERTY POSITION_INDEPENDENT_CODE ON)
    set_property(TARGET mbedx509 PROPERTY POSITION_INDEPENDENT_CODE ON)
    set_property(TARGET mbedcrypto PROPERTY POSITION_INDEPENDENT_CODE ON)
    set_target_properties(${PROJECT_NAME} PROPERTIES
            VERSION ${${PROJECT_NAME}_VERSION_STRING}
            SOVERSION ${${PROJECT_NAME}_MAJOR}
            )
endif ()

if (${${PROJECT_NAME}_PACKAGE})

    if (NOT ${PROJECT_NAME}_SYSNAME)
        set(${PROJECT_NAME}_SYSNAME ${CMAKE_SYSTEM_NAME})
    endif ()
    
    set_target_properties(${PROJECT_NAME} PROPERTIES
            ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin"
            LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin"
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin"

            ARCHIVE_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/debug"
            LIBRARY_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/debug"
            RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/debug"

            ARCHIVE_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/release"
            LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/release"
            RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/release"
            )

    add_custom_command(TARGET ${PROJECT_NAME}
            POST_BUILD COMMAND ${CMAKE_COMMAND}
            -E copy ${CMAKE_CURRENT_LIST_DIR}/NOTICE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/NOTICE"
            )

    add_custom_command(TARGET ${PROJECT_NAME}
            POST_BUILD COMMAND ${CMAKE_COMMAND}
            -E copy_directory ${CMAKE_CURRENT_LIST_DIR}/include "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/include"
            )

    string(TOLOWER "${PROJECT_NAME}-${${PROJECT_NAME}_VERSION_STRING}-${${PROJECT_NAME}_SYSNAME}-${CMAKE_HOST_SYSTEM_PROCESSOR}.tar.gz" ${PROJECT_NAME}_OUTPUT_ARCHIVE_FILENAME)

    add_custom_command(TARGET ${PROJECT_NAME}
            POST_BUILD COMMAND ${CMAKE_COMMAND}
            -E tar "czvf" ${${PROJECT_NAME}_OUTPUT_ARCHIVE_FILENAME} ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}
            )
endif ()

target_include_directories(${PROJECT_NAME} PUBLIC include)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_LIST_DIR}/lib/mbedtls/include)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_LIST_DIR}/lib/chillbuff/include)

if ((${CMAKE_SYSTEM_NAME} STREQUAL "Linux") OR (${CYGWIN}))
    target_link_libraries(${PROJECT_NAME} PRIVATE -luuid -lm)
endif ()

if (WIN32)
    target_link_libraries(${PROJECT_NAME} PUBLIC bcrypt)
endif ()

target_link_libraries(${PROJECT_NAME} PRIVATE mbedtls mbedx509 mbedcrypto)

if (${${PROJECT_NAME}_ENABLE_EXAMPLES})
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/examples)
endif ()
