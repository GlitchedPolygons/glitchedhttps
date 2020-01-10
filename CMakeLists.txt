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

add_subdirectory(lib/mbedtls)
add_subdirectory(lib/chillbuff)

set(glitchedhttps_headers
        lib/chillbuff/include/chillbuff.h
        include/glitchedhttps_exitcodes.h
        include/glitchedhttps_cacerts.h
        include/glitchedhttps_strutil.h
        include/glitchedhttps_debug.h
        include/glitchedhttps_guid.h
        include/glitchedhttps_method.h
        include/glitchedhttps_header.h
        include/glitchedhttps_request.h
        include/glitchedhttps_response.h
        include/glitchedhttps.h
        )

set(glitchedhttps_sources
        src/glitchedhttps.c
        src/glitchedhttps_debug.c
        src/glitchedhttps_guid.c
        src/glitchedhttps_method.c
        src/glitchedhttps_header.c
        src/glitchedhttps_response.c
        )

add_library(glitchedhttps ${glitchedhttps_headers} ${glitchedhttps_sources})

target_include_directories(glitchedhttps PUBLIC include)
target_include_directories(glitchedhttps PRIVATE lib/chillbuff/include)

if (UNIX AND NOT APPLE)
    target_link_libraries(glitchedhttps PRIVATE -luuid -lm)
endif ()

target_link_libraries(glitchedhttps PRIVATE mbedtls mbedx509)
