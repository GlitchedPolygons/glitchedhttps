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

add_library(glitchedhttps INTERFACE)

target_include_directories(glitchedhttps INTERFACE include lib/chillbuff/include)

if (UNIX AND NOT APPLE)
    target_link_libraries(glitchedhttps INTERFACE -luuid -lm)
endif ()

target_link_libraries(glitchedhttps INTERFACE mbedtls mbedx509)
