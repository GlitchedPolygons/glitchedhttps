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
set(CMAKE_C_STANDARD 11)
project(glitchedhttps_examples C)

add_executable(glitchedhttps_example_get get/main.c)
add_executable(glitchedhttps_example_put put/main.c)
add_executable(glitchedhttps_example_post post/main.c)
add_executable(glitchedhttps_example_delete delete/main.c)

target_link_libraries(glitchedhttps_example_get PRIVATE glitchedhttps)
target_link_libraries(glitchedhttps_example_put PRIVATE glitchedhttps)
target_link_libraries(glitchedhttps_example_post PRIVATE glitchedhttps)
target_link_libraries(glitchedhttps_example_delete PRIVATE glitchedhttps)
