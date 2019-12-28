cmake_minimum_required(VERSION 3.1)
set(CMAKE_C_STANDARD 11)
project(glitchedhttps_examples C)

add_subdirectory(../ lib)

add_executable(example_get get/main.c)
add_executable(example_post post/main.c)

target_link_libraries(example_get PRIVATE glitchedhttps)
target_link_libraries(example_post PRIVATE glitchedhttps)
