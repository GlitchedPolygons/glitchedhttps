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
