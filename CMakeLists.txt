cmake_minimum_required(VERSION 3.1)
project(glitchedhttps C)

set(CMAKE_C_STANDARD 11)
add_subdirectory(lib/mbedtls)

add_library(glitchedhttps
        ${CMAKE_CURRENT_LIST_DIR}/lib/chillbuff/include/chillbuff.h
        ${CMAKE_CURRENT_LIST_DIR}/include/glitchedhttps.h
        ${CMAKE_CURRENT_LIST_DIR}/src/glitchedhttps.c)

target_include_directories(glitchedhttps PUBLIC include)
target_include_directories(glitchedhttps PRIVATE lib/chillbuff/include)

if (UNIX AND NOT APPLE)
    target_link_libraries(glitchedhttps PRIVATE -luuid -lm)
endif ()

target_link_libraries(glitchedhttps PRIVATE mbedtls mbedx509)
