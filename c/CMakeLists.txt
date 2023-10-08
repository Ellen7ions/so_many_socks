cmake_minimum_required(VERSION 3.14)
project(c_socks)

add_executable(socks5_server socks5_server.c)

if (${CMAKE_BUILD_TYPE} MATCHES "Debug")
    target_compile_definitions(socks5_server PUBLIC SOCKS_DEBUG)
endif()