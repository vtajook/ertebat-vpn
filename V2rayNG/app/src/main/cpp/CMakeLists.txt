# OpenVPN 3 core (AGPL-3.0) built as libovpn3.so, driven from Kotlin through the SWIG bindings that
# scripts/gen-ovpn3-swig.sh generates into ./gen (C++) and app/src/main/java/net/openvpn/ovpn3 (Java).
# Dependencies are git submodules in <repo>/third_party and use mbedTLS as the TLS library.
cmake_minimum_required(VERSION 3.22.1)
project(egn_ovpn3 C CXX)

set(THIRD ${CMAKE_CURRENT_LIST_DIR}/../../../../../third_party)
get_filename_component(THIRD ${THIRD} ABSOLUTE)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_link_options("LINKER:--build-id=none")

# mbedTLS: library only
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
add_subdirectory(${THIRD}/mbedtls ${CMAKE_CURRENT_BINARY_DIR}/mbedtls EXCLUDE_FROM_ALL)

add_subdirectory(${THIRD}/fmt ${CMAKE_CURRENT_BINARY_DIR}/fmt EXCLUDE_FROM_ALL)

add_library(lz4 STATIC ${THIRD}/lz4/lib/lz4.c)
target_include_directories(lz4 PUBLIC ${THIRD}/lz4/lib)

execute_process(
    COMMAND git -C ${THIRD}/openvpn3 describe --tags --always --long
    OUTPUT_VARIABLE OPENVPN3_GIT OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
if(NOT OPENVPN3_GIT)
    set(OPENVPN3_GIT "unknown")
endif()

add_library(ovpn3 SHARED
    ${THIRD}/openvpn3/client/ovpncli.cpp
    ${THIRD}/openvpn3/openvpn/crypto/data_epoch.cpp
    ${CMAKE_CURRENT_LIST_DIR}/gen/ovpncli_wrap.cxx)

target_include_directories(ovpn3 PRIVATE
    ${THIRD}/openvpn3
    ${THIRD}/openvpn3/client
    ${THIRD}/asio/asio/include
    ${THIRD}/mbedtls/include)

target_compile_definitions(ovpn3 PRIVATE
    USE_MBEDTLS
    HAVE_CONFIG_H
    HAVE_LZ4
    ASIO_STANDALONE
    USE_ASIO
    OPENVPN_PLATFORM_ANDROID
    OPENVPN_CORE_GIT_VERSION="${OPENVPN3_GIT}"
    OPENVPN_ALLOW_INSECURE_CERTPROFILE
    OPENVPN_DISABLE_MBEDTLS_PLATFORM_ENTROPY_POLL)

target_link_libraries(ovpn3 mbedtls mbedx509 mbedcrypto lz4 fmt log)
