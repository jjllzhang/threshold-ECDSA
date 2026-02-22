cmake_minimum_required(VERSION 3.22)
project(threshold_ecdsa LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL QUIET)

set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_CTIME_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SECP256K1_INSTALL OFF CACHE BOOL "" FORCE)
add_subdirectory(third_party/secp256k1 EXCLUDE_FROM_ALL)

file(GLOB LIBHCS_VENDOR_SOURCES CONFIGURE_DEPENDS
  third_party/libhcs/src/*.c
  third_party/libhcs/src/com/*.c
)

add_library(hcs_vendor STATIC ${LIBHCS_VENDOR_SOURCES})
target_include_directories(hcs_vendor PUBLIC third_party/libhcs/include)
target_link_libraries(hcs_vendor PUBLIC gmp)
set_target_properties(hcs_vendor PROPERTIES
  C_STANDARD 99
  C_STANDARD_REQUIRED ON
)

add_library(tecdsa_core
  src/crypto/scalar.cpp
  src/crypto/ec_point.cpp
  src/crypto/hash.cpp
  src/crypto/random.cpp
  src/crypto/commitment.cpp
  src/crypto/encoding.cpp
  src/crypto/paillier.cpp
  src/crypto/strict_proofs.cpp
  src/crypto/transcript.cpp
  src/net/envelope.cpp
  src/net/in_memory_transport.cpp
  src/protocol/session.cpp
  src/protocol/session_router.cpp
  src/protocol/keygen_session.cpp
  src/protocol/sign_session.cpp
)

target_include_directories(tecdsa_core PUBLIC include)

target_link_libraries(tecdsa_core PUBLIC gmpxx gmp hcs_vendor secp256k1)
if(OpenSSL_FOUND)
  target_link_libraries(tecdsa_core PUBLIC OpenSSL::Crypto)
else()
  target_link_libraries(tecdsa_core PUBLIC crypto)
endif()

add_library(tecdsa_m0 ALIAS tecdsa_core)

add_executable(crypto_primitives_tests tests/crypto_primitives_tests.cpp)
target_link_libraries(crypto_primitives_tests PRIVATE tecdsa_core)

add_executable(protocol_infrastructure_tests tests/protocol_infrastructure_tests.cpp)
target_link_libraries(protocol_infrastructure_tests PRIVATE tecdsa_core)

add_executable(keygen_flow_tests tests/keygen_flow_tests.cpp)
target_link_libraries(keygen_flow_tests PRIVATE tecdsa_core)

add_executable(sign_flow_tests tests/sign_flow_tests.cpp)
target_link_libraries(sign_flow_tests PRIVATE tecdsa_core)

add_executable(protocol_flow_bench bench/protocol_flow_bench.cpp)
target_link_libraries(protocol_flow_bench PRIVATE tecdsa_core)

enable_testing()
add_test(NAME crypto_primitives_tests COMMAND crypto_primitives_tests)
add_test(NAME protocol_infrastructure_tests COMMAND protocol_infrastructure_tests)
add_test(NAME keygen_flow_tests COMMAND keygen_flow_tests)
add_test(NAME sign_flow_tests COMMAND sign_flow_tests)
