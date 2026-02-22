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

add_library(tecdsa_m0
  src/crypto/scalar.cpp
  src/crypto/ec_point.cpp
  src/crypto/hash.cpp
  src/crypto/random.cpp
  src/crypto/commitment.cpp
  src/crypto/encoding.cpp
  src/crypto/paillier.cpp
  src/crypto/transcript.cpp
  src/net/envelope.cpp
  src/net/in_memory_transport.cpp
  src/protocol/session.cpp
  src/protocol/session_router.cpp
  src/protocol/keygen_session.cpp
  src/protocol/sign_session.cpp
)

target_include_directories(tecdsa_m0 PUBLIC include)

target_link_libraries(tecdsa_m0 PUBLIC gmpxx gmp hcs_vendor secp256k1)
if(OpenSSL_FOUND)
  target_link_libraries(tecdsa_m0 PUBLIC OpenSSL::Crypto)
else()
  target_link_libraries(tecdsa_m0 PUBLIC crypto)
endif()

add_executable(m0_tests tests/m0_tests.cpp)
target_link_libraries(m0_tests PRIVATE tecdsa_m0)

add_executable(m2_tests tests/m2_tests.cpp)
target_link_libraries(m2_tests PRIVATE tecdsa_m0)

enable_testing()
add_test(NAME m0_tests COMMAND m0_tests)
add_test(NAME m2_tests COMMAND m2_tests)
