cmake_minimum_required(VERSION 3.20)
project(threshold_ecdsa LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL QUIET)
find_package(OpenMP QUIET)

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
if(OpenMP_C_FOUND)
  target_link_libraries(hcs_vendor PUBLIC OpenMP::OpenMP_C)
endif()

add_library(tecdsa_m0
  src/crypto/scalar.cpp
  src/crypto/ec_point.cpp
  src/crypto/encoding.cpp
  src/crypto/paillier.cpp
  src/crypto/transcript.cpp
  src/net/envelope.cpp
)

target_include_directories(tecdsa_m0 PUBLIC include)

target_link_libraries(tecdsa_m0 PUBLIC gmpxx gmp hcs_vendor)
if(OpenSSL_FOUND)
  target_link_libraries(tecdsa_m0 PUBLIC OpenSSL::Crypto)
else()
  target_link_libraries(tecdsa_m0 PUBLIC crypto)
endif()

add_executable(m0_tests tests/m0_tests.cpp)
target_link_libraries(m0_tests PRIVATE tecdsa_m0)

enable_testing()
add_test(NAME m0_tests COMMAND m0_tests)
