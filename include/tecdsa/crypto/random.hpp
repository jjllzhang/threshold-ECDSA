#pragma once

#include <cstddef>

#include "tecdsa/common/bytes.hpp"
#include "tecdsa/crypto/scalar.hpp"

namespace tecdsa {

class Csprng {
 public:
  static Bytes RandomBytes(size_t size);
  static Scalar RandomScalar();
};

}  // namespace tecdsa
