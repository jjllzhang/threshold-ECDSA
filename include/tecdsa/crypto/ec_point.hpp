#pragma once

#include <array>
#include <cstdint>
#include <span>

#include "tecdsa/common/bytes.hpp"

namespace tecdsa {

class ECPoint {
 public:
  ECPoint();
  explicit ECPoint(std::span<const uint8_t> compressed_bytes);

  static ECPoint FromCompressed(std::span<const uint8_t> compressed_bytes);
  Bytes ToCompressedBytes() const;

  bool operator==(const ECPoint& other) const;
  bool operator!=(const ECPoint& other) const;

 private:
  std::array<uint8_t, 33> compressed_{};
};

}  // namespace tecdsa
