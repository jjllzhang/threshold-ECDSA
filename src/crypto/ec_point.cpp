#include "tecdsa/crypto/ec_point.hpp"

#include <algorithm>
#include <stdexcept>

namespace tecdsa {

ECPoint::ECPoint() {
  compressed_.fill(0);
}

ECPoint::ECPoint(std::span<const uint8_t> compressed_bytes)
    : ECPoint(FromCompressed(compressed_bytes)) {}

ECPoint ECPoint::FromCompressed(std::span<const uint8_t> compressed_bytes) {
  if (compressed_bytes.size() != 33) {
    throw std::invalid_argument("Compressed point must be 33 bytes");
  }

  if (compressed_bytes[0] != 0x02 && compressed_bytes[0] != 0x03) {
    throw std::invalid_argument("Compressed point prefix must be 0x02 or 0x03");
  }

  ECPoint out;
  std::copy(compressed_bytes.begin(), compressed_bytes.end(), out.compressed_.begin());
  return out;
}

Bytes ECPoint::ToCompressedBytes() const {
  return Bytes(compressed_.begin(), compressed_.end());
}

bool ECPoint::operator==(const ECPoint& other) const {
  return compressed_ == other.compressed_;
}

bool ECPoint::operator!=(const ECPoint& other) const {
  return !(*this == other);
}

}  // namespace tecdsa
