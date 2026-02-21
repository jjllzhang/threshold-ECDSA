#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include <gmpxx.h>

#include "tecdsa/common/bytes.hpp"
#include "tecdsa/crypto/ec_point.hpp"

namespace tecdsa {

Bytes EncodeMpz(const mpz_class& value);
mpz_class DecodeMpz(std::span<const uint8_t> encoded, size_t max_len = 8192);

Bytes EncodePoint(const ECPoint& point);
ECPoint DecodePoint(std::span<const uint8_t> encoded);

}  // namespace tecdsa
