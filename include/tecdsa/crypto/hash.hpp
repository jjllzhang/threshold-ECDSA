#pragma once

#include <span>

#include "tecdsa/common/bytes.hpp"

namespace tecdsa {

Bytes Sha256(std::span<const uint8_t> data);
Bytes Sha512(std::span<const uint8_t> data);

}  // namespace tecdsa
