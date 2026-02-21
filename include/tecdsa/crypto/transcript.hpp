#pragma once

#include <span>
#include <string>

#include "tecdsa/common/bytes.hpp"
#include "tecdsa/crypto/scalar.hpp"

namespace tecdsa {

class Transcript {
 public:
  void append(const std::string& label, std::span<const uint8_t> data);
  Scalar challenge_scalar_mod_q() const;

  const Bytes& bytes() const;

 private:
  Bytes transcript_;
};

}  // namespace tecdsa
