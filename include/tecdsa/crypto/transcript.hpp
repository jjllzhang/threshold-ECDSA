#pragma once

#include <cstdint>
#include <initializer_list>
#include <span>
#include <string>
#include <string_view>

#include "tecdsa/common/bytes.hpp"
#include "tecdsa/crypto/scalar.hpp"

namespace tecdsa {

struct TranscriptFieldRef {
  std::string_view label;
  std::span<const uint8_t> data;
};

class Transcript {
 public:
  void append(std::string_view label, std::span<const uint8_t> data);
  void append_u32_be(std::string_view label, uint32_t value);
  void append_fields(std::initializer_list<TranscriptFieldRef> fields);
  Scalar challenge_scalar_mod_q() const;

  const Bytes& bytes() const;

 private:
  Bytes transcript_;
};

}  // namespace tecdsa
