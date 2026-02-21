#include "tecdsa/crypto/transcript.hpp"

#include <array>
#include <stdexcept>

#include <openssl/sha.h>

namespace tecdsa {
namespace {

void AppendU32Be(uint32_t value, Bytes* out) {
  out->push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
  out->push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
  out->push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
  out->push_back(static_cast<uint8_t>(value & 0xFF));
}

std::array<uint8_t, SHA256_DIGEST_LENGTH> Sha256(std::span<const uint8_t> input) {
  std::array<uint8_t, SHA256_DIGEST_LENGTH> digest{};
  if (SHA256(input.data(), input.size(), digest.data()) == nullptr) {
    throw std::runtime_error("SHA256 failed");
  }
  return digest;
}

}  // namespace

void Transcript::append(const std::string& label, std::span<const uint8_t> data) {
  if (label.size() > UINT32_MAX || data.size() > UINT32_MAX) {
    throw std::invalid_argument("Transcript field exceeds uint32 length");
  }

  AppendU32Be(static_cast<uint32_t>(label.size()), &transcript_);
  transcript_.insert(transcript_.end(), label.begin(), label.end());

  AppendU32Be(static_cast<uint32_t>(data.size()), &transcript_);
  transcript_.insert(transcript_.end(), data.begin(), data.end());
}

Scalar Transcript::challenge_scalar_mod_q() const {
  const auto digest = Sha256(transcript_);
  return Scalar::FromBigEndianModQ(digest);
}

const Bytes& Transcript::bytes() const {
  return transcript_;
}

}  // namespace tecdsa
