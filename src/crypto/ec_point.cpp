#include "tecdsa/crypto/ec_point.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

extern "C" {
#include <secp256k1.h>
}

namespace tecdsa {
namespace {

secp256k1_context* GetSecpContext() {
  static secp256k1_context* ctx = []() {
    secp256k1_context* created = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (created == nullptr) {
      throw std::runtime_error("Failed to create secp256k1 context");
    }
    return created;
  }();
  return ctx;
}

secp256k1_pubkey ParsePubkey(const std::array<uint8_t, 33>& compressed) {
  secp256k1_pubkey pubkey;
  if (secp256k1_ec_pubkey_parse(GetSecpContext(), &pubkey, compressed.data(), compressed.size()) != 1) {
    throw std::invalid_argument("Compressed point is not a valid secp256k1 point");
  }
  return pubkey;
}

std::array<uint8_t, 32> ToScalarBytes(const Scalar& scalar) {
  return scalar.ToCanonicalBytes();
}

std::array<uint8_t, 33> SerializeCompressed(const secp256k1_pubkey& pubkey) {
  std::array<uint8_t, 33> out{};
  size_t out_len = out.size();
  if (secp256k1_ec_pubkey_serialize(
          GetSecpContext(), out.data(), &out_len, &pubkey, SECP256K1_EC_COMPRESSED) != 1 ||
      out_len != out.size()) {
    throw std::runtime_error("Failed to serialize secp256k1 point");
  }
  return out;
}

}  // namespace

ECPoint::ECPoint() {
  compressed_.fill(0);
  compressed_[0] = 0x02;
}

ECPoint ECPoint::FromCompressed(std::span<const uint8_t> compressed_bytes) {
  if (compressed_bytes.size() != 33) {
    throw std::invalid_argument("Compressed point must be 33 bytes");
  }

  std::array<uint8_t, 33> compressed{};
  std::copy(compressed_bytes.begin(), compressed_bytes.end(), compressed.begin());
  (void)ParsePubkey(compressed);

  ECPoint out;
  out.compressed_ = compressed;
  return out;
}

ECPoint ECPoint::GeneratorMultiply(const Scalar& scalar) {
  std::array<uint8_t, 32> scalar_bytes = ToScalarBytes(scalar);

  secp256k1_pubkey pubkey;
  if (secp256k1_ec_pubkey_create(GetSecpContext(), &pubkey, scalar_bytes.data()) != 1) {
    throw std::invalid_argument("Generator multiplication failed: scalar must be in [1, q-1]");
  }

  ECPoint out;
  out.compressed_ = SerializeCompressed(pubkey);
  return out;
}

ECPoint ECPoint::Add(const ECPoint& other) const {
  secp256k1_pubkey lhs = ParsePubkey(compressed_);
  secp256k1_pubkey rhs = ParsePubkey(other.compressed_);

  const secp256k1_pubkey* inputs[2] = {&lhs, &rhs};
  secp256k1_pubkey combined;
  if (secp256k1_ec_pubkey_combine(GetSecpContext(), &combined, inputs, 2) != 1) {
    throw std::invalid_argument("Point addition failed (sum is point at infinity?)");
  }

  ECPoint out;
  out.compressed_ = SerializeCompressed(combined);
  return out;
}

ECPoint ECPoint::Mul(const Scalar& scalar) const {
  secp256k1_pubkey pubkey = ParsePubkey(compressed_);
  std::array<uint8_t, 32> scalar_bytes = ToScalarBytes(scalar);

  if (secp256k1_ec_pubkey_tweak_mul(GetSecpContext(), &pubkey, scalar_bytes.data()) != 1) {
    throw std::invalid_argument("Point scalar multiplication failed");
  }

  ECPoint out;
  out.compressed_ = SerializeCompressed(pubkey);
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
