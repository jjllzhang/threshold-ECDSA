#include "tecdsa/crypto/strict_proofs.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>

#include "tecdsa/crypto/encoding.hpp"
#include "tecdsa/crypto/hash.hpp"
#include "tecdsa/crypto/random.hpp"
#include "tecdsa/crypto/transcript.hpp"

namespace tecdsa {
namespace {

constexpr char kSquareFreeProofId[] = "GG2019/SquareFreeDevDigest/v1";
constexpr char kAuxParamProofId[] = "GG2019/AuxParamDevDigest/v1";
constexpr uint32_t kProofWireMagic = 0x53505231;  // "SPR1"
constexpr uint32_t kDevProofVersion = 1;

void AppendU32Be(uint32_t value, Bytes* out) {
  out->push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
  out->push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
  out->push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
  out->push_back(static_cast<uint8_t>(value & 0xFF));
}

uint32_t ReadU32Be(std::span<const uint8_t> input, size_t* offset) {
  if (*offset + 4 > input.size()) {
    throw std::invalid_argument("Not enough bytes to read u32");
  }

  const size_t i = *offset;
  *offset += 4;
  return (static_cast<uint32_t>(input[i]) << 24) |
         (static_cast<uint32_t>(input[i + 1]) << 16) |
         (static_cast<uint32_t>(input[i + 2]) << 8) |
         static_cast<uint32_t>(input[i + 3]);
}

uint32_t SchemeToU32(StrictProofScheme scheme) {
  return static_cast<uint32_t>(scheme);
}

StrictProofScheme U32ToScheme(uint32_t raw) {
  switch (raw) {
    case static_cast<uint32_t>(StrictProofScheme::kUnknown):
      return StrictProofScheme::kUnknown;
    case static_cast<uint32_t>(StrictProofScheme::kDevDigestBindingV1):
      return StrictProofScheme::kDevDigestBindingV1;
    case static_cast<uint32_t>(StrictProofScheme::kStrictExternalV1):
      return StrictProofScheme::kStrictExternalV1;
    default:
      return StrictProofScheme::kUnknown;
  }
}

ProofMetadata DevProofMetadata() {
  return ProofMetadata{
      .scheme = StrictProofScheme::kDevDigestBindingV1,
      .version = kDevProofVersion,
  };
}

Bytes EncodeProofWire(const ProofMetadata& metadata, std::span<const uint8_t> blob) {
  // Preserve legacy format for unknown metadata, where payload is raw blob only.
  if (metadata.scheme == StrictProofScheme::kUnknown && metadata.version == 0) {
    return Bytes(blob.begin(), blob.end());
  }

  if (blob.size() > UINT32_MAX) {
    throw std::invalid_argument("proof blob exceeds uint32 length");
  }

  Bytes out;
  out.reserve(16 + blob.size());
  AppendU32Be(kProofWireMagic, &out);
  AppendU32Be(SchemeToU32(metadata.scheme), &out);
  AppendU32Be(metadata.version, &out);
  AppendU32Be(static_cast<uint32_t>(blob.size()), &out);
  out.insert(out.end(), blob.begin(), blob.end());
  return out;
}

std::pair<ProofMetadata, Bytes> DecodeProofWire(std::span<const uint8_t> encoded, size_t max_len) {
  if (encoded.empty()) {
    return {ProofMetadata{}, Bytes{}};
  }

  if (encoded.size() >= 16) {
    size_t offset = 0;
    const uint32_t magic = ReadU32Be(encoded, &offset);
    if (magic == kProofWireMagic) {
      const StrictProofScheme scheme = U32ToScheme(ReadU32Be(encoded, &offset));
      const uint32_t version = ReadU32Be(encoded, &offset);
      const uint32_t blob_len = ReadU32Be(encoded, &offset);
      if (blob_len > max_len) {
        throw std::invalid_argument("proof blob exceeds maximum length");
      }
      if (offset + blob_len != encoded.size()) {
        throw std::invalid_argument("proof wire payload has inconsistent length");
      }

      Bytes blob(
          encoded.begin() + static_cast<std::ptrdiff_t>(offset),
          encoded.begin() + static_cast<std::ptrdiff_t>(offset + blob_len));
      return {
          ProofMetadata{
              .scheme = scheme,
              .version = version,
          },
          std::move(blob),
      };
    }
  }

  if (encoded.size() > max_len) {
    throw std::invalid_argument("legacy proof blob exceeds maximum length");
  }
  return {ProofMetadata{}, Bytes(encoded.begin(), encoded.end())};
}

mpz_class PickCoprime(const mpz_class& modulus, const mpz_class& seed) {
  mpz_class value = seed % modulus;
  if (value < 2) {
    value = 2;
  }

  while (true) {
    if (value >= modulus) {
      value = 2;
    }
    mpz_class gcd;
    mpz_gcd(gcd.get_mpz_t(), value.get_mpz_t(), modulus.get_mpz_t());
    if (gcd == 1) {
      return value;
    }
    ++value;
  }
}

Bytes BuildProofDigest(const char* proof_id,
                       const std::array<std::pair<const char*, Bytes>, 1>& fields) {
  Transcript transcript;
  const std::span<const uint8_t> proof_id_view(
      reinterpret_cast<const uint8_t*>(proof_id), std::strlen(proof_id));
  transcript.append("proof_id", proof_id_view);
  for (const auto& [label, value] : fields) {
    transcript.append(label, value);
  }
  return Sha256(transcript.bytes());
}

Bytes BuildProofDigest(const char* proof_id,
                       const std::array<std::pair<const char*, Bytes>, 3>& fields) {
  Transcript transcript;
  const std::span<const uint8_t> proof_id_view(
      reinterpret_cast<const uint8_t*>(proof_id), std::strlen(proof_id));
  transcript.append("proof_id", proof_id_view);
  for (const auto& [label, value] : fields) {
    transcript.append(label, value);
  }
  return Sha256(transcript.bytes());
}

}  // namespace

bool IsZnStarElement(const mpz_class& value, const mpz_class& modulus) {
  if (modulus <= 2 || value <= 0 || value >= modulus) {
    return false;
  }
  mpz_class gcd;
  mpz_gcd(gcd.get_mpz_t(), value.get_mpz_t(), modulus.get_mpz_t());
  return gcd == 1;
}

bool ValidateAuxRsaParams(const AuxRsaParams& params) {
  if (params.n_tilde <= 2) {
    return false;
  }
  if (params.h1 == params.h2) {
    return false;
  }
  if (!IsZnStarElement(params.h1, params.n_tilde) ||
      !IsZnStarElement(params.h2, params.n_tilde)) {
    return false;
  }
  return true;
}

bool IsStrictProofScheme(StrictProofScheme scheme) {
  return scheme == StrictProofScheme::kStrictExternalV1;
}

bool IsDevProofScheme(StrictProofScheme scheme) {
  return scheme == StrictProofScheme::kDevDigestBindingV1;
}

Bytes EncodeSquareFreeProof(const SquareFreeProof& proof) {
  return EncodeProofWire(proof.metadata, proof.blob);
}

SquareFreeProof DecodeSquareFreeProof(std::span<const uint8_t> encoded, size_t max_len) {
  auto [metadata, blob] = DecodeProofWire(encoded, max_len);
  return SquareFreeProof{
      .metadata = metadata,
      .blob = std::move(blob),
  };
}

Bytes EncodeAuxRsaParamProof(const AuxRsaParamProof& proof) {
  return EncodeProofWire(proof.metadata, proof.blob);
}

AuxRsaParamProof DecodeAuxRsaParamProof(std::span<const uint8_t> encoded, size_t max_len) {
  auto [metadata, blob] = DecodeProofWire(encoded, max_len);
  return AuxRsaParamProof{
      .metadata = metadata,
      .blob = std::move(blob),
  };
}

bool IsLikelySquareFreeModulus(const mpz_class& modulus_n) {
  if (modulus_n <= 2) {
    return false;
  }
  if (mpz_even_p(modulus_n.get_mpz_t()) != 0) {
    return false;
  }
  if (mpz_perfect_square_p(modulus_n.get_mpz_t()) != 0) {
    return false;
  }

  static constexpr std::array<unsigned long, 168> kSmallPrimes = {
      2,   3,   5,   7,   11,  13,  17,  19,  23,  29,  31,  37,  41,  43,
      47,  53,  59,  61,  67,  71,  73,  79,  83,  89,  97,  101, 103, 107,
      109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
      191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263,
      269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
      353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433,
      439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521,
      523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613,
      617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
      709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809,
      811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887,
      907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997,
  };

  for (unsigned long prime : kSmallPrimes) {
    const unsigned long prime_square = prime * prime;
    if (mpz_divisible_ui_p(modulus_n.get_mpz_t(), prime_square) != 0) {
      return false;
    }
  }

  return true;
}

AuxRsaParams GenerateAuxRsaParams(uint32_t modulus_bits, PartyIndex party_id) {
  if (modulus_bits < 32) {
    throw std::invalid_argument("aux RSA modulus bits must be >= 32");
  }

  const size_t byte_len = (static_cast<size_t>(modulus_bits) + 7) / 8;
  Bytes modulus_bytes;
  do {
    modulus_bytes = Csprng::RandomBytes(byte_len);
    if (modulus_bytes.empty()) {
      throw std::runtime_error("failed to sample auxiliary RSA modulus bytes");
    }

    const unsigned int top_bits = modulus_bits % 8;
    if (top_bits != 0) {
      const uint8_t mask = static_cast<uint8_t>((1u << top_bits) - 1u);
      modulus_bytes.front() &= mask;
    }
    const unsigned int msb_idx = (modulus_bits - 1) % 8;
    modulus_bytes.front() |= static_cast<uint8_t>(1u << msb_idx);
    modulus_bytes.back() |= 0x01;  // odd
  } while (modulus_bytes.size() > 1 && modulus_bytes.front() == 0);

  mpz_class modulus_n;
  mpz_import(modulus_n.get_mpz_t(),
             modulus_bytes.size(),
             1,
             sizeof(uint8_t),
             1,
             0,
             modulus_bytes.data());
  if (modulus_n <= 2) {
    throw std::runtime_error("generated auxiliary RSA modulus is invalid");
  }

  const mpz_class h1 = PickCoprime(modulus_n, mpz_class(2 + 2 * party_id));
  mpz_class h2 = PickCoprime(modulus_n, mpz_class(3 + 2 * party_id));
  if (h1 == h2) {
    h2 = PickCoprime(modulus_n, h1 + 1);
  }

  AuxRsaParams params{
      .n_tilde = modulus_n,
      .h1 = h1,
      .h2 = h2,
  };
  if (!ValidateAuxRsaParams(params)) {
    throw std::runtime_error("failed to generate valid auxiliary RSA params");
  }
  return params;
}

AuxRsaParams DeriveAuxRsaParamsFromModulus(const mpz_class& modulus_n, PartyIndex party_id) {
  if (modulus_n <= 2) {
    throw std::invalid_argument("aux RSA modulus must be > 2");
  }

  const mpz_class h1 = PickCoprime(modulus_n, mpz_class(2 + 2 * party_id));
  mpz_class h2 = PickCoprime(modulus_n, mpz_class(3 + 2 * party_id));
  if (h1 == h2) {
    h2 = PickCoprime(modulus_n, h1 + 1);
  }

  AuxRsaParams params{
      .n_tilde = modulus_n,
      .h1 = h1,
      .h2 = h2,
  };
  if (!ValidateAuxRsaParams(params)) {
    throw std::runtime_error("failed to derive valid auxiliary RSA params");
  }
  return params;
}

SquareFreeProof BuildSquareFreeProof(const mpz_class& modulus_n) {
  SquareFreeProof proof;
  proof.metadata = DevProofMetadata();
  proof.blob = BuildProofDigest(
      kSquareFreeProofId,
      std::array<std::pair<const char*, Bytes>, 1>{{
          {"N", EncodeMpz(modulus_n)},
      }});
  return proof;
}

bool VerifySquareFreeProofWeak(const mpz_class& modulus_n, const SquareFreeProof& proof) {
  if (proof.blob.empty()) {
    return false;
  }
  if (!IsLikelySquareFreeModulus(modulus_n)) {
    return false;
  }

  if (proof.metadata.scheme == StrictProofScheme::kUnknown && proof.metadata.version == 0) {
    const SquareFreeProof expected = BuildSquareFreeProof(modulus_n);
    return proof.blob == expected.blob;
  }

  if (!IsDevProofScheme(proof.metadata.scheme) || proof.metadata.version != kDevProofVersion) {
    return false;
  }
  const SquareFreeProof expected = BuildSquareFreeProof(modulus_n);
  return proof.blob == expected.blob;
}

bool VerifySquareFreeProofStrict(const mpz_class& modulus_n, const SquareFreeProof& proof) {
  if (!VerifySquareFreeProofWeak(modulus_n, proof)) {
    return false;
  }
  return IsStrictProofScheme(proof.metadata.scheme);
}

bool VerifySquareFreeProof(const mpz_class& modulus_n, const SquareFreeProof& proof) {
  return VerifySquareFreeProofWeak(modulus_n, proof);
}

AuxRsaParamProof BuildAuxRsaParamProof(const AuxRsaParams& params) {
  if (!ValidateAuxRsaParams(params)) {
    throw std::invalid_argument("cannot build aux param proof from invalid parameters");
  }

  AuxRsaParamProof proof;
  proof.metadata = DevProofMetadata();
  proof.blob = BuildProofDigest(
      kAuxParamProofId,
      std::array<std::pair<const char*, Bytes>, 3>{{
          {"Ntilde", EncodeMpz(params.n_tilde)},
          {"h1", EncodeMpz(params.h1)},
          {"h2", EncodeMpz(params.h2)},
      }});
  return proof;
}

bool VerifyAuxRsaParamProofWeak(const AuxRsaParams& params, const AuxRsaParamProof& proof) {
  if (proof.blob.empty()) {
    return false;
  }
  if (!ValidateAuxRsaParams(params)) {
    return false;
  }

  if (proof.metadata.scheme == StrictProofScheme::kUnknown && proof.metadata.version == 0) {
    const AuxRsaParamProof expected = BuildAuxRsaParamProof(params);
    return proof.blob == expected.blob;
  }

  if (!IsDevProofScheme(proof.metadata.scheme) || proof.metadata.version != kDevProofVersion) {
    return false;
  }
  const AuxRsaParamProof expected = BuildAuxRsaParamProof(params);
  return proof.blob == expected.blob;
}

bool VerifyAuxRsaParamProofStrict(const AuxRsaParams& params, const AuxRsaParamProof& proof) {
  if (!VerifyAuxRsaParamProofWeak(params, proof)) {
    return false;
  }
  return IsStrictProofScheme(proof.metadata.scheme);
}

bool VerifyAuxRsaParamProof(const AuxRsaParams& params, const AuxRsaParamProof& proof) {
  return VerifyAuxRsaParamProofWeak(params, proof);
}

}  // namespace tecdsa
