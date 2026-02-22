#include "tecdsa/crypto/strict_proofs.hpp"

#include <algorithm>
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

constexpr char kSquareFreeProofIdWeak[] = "GG2019/SquareFreeDevDigest/v2";
constexpr char kAuxParamProofIdWeak[] = "GG2019/AuxParamDevDigest/v2";
constexpr char kSquareFreeProofIdStrict[] = "GG2019/SquareFreeStrictAlgebraic/v1";
constexpr char kAuxParamProofIdStrict[] = "GG2019/AuxParamStrictAlgebraic/v1";
constexpr char kSquareFreeSchemeIdWeak[] = "GG2019/DevDigestBinding/SquareFree/v2";
constexpr char kAuxParamSchemeIdWeak[] = "GG2019/DevDigestBinding/AuxParam/v2";
constexpr char kSquareFreeSchemeIdStrict[] = "GG2019/StrictAlgebraic/SquareFree/v1";
constexpr char kAuxParamSchemeIdStrict[] = "GG2019/StrictAlgebraic/AuxParam/v1";

constexpr uint32_t kProofWireMagicV1 = 0x53505231;  // "SPR1"
constexpr uint32_t kProofWireMagicV2 = 0x53505232;  // "SPR2"
constexpr uint32_t kDevProofVersion = 1;
constexpr uint32_t kStrictAlgebraicVersion = 1;
constexpr size_t kMaxSchemeIdLen = 256;
constexpr size_t kStrictNonceLen = 32;
constexpr size_t kMaxStrictNonceLen = 256;
constexpr size_t kMaxStrictFieldLen = 8192;
constexpr size_t kMaxAuxParamGenerationAttempts = 128;

struct SquareFreeStrictPayload {
  Bytes nonce;
  mpz_class y;
  mpz_class t1;
  mpz_class t2;
  mpz_class z1;
  mpz_class z2;
};

struct AuxParamStrictPayload {
  Bytes nonce;
  mpz_class c1;
  mpz_class c2;
  mpz_class t1;
  mpz_class t2;
  mpz_class z;
};

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

void AppendSizedField(std::span<const uint8_t> field, Bytes* out) {
  if (field.size() > UINT32_MAX) {
    throw std::invalid_argument("sized field exceeds uint32 length");
  }
  AppendU32Be(static_cast<uint32_t>(field.size()), out);
  out->insert(out->end(), field.begin(), field.end());
}

Bytes ReadSizedField(std::span<const uint8_t> input,
                     size_t* offset,
                     size_t max_len,
                     const char* field_name) {
  const uint32_t len = ReadU32Be(input, offset);
  if (len > max_len) {
    throw std::invalid_argument(std::string(field_name) + " exceeds maximum length");
  }
  if (*offset + len > input.size()) {
    throw std::invalid_argument(std::string(field_name) + " has inconsistent length");
  }

  Bytes out(input.begin() + static_cast<std::ptrdiff_t>(*offset),
            input.begin() + static_cast<std::ptrdiff_t>(*offset + len));
  *offset += len;
  return out;
}

void AppendMpzField(const mpz_class& value, Bytes* out) {
  const Bytes encoded = EncodeMpz(value);
  AppendSizedField(encoded, out);
}

mpz_class ReadMpzField(std::span<const uint8_t> input, size_t* offset, const char* field_name) {
  const Bytes encoded = ReadSizedField(input, offset, kMaxStrictFieldLen, field_name);
  return DecodeMpz(encoded, kMaxStrictFieldLen);
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
    case static_cast<uint32_t>(StrictProofScheme::kStrictAlgebraicV1):
      return StrictProofScheme::kStrictAlgebraicV1;
    case static_cast<uint32_t>(StrictProofScheme::kStrictExternalV1):
      return StrictProofScheme::kStrictExternalV1;
    case static_cast<uint32_t>(StrictProofScheme::kSquareFreeGmr98V1):
      return StrictProofScheme::kSquareFreeGmr98V1;
    default:
      return StrictProofScheme::kUnknown;
  }
}

ProofMetadata MakeWeakMetadata(const char* scheme_id) {
  return ProofMetadata{
      .scheme = StrictProofScheme::kDevDigestBindingV1,
      .version = kDevProofVersion,
      .capability_flags = kProofCapabilityNone,
      .scheme_id = scheme_id,
  };
}

bool HasContextBinding(const StrictProofVerifierContext& context) {
  return !context.session_id.empty() || context.prover_id.has_value() || context.verifier_id.has_value();
}

ProofMetadata MakeStrictMetadata(const char* scheme_id, const StrictProofVerifierContext& context) {
  uint32_t capability_flags =
      kProofCapabilityStrictReady |
      kProofCapabilityAlgebraicChecks |
      kProofCapabilityFreshRandomness;
  if (HasContextBinding(context)) {
    capability_flags |= kProofCapabilityContextBinding;
  }

  return ProofMetadata{
      .scheme = StrictProofScheme::kStrictAlgebraicV1,
      .version = kStrictAlgebraicVersion,
      .capability_flags = capability_flags,
      .scheme_id = scheme_id,
  };
}

void AppendVerifierContext(Transcript* transcript, const StrictProofVerifierContext& context) {
  if (!context.session_id.empty()) {
    transcript->append_session_id(context.session_id);
  }
  if (context.prover_id.has_value()) {
    transcript->append_u32_be("prover_id", *context.prover_id);
  }
  if (context.verifier_id.has_value()) {
    transcript->append_u32_be("verifier_id", *context.verifier_id);
  }
}

Bytes EncodeProofWire(const ProofMetadata& metadata, std::span<const uint8_t> blob) {
  // Preserve legacy format for unknown metadata, where payload is raw blob only.
  if (metadata.scheme == StrictProofScheme::kUnknown &&
      metadata.version == 0 &&
      metadata.capability_flags == kProofCapabilityNone &&
      metadata.scheme_id.empty()) {
    return Bytes(blob.begin(), blob.end());
  }

  if (blob.size() > UINT32_MAX) {
    throw std::invalid_argument("proof blob exceeds uint32 length");
  }
  if (metadata.scheme_id.size() > UINT32_MAX || metadata.scheme_id.size() > kMaxSchemeIdLen) {
    throw std::invalid_argument("proof scheme id exceeds maximum length");
  }

  Bytes out;
  out.reserve(24 + metadata.scheme_id.size() + blob.size());
  AppendU32Be(kProofWireMagicV2, &out);
  AppendU32Be(SchemeToU32(metadata.scheme), &out);
  AppendU32Be(metadata.version, &out);
  AppendU32Be(metadata.capability_flags, &out);
  AppendU32Be(static_cast<uint32_t>(metadata.scheme_id.size()), &out);
  AppendU32Be(static_cast<uint32_t>(blob.size()), &out);
  out.insert(out.end(), metadata.scheme_id.begin(), metadata.scheme_id.end());
  out.insert(out.end(), blob.begin(), blob.end());
  return out;
}

std::pair<ProofMetadata, Bytes> DecodeProofWire(std::span<const uint8_t> encoded, size_t max_len) {
  if (encoded.empty()) {
    return {ProofMetadata{}, Bytes{}};
  }

  if (encoded.size() >= 24) {
    size_t offset = 0;
    const uint32_t magic = ReadU32Be(encoded, &offset);
    if (magic == kProofWireMagicV2) {
      ProofMetadata metadata;
      metadata.scheme = U32ToScheme(ReadU32Be(encoded, &offset));
      metadata.version = ReadU32Be(encoded, &offset);
      metadata.capability_flags = ReadU32Be(encoded, &offset);
      const uint32_t scheme_id_len = ReadU32Be(encoded, &offset);
      const uint32_t blob_len = ReadU32Be(encoded, &offset);
      if (blob_len > max_len) {
        throw std::invalid_argument("proof blob exceeds maximum length");
      }
      if (scheme_id_len > kMaxSchemeIdLen) {
        throw std::invalid_argument("proof scheme id exceeds maximum length");
      }
      if (offset + scheme_id_len + blob_len != encoded.size()) {
        throw std::invalid_argument("proof wire payload has inconsistent length");
      }

      metadata.scheme_id.assign(
          reinterpret_cast<const char*>(encoded.data() + static_cast<std::ptrdiff_t>(offset)),
          scheme_id_len);
      offset += scheme_id_len;

      Bytes blob(
          encoded.begin() + static_cast<std::ptrdiff_t>(offset),
          encoded.begin() + static_cast<std::ptrdiff_t>(offset + blob_len));
      return {std::move(metadata), std::move(blob)};
    }
  }

  if (encoded.size() >= 16) {
    size_t offset = 0;
    const uint32_t magic = ReadU32Be(encoded, &offset);
    if (magic == kProofWireMagicV1) {
      ProofMetadata metadata;
      metadata.scheme = U32ToScheme(ReadU32Be(encoded, &offset));
      metadata.version = ReadU32Be(encoded, &offset);
      metadata.capability_flags = kProofCapabilityNone;
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
      return {std::move(metadata), std::move(blob)};
    }
  }

  if (encoded.size() > max_len) {
    throw std::invalid_argument("legacy proof blob exceeds maximum length");
  }
  return {ProofMetadata{}, Bytes(encoded.begin(), encoded.end())};
}

mpz_class RandomBelow(const mpz_class& upper_exclusive) {
  if (upper_exclusive <= 0) {
    throw std::invalid_argument("random upper bound must be positive");
  }

  const size_t bit_len = mpz_sizeinbase(upper_exclusive.get_mpz_t(), 2);
  const size_t byte_len = std::max<size_t>(1, (bit_len + 7) / 8);
  while (true) {
    const Bytes random = Csprng::RandomBytes(byte_len);
    mpz_class candidate;
    mpz_import(candidate.get_mpz_t(), random.size(), 1, sizeof(uint8_t), 1, 0, random.data());
    if (candidate < upper_exclusive) {
      return candidate;
    }
  }
}

mpz_class RandomZnStar(const mpz_class& modulus_n) {
  if (modulus_n <= 2) {
    throw std::invalid_argument("modulus must be > 2");
  }

  mpz_class candidate;
  mpz_class gcd;
  do {
    candidate = RandomBelow(modulus_n);
    mpz_gcd(gcd.get_mpz_t(), candidate.get_mpz_t(), modulus_n.get_mpz_t());
  } while (candidate == 0 || gcd != 1);
  return candidate;
}

bool IsInRange(const mpz_class& value, const mpz_class& modulus) {
  return value >= 0 && value < modulus;
}

bool IsZnStarElementMod(const mpz_class& value, const mpz_class& modulus) {
  if (!IsInRange(value, modulus) || value == 0) {
    return false;
  }
  mpz_class gcd;
  mpz_gcd(gcd.get_mpz_t(), value.get_mpz_t(), modulus.get_mpz_t());
  return gcd == 1;
}

mpz_class NormalizeMod(const mpz_class& value, const mpz_class& modulus) {
  mpz_class out = value % modulus;
  if (out < 0) {
    out += modulus;
  }
  return out;
}

mpz_class MulMod(const mpz_class& lhs, const mpz_class& rhs, const mpz_class& modulus) {
  return NormalizeMod(lhs * rhs, modulus);
}

mpz_class PowMod(const mpz_class& base, const mpz_class& exp, const mpz_class& modulus) {
  if (exp < 0) {
    throw std::invalid_argument("modular exponent must be non-negative");
  }
  mpz_class out;
  mpz_powm(out.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), modulus.get_mpz_t());
  return out;
}

Bytes BuildWeakDigest(const char* proof_id,
                      const StrictProofVerifierContext& context,
                      const std::array<std::pair<const char*, Bytes>, 1>& fields) {
  Transcript transcript;
  transcript.append_proof_id(proof_id);
  AppendVerifierContext(&transcript, context);
  for (const auto& [label, value] : fields) {
    transcript.append(label, value);
  }
  return Sha256(transcript.bytes());
}

Bytes BuildWeakDigest(const char* proof_id,
                      const StrictProofVerifierContext& context,
                      const std::array<std::pair<const char*, Bytes>, 3>& fields) {
  Transcript transcript;
  transcript.append_proof_id(proof_id);
  AppendVerifierContext(&transcript, context);
  for (const auto& [label, value] : fields) {
    transcript.append(label, value);
  }
  return Sha256(transcript.bytes());
}

Scalar BuildSquareFreeStrictChallenge(const mpz_class& modulus_n,
                                      const StrictProofVerifierContext& context,
                                      std::span<const uint8_t> nonce,
                                      const mpz_class& y,
                                      const mpz_class& t1,
                                      const mpz_class& t2) {
  Transcript transcript;
  transcript.append_proof_id(kSquareFreeProofIdStrict);
  AppendVerifierContext(&transcript, context);
  const Bytes n_bytes = EncodeMpz(modulus_n);
  const Bytes y_bytes = EncodeMpz(y);
  const Bytes t1_bytes = EncodeMpz(t1);
  const Bytes t2_bytes = EncodeMpz(t2);
  transcript.append_fields({
      TranscriptFieldRef{.label = "N", .data = n_bytes},
      TranscriptFieldRef{.label = "nonce", .data = nonce},
      TranscriptFieldRef{.label = "y", .data = y_bytes},
      TranscriptFieldRef{.label = "t1", .data = t1_bytes},
      TranscriptFieldRef{.label = "t2", .data = t2_bytes},
  });
  return transcript.challenge_scalar_mod_q();
}

Scalar BuildAuxParamStrictChallenge(const AuxRsaParams& params,
                                    const StrictProofVerifierContext& context,
                                    std::span<const uint8_t> nonce,
                                    const mpz_class& c1,
                                    const mpz_class& c2,
                                    const mpz_class& t1,
                                    const mpz_class& t2) {
  Transcript transcript;
  transcript.append_proof_id(kAuxParamProofIdStrict);
  AppendVerifierContext(&transcript, context);
  const Bytes n_tilde_bytes = EncodeMpz(params.n_tilde);
  const Bytes h1_bytes = EncodeMpz(params.h1);
  const Bytes h2_bytes = EncodeMpz(params.h2);
  const Bytes c1_bytes = EncodeMpz(c1);
  const Bytes c2_bytes = EncodeMpz(c2);
  const Bytes t1_bytes = EncodeMpz(t1);
  const Bytes t2_bytes = EncodeMpz(t2);
  transcript.append_fields({
      TranscriptFieldRef{.label = "Ntilde", .data = n_tilde_bytes},
      TranscriptFieldRef{.label = "h1", .data = h1_bytes},
      TranscriptFieldRef{.label = "h2", .data = h2_bytes},
      TranscriptFieldRef{.label = "nonce", .data = nonce},
      TranscriptFieldRef{.label = "c1", .data = c1_bytes},
      TranscriptFieldRef{.label = "c2", .data = c2_bytes},
      TranscriptFieldRef{.label = "t1", .data = t1_bytes},
      TranscriptFieldRef{.label = "t2", .data = t2_bytes},
  });
  return transcript.challenge_scalar_mod_q();
}

Bytes EncodeSquareFreeStrictPayload(const SquareFreeStrictPayload& payload) {
  Bytes out;
  AppendSizedField(payload.nonce, &out);
  AppendMpzField(payload.y, &out);
  AppendMpzField(payload.t1, &out);
  AppendMpzField(payload.t2, &out);
  AppendMpzField(payload.z1, &out);
  AppendMpzField(payload.z2, &out);
  return out;
}

SquareFreeStrictPayload DecodeSquareFreeStrictPayload(std::span<const uint8_t> blob) {
  size_t offset = 0;
  SquareFreeStrictPayload payload;
  payload.nonce = ReadSizedField(blob, &offset, kMaxStrictNonceLen, "square-free nonce");
  payload.y = ReadMpzField(blob, &offset, "square-free y");
  payload.t1 = ReadMpzField(blob, &offset, "square-free t1");
  payload.t2 = ReadMpzField(blob, &offset, "square-free t2");
  payload.z1 = ReadMpzField(blob, &offset, "square-free z1");
  payload.z2 = ReadMpzField(blob, &offset, "square-free z2");
  if (offset != blob.size()) {
    throw std::invalid_argument("square-free proof payload has trailing bytes");
  }
  return payload;
}

Bytes EncodeAuxParamStrictPayload(const AuxParamStrictPayload& payload) {
  Bytes out;
  AppendSizedField(payload.nonce, &out);
  AppendMpzField(payload.c1, &out);
  AppendMpzField(payload.c2, &out);
  AppendMpzField(payload.t1, &out);
  AppendMpzField(payload.t2, &out);
  AppendMpzField(payload.z, &out);
  return out;
}

AuxParamStrictPayload DecodeAuxParamStrictPayload(std::span<const uint8_t> blob) {
  size_t offset = 0;
  AuxParamStrictPayload payload;
  payload.nonce = ReadSizedField(blob, &offset, kMaxStrictNonceLen, "aux-param nonce");
  payload.c1 = ReadMpzField(blob, &offset, "aux-param c1");
  payload.c2 = ReadMpzField(blob, &offset, "aux-param c2");
  payload.t1 = ReadMpzField(blob, &offset, "aux-param t1");
  payload.t2 = ReadMpzField(blob, &offset, "aux-param t2");
  payload.z = ReadMpzField(blob, &offset, "aux-param z");
  if (offset != blob.size()) {
    throw std::invalid_argument("aux-param proof payload has trailing bytes");
  }
  return payload;
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
  return scheme == StrictProofScheme::kStrictAlgebraicV1 ||
         scheme == StrictProofScheme::kStrictExternalV1 ||
         scheme == StrictProofScheme::kSquareFreeGmr98V1;
}

bool IsDevProofScheme(StrictProofScheme scheme) {
  return scheme == StrictProofScheme::kDevDigestBindingV1;
}

bool HasProofCapability(const ProofMetadata& metadata, uint32_t capability_mask) {
  return (metadata.capability_flags & capability_mask) == capability_mask;
}

bool IsProofMetadataCompatible(const ProofMetadata& expected,
                               const ProofMetadata& candidate,
                               bool require_strict_scheme) {
  if (require_strict_scheme && !IsStrictProofScheme(candidate.scheme)) {
    return false;
  }

  if (expected.scheme != StrictProofScheme::kUnknown &&
      candidate.scheme != expected.scheme) {
    return false;
  }
  if (expected.version != 0 && candidate.version < expected.version) {
    return false;
  }
  if (!expected.scheme_id.empty() && candidate.scheme_id != expected.scheme_id) {
    return false;
  }
  if (expected.capability_flags != kProofCapabilityNone &&
      !HasProofCapability(candidate, expected.capability_flags)) {
    return false;
  }
  return true;
}

Bytes EncodeSquareFreeProof(const SquareFreeProof& proof) {
  return EncodeProofWire(proof.metadata, proof.blob);
}

SquareFreeProof DecodeSquareFreeProof(std::span<const uint8_t> encoded, size_t max_len) {
  auto [metadata, blob] = DecodeProofWire(encoded, max_len);
  return SquareFreeProof{
      .metadata = std::move(metadata),
      .blob = std::move(blob),
  };
}

Bytes EncodeAuxRsaParamProof(const AuxRsaParamProof& proof) {
  return EncodeProofWire(proof.metadata, proof.blob);
}

AuxRsaParamProof DecodeAuxRsaParamProof(std::span<const uint8_t> encoded, size_t max_len) {
  auto [metadata, blob] = DecodeProofWire(encoded, max_len);
  return AuxRsaParamProof{
      .metadata = std::move(metadata),
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
  for (size_t attempt = 0; attempt < kMaxAuxParamGenerationAttempts; ++attempt) {
    Bytes modulus_bytes = Csprng::RandomBytes(byte_len);
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
    if (modulus_bytes.size() > 1 && modulus_bytes.front() == 0) {
      continue;
    }

    mpz_class modulus_n;
    mpz_import(modulus_n.get_mpz_t(),
               modulus_bytes.size(),
               1,
               sizeof(uint8_t),
               1,
               0,
               modulus_bytes.data());
    if (modulus_n <= 2 || !IsLikelySquareFreeModulus(modulus_n)) {
      continue;
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
    if (ValidateAuxRsaParams(params)) {
      return params;
    }
  }

  throw std::runtime_error("failed to generate likely square-free auxiliary RSA params");
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

SquareFreeProof BuildSquareFreeProofWeak(const mpz_class& modulus_n,
                                         const StrictProofVerifierContext& context) {
  SquareFreeProof proof;
  proof.metadata = MakeWeakMetadata(kSquareFreeSchemeIdWeak);
  proof.blob = BuildWeakDigest(
      kSquareFreeProofIdWeak,
      context,
      std::array<std::pair<const char*, Bytes>, 1>{{
          {"N", EncodeMpz(modulus_n)},
      }});
  return proof;
}

SquareFreeProof BuildSquareFreeProofStrict(const mpz_class& modulus_n,
                                           const StrictProofVerifierContext& context) {
  if (modulus_n <= 2) {
    throw std::invalid_argument("square-free proof requires modulus N > 2");
  }
  if (!IsLikelySquareFreeModulus(modulus_n)) {
    throw std::invalid_argument("square-free strict proof requires likely square-free modulus");
  }

  const mpz_class n2 = modulus_n * modulus_n;
  const mpz_class witness = RandomZnStar(modulus_n);
  const mpz_class r1 = RandomZnStar(modulus_n);
  const mpz_class r2 = RandomZnStar(modulus_n);

  const mpz_class y = PowMod(witness, modulus_n, n2);
  const mpz_class t1 = PowMod(r1, modulus_n, n2);
  const mpz_class t2 = PowMod(r2, modulus_n, n2);
  const Bytes nonce = Csprng::RandomBytes(kStrictNonceLen);
  const mpz_class e =
      BuildSquareFreeStrictChallenge(modulus_n, context, nonce, y, t1, t2).value();

  const mpz_class z1 = MulMod(r1, PowMod(witness, e, modulus_n), modulus_n);
  const mpz_class z2 = MulMod(r2, PowMod(witness, e + 1, modulus_n), modulus_n);

  SquareFreeProof proof;
  proof.metadata = MakeStrictMetadata(kSquareFreeSchemeIdStrict, context);
  proof.metadata.capability_flags |= kProofCapabilityHeuristicChecks;
  proof.blob = EncodeSquareFreeStrictPayload(SquareFreeStrictPayload{
      .nonce = nonce,
      .y = y,
      .t1 = t1,
      .t2 = t2,
      .z1 = z1,
      .z2 = z2,
  });
  return proof;
}

bool VerifySquareFreeProofWeak(const mpz_class& modulus_n,
                               const SquareFreeProof& proof,
                               const StrictProofVerifierContext& context) {
  if (proof.blob.empty()) {
    return false;
  }
  if (!IsLikelySquareFreeModulus(modulus_n)) {
    return false;
  }

  if (proof.metadata.scheme == StrictProofScheme::kUnknown && proof.metadata.version == 0) {
    const SquareFreeProof expected = BuildSquareFreeProofWeak(modulus_n, context);
    return proof.blob == expected.blob;
  }

  if (!IsDevProofScheme(proof.metadata.scheme) || proof.metadata.version != kDevProofVersion) {
    return false;
  }
  if (!proof.metadata.scheme_id.empty() && proof.metadata.scheme_id != kSquareFreeSchemeIdWeak) {
    return false;
  }
  const SquareFreeProof expected = BuildSquareFreeProofWeak(modulus_n, context);
  return proof.blob == expected.blob;
}

bool VerifySquareFreeProofStrict(const mpz_class& modulus_n,
                                 const SquareFreeProof& proof,
                                 const StrictProofVerifierContext& context) {
  if (!IsLikelySquareFreeModulus(modulus_n)) {
    return false;
  }
  if (proof.blob.empty()) {
    return false;
  }
  if (!IsStrictProofScheme(proof.metadata.scheme)) {
    return false;
  }
  if (proof.metadata.scheme != StrictProofScheme::kStrictAlgebraicV1) {
    // External strict schemes are reserved but not implemented in this module.
    return false;
  }
  if (proof.metadata.version != kStrictAlgebraicVersion) {
    return false;
  }
  if (!proof.metadata.scheme_id.empty() && proof.metadata.scheme_id != kSquareFreeSchemeIdStrict) {
    return false;
  }
  if (!HasProofCapability(
          proof.metadata,
          kProofCapabilityStrictReady |
              kProofCapabilityAlgebraicChecks |
              kProofCapabilityFreshRandomness |
              kProofCapabilityHeuristicChecks)) {
    return false;
  }
  if (HasContextBinding(context) &&
      !HasProofCapability(proof.metadata, kProofCapabilityContextBinding)) {
    return false;
  }

  const mpz_class n2 = modulus_n * modulus_n;
  SquareFreeStrictPayload payload;
  try {
    payload = DecodeSquareFreeStrictPayload(proof.blob);
  } catch (const std::exception&) {
    return false;
  }
  if (payload.nonce.size() != kStrictNonceLen) {
    return false;
  }
  if (!IsZnStarElementMod(payload.y, n2) ||
      !IsZnStarElementMod(payload.t1, n2) ||
      !IsZnStarElementMod(payload.t2, n2) ||
      !IsZnStarElementMod(payload.z1, modulus_n) ||
      !IsZnStarElementMod(payload.z2, modulus_n)) {
    return false;
  }

  const mpz_class e =
      BuildSquareFreeStrictChallenge(modulus_n,
                                     context,
                                     payload.nonce,
                                     payload.y,
                                     payload.t1,
                                     payload.t2)
          .value();

  const mpz_class lhs1 = PowMod(payload.z1, modulus_n, n2);
  const mpz_class rhs1 = MulMod(payload.t1, PowMod(payload.y, e, n2), n2);
  if (lhs1 != rhs1) {
    return false;
  }

  const mpz_class lhs2 = PowMod(payload.z2, modulus_n, n2);
  const mpz_class rhs2 = MulMod(payload.t2, PowMod(payload.y, e + 1, n2), n2);
  return lhs2 == rhs2;
}

SquareFreeProof BuildSquareFreeProofGmr98(const mpz_class& modulus_n,
                                          const StrictProofVerifierContext& context) {
  // Skeleton path: keep behavior stable until dedicated [21]/GMR98 prover is introduced.
  return BuildSquareFreeProofStrict(modulus_n, context);
}

bool VerifySquareFreeProofGmr98(const mpz_class& modulus_n,
                                const SquareFreeProof& proof,
                                const StrictProofVerifierContext& context) {
  // Skeleton path: keep behavior stable until dedicated [21]/GMR98 verifier is introduced.
  return VerifySquareFreeProofStrict(modulus_n, proof, context);
}

SquareFreeProof BuildSquareFreeProof(const mpz_class& modulus_n,
                                     const StrictProofVerifierContext& context) {
  return BuildSquareFreeProofGmr98(modulus_n, context);
}

bool VerifySquareFreeProof(const mpz_class& modulus_n,
                           const SquareFreeProof& proof,
                           const StrictProofVerifierContext& context) {
  if (IsStrictProofScheme(proof.metadata.scheme)) {
    return VerifySquareFreeProofGmr98(modulus_n, proof, context);
  }
  return VerifySquareFreeProofWeak(modulus_n, proof, context);
}

AuxRsaParamProof BuildAuxRsaParamProofWeak(const AuxRsaParams& params,
                                           const StrictProofVerifierContext& context) {
  if (!ValidateAuxRsaParams(params)) {
    throw std::invalid_argument("cannot build aux param proof from invalid parameters");
  }

  AuxRsaParamProof proof;
  proof.metadata = MakeWeakMetadata(kAuxParamSchemeIdWeak);
  proof.blob = BuildWeakDigest(
      kAuxParamProofIdWeak,
      context,
      std::array<std::pair<const char*, Bytes>, 3>{{
          {"Ntilde", EncodeMpz(params.n_tilde)},
          {"h1", EncodeMpz(params.h1)},
          {"h2", EncodeMpz(params.h2)},
      }});
  return proof;
}

AuxRsaParamProof BuildAuxRsaParamProofStrict(const AuxRsaParams& params,
                                             const StrictProofVerifierContext& context) {
  if (!ValidateAuxRsaParams(params)) {
    throw std::invalid_argument("cannot build aux param proof from invalid parameters");
  }
  if (!IsLikelySquareFreeModulus(params.n_tilde)) {
    throw std::invalid_argument("aux strict proof requires likely square-free Ntilde");
  }

  mpz_class alpha;
  do {
    alpha = RandomBelow(Scalar::ModulusQ());
  } while (alpha == 0);
  mpz_class r;
  do {
    r = RandomBelow(Scalar::ModulusQ());
  } while (r == 0);

  const mpz_class c1 = PowMod(params.h1, alpha, params.n_tilde);
  const mpz_class c2 = PowMod(params.h2, alpha, params.n_tilde);
  const mpz_class t1 = PowMod(params.h1, r, params.n_tilde);
  const mpz_class t2 = PowMod(params.h2, r, params.n_tilde);
  const Bytes nonce = Csprng::RandomBytes(kStrictNonceLen);
  const mpz_class e = BuildAuxParamStrictChallenge(
                          params, context, nonce, c1, c2, t1, t2)
                          .value();
  const mpz_class z = r + (e * alpha);

  AuxRsaParamProof proof;
  proof.metadata = MakeStrictMetadata(kAuxParamSchemeIdStrict, context);
  proof.metadata.capability_flags |= kProofCapabilityHeuristicChecks;
  proof.blob = EncodeAuxParamStrictPayload(AuxParamStrictPayload{
      .nonce = nonce,
      .c1 = c1,
      .c2 = c2,
      .t1 = t1,
      .t2 = t2,
      .z = z,
  });
  return proof;
}

bool VerifyAuxRsaParamProofWeak(const AuxRsaParams& params,
                                const AuxRsaParamProof& proof,
                                const StrictProofVerifierContext& context) {
  if (proof.blob.empty()) {
    return false;
  }
  if (!ValidateAuxRsaParams(params)) {
    return false;
  }

  if (proof.metadata.scheme == StrictProofScheme::kUnknown && proof.metadata.version == 0) {
    const AuxRsaParamProof expected = BuildAuxRsaParamProofWeak(params, context);
    return proof.blob == expected.blob;
  }

  if (!IsDevProofScheme(proof.metadata.scheme) || proof.metadata.version != kDevProofVersion) {
    return false;
  }
  if (!proof.metadata.scheme_id.empty() && proof.metadata.scheme_id != kAuxParamSchemeIdWeak) {
    return false;
  }
  const AuxRsaParamProof expected = BuildAuxRsaParamProofWeak(params, context);
  return proof.blob == expected.blob;
}

bool VerifyAuxRsaParamProofStrict(const AuxRsaParams& params,
                                  const AuxRsaParamProof& proof,
                                  const StrictProofVerifierContext& context) {
  if (!ValidateAuxRsaParams(params)) {
    return false;
  }
  if (!IsLikelySquareFreeModulus(params.n_tilde)) {
    return false;
  }
  if (proof.blob.empty()) {
    return false;
  }
  if (!IsStrictProofScheme(proof.metadata.scheme)) {
    return false;
  }
  if (proof.metadata.scheme != StrictProofScheme::kStrictAlgebraicV1) {
    // External strict schemes are reserved but not implemented in this module.
    return false;
  }
  if (proof.metadata.version != kStrictAlgebraicVersion) {
    return false;
  }
  if (!proof.metadata.scheme_id.empty() && proof.metadata.scheme_id != kAuxParamSchemeIdStrict) {
    return false;
  }
  if (!HasProofCapability(
          proof.metadata,
          kProofCapabilityStrictReady |
              kProofCapabilityAlgebraicChecks |
              kProofCapabilityFreshRandomness |
              kProofCapabilityHeuristicChecks)) {
    return false;
  }
  if (HasContextBinding(context) &&
      !HasProofCapability(proof.metadata, kProofCapabilityContextBinding)) {
    return false;
  }

  AuxParamStrictPayload payload;
  try {
    payload = DecodeAuxParamStrictPayload(proof.blob);
  } catch (const std::exception&) {
    return false;
  }
  if (payload.nonce.size() != kStrictNonceLen) {
    return false;
  }
  if (payload.z < 0) {
    return false;
  }
  if (!IsZnStarElement(payload.c1, params.n_tilde) ||
      !IsZnStarElement(payload.c2, params.n_tilde) ||
      !IsZnStarElement(payload.t1, params.n_tilde) ||
      !IsZnStarElement(payload.t2, params.n_tilde)) {
    return false;
  }

  const mpz_class e = BuildAuxParamStrictChallenge(
                          params, context, payload.nonce, payload.c1, payload.c2, payload.t1, payload.t2)
                          .value();

  const mpz_class lhs1 = PowMod(params.h1, payload.z, params.n_tilde);
  const mpz_class rhs1 = MulMod(payload.t1, PowMod(payload.c1, e, params.n_tilde), params.n_tilde);
  if (lhs1 != rhs1) {
    return false;
  }

  const mpz_class lhs2 = PowMod(params.h2, payload.z, params.n_tilde);
  const mpz_class rhs2 = MulMod(payload.t2, PowMod(payload.c2, e, params.n_tilde), params.n_tilde);
  return lhs2 == rhs2;
}

AuxRsaParamProof BuildAuxRsaParamProof(const AuxRsaParams& params,
                                       const StrictProofVerifierContext& context) {
  return BuildAuxRsaParamProofStrict(params, context);
}

bool VerifyAuxRsaParamProof(const AuxRsaParams& params,
                            const AuxRsaParamProof& proof,
                            const StrictProofVerifierContext& context) {
  if (IsStrictProofScheme(proof.metadata.scheme)) {
    return VerifyAuxRsaParamProofStrict(params, proof, context);
  }
  return VerifyAuxRsaParamProofWeak(params, proof, context);
}

}  // namespace tecdsa
