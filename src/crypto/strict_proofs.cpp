#include "tecdsa/crypto/strict_proofs.hpp"

#include <array>
#include <cstring>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>

#include "tecdsa/crypto/encoding.hpp"
#include "tecdsa/crypto/hash.hpp"
#include "tecdsa/crypto/transcript.hpp"

namespace tecdsa {
namespace {

constexpr char kSquareFreeProofId[] = "GG2019/SquareFreeStub/v1";
constexpr char kAuxParamProofId[] = "GG2019/AuxParamStub/v1";

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
  proof.blob = BuildProofDigest(
      kSquareFreeProofId,
      std::array<std::pair<const char*, Bytes>, 1>{{
          {"N", EncodeMpz(modulus_n)},
      }});
  return proof;
}

bool VerifySquareFreeProof(const mpz_class& modulus_n, const SquareFreeProof& proof) {
  if (proof.blob.empty()) {
    return false;
  }
  if (!IsLikelySquareFreeModulus(modulus_n)) {
    return false;
  }
  const SquareFreeProof expected = BuildSquareFreeProof(modulus_n);
  return proof.blob == expected.blob;
}

AuxRsaParamProof BuildAuxRsaParamProof(const AuxRsaParams& params) {
  if (!ValidateAuxRsaParams(params)) {
    throw std::invalid_argument("cannot build aux param proof from invalid parameters");
  }

  AuxRsaParamProof proof;
  proof.blob = BuildProofDigest(
      kAuxParamProofId,
      std::array<std::pair<const char*, Bytes>, 3>{{
          {"Ntilde", EncodeMpz(params.n_tilde)},
          {"h1", EncodeMpz(params.h1)},
          {"h2", EncodeMpz(params.h2)},
      }});
  return proof;
}

bool VerifyAuxRsaParamProof(const AuxRsaParams& params, const AuxRsaParamProof& proof) {
  if (proof.blob.empty()) {
    return false;
  }
  if (!ValidateAuxRsaParams(params)) {
    return false;
  }
  const AuxRsaParamProof expected = BuildAuxRsaParamProof(params);
  return proof.blob == expected.blob;
}

}  // namespace tecdsa
