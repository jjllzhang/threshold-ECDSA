#pragma once

#include <gmpxx.h>
#include <span>

#include "tecdsa/common/bytes.hpp"
#include "tecdsa/protocol/types.hpp"

namespace tecdsa {

enum class StrictProofScheme : uint32_t {
  kUnknown = 0,
  // Development-only hash binding placeholder.
  kDevDigestBindingV1 = 1,
  // Reserved for future strict external/cryptographic proofs.
  kStrictExternalV1 = 2,
};

struct ProofMetadata {
  StrictProofScheme scheme = StrictProofScheme::kUnknown;
  uint32_t version = 0;
};

struct AuxRsaParams {
  mpz_class n_tilde;
  mpz_class h1;
  mpz_class h2;
};

struct SquareFreeProof {
  ProofMetadata metadata;
  Bytes blob;
};

struct AuxRsaParamProof {
  ProofMetadata metadata;
  Bytes blob;
};

bool IsZnStarElement(const mpz_class& value, const mpz_class& modulus);
bool ValidateAuxRsaParams(const AuxRsaParams& params);
bool IsLikelySquareFreeModulus(const mpz_class& modulus_n);
bool IsStrictProofScheme(StrictProofScheme scheme);
bool IsDevProofScheme(StrictProofScheme scheme);

Bytes EncodeSquareFreeProof(const SquareFreeProof& proof);
SquareFreeProof DecodeSquareFreeProof(std::span<const uint8_t> encoded, size_t max_len = 4096);

Bytes EncodeAuxRsaParamProof(const AuxRsaParamProof& proof);
AuxRsaParamProof DecodeAuxRsaParamProof(std::span<const uint8_t> encoded, size_t max_len = 4096);

AuxRsaParams DeriveAuxRsaParamsFromModulus(const mpz_class& modulus_n, PartyIndex party_id);
AuxRsaParams GenerateAuxRsaParams(uint32_t modulus_bits, PartyIndex party_id);

SquareFreeProof BuildSquareFreeProof(const mpz_class& modulus_n);
bool VerifySquareFreeProof(const mpz_class& modulus_n, const SquareFreeProof& proof);
bool VerifySquareFreeProofWeak(const mpz_class& modulus_n, const SquareFreeProof& proof);
bool VerifySquareFreeProofStrict(const mpz_class& modulus_n, const SquareFreeProof& proof);

AuxRsaParamProof BuildAuxRsaParamProof(const AuxRsaParams& params);
bool VerifyAuxRsaParamProof(const AuxRsaParams& params, const AuxRsaParamProof& proof);
bool VerifyAuxRsaParamProofWeak(const AuxRsaParams& params, const AuxRsaParamProof& proof);
bool VerifyAuxRsaParamProofStrict(const AuxRsaParams& params, const AuxRsaParamProof& proof);

}  // namespace tecdsa
