#pragma once

#include <gmpxx.h>

#include "tecdsa/common/bytes.hpp"
#include "tecdsa/protocol/types.hpp"

namespace tecdsa {

struct AuxRsaParams {
  mpz_class n_tilde;
  mpz_class h1;
  mpz_class h2;
};

struct SquareFreeProof {
  Bytes blob;
};

struct AuxRsaParamProof {
  Bytes blob;
};

bool IsZnStarElement(const mpz_class& value, const mpz_class& modulus);
bool ValidateAuxRsaParams(const AuxRsaParams& params);
bool IsLikelySquareFreeModulus(const mpz_class& modulus_n);

AuxRsaParams DeriveAuxRsaParamsFromModulus(const mpz_class& modulus_n, PartyIndex party_id);

SquareFreeProof BuildSquareFreeProof(const mpz_class& modulus_n);
bool VerifySquareFreeProof(const mpz_class& modulus_n, const SquareFreeProof& proof);

AuxRsaParamProof BuildAuxRsaParamProof(const AuxRsaParams& params);
bool VerifyAuxRsaParamProof(const AuxRsaParams& params, const AuxRsaParamProof& proof);

}  // namespace tecdsa
