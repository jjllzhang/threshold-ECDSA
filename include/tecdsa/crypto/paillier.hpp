#pragma once

#include <gmpxx.h>

extern "C" {
#include <libhcs/hcs_random.h>
#include <libhcs/pcs.h>
}

namespace tecdsa {

struct PaillierCiphertextWithRandom {
  mpz_class ciphertext;
  mpz_class randomness;
};

class PaillierProvider {
 public:
  explicit PaillierProvider(unsigned long modulus_bits);
  ~PaillierProvider();

  PaillierProvider(const PaillierProvider&) = delete;
  PaillierProvider& operator=(const PaillierProvider&) = delete;

  PaillierProvider(PaillierProvider&& other) noexcept;
  PaillierProvider& operator=(PaillierProvider&& other) noexcept;

  mpz_class Encrypt(const mpz_class& plaintext) const;
  PaillierCiphertextWithRandom EncryptWithRandom(const mpz_class& plaintext) const;
  mpz_class EncryptWithProvidedRandom(const mpz_class& plaintext,
                                      const mpz_class& randomness) const;

  mpz_class Decrypt(const mpz_class& ciphertext) const;

  mpz_class AddCiphertexts(const mpz_class& lhs_cipher,
                           const mpz_class& rhs_cipher) const;
  mpz_class AddPlaintext(const mpz_class& cipher, const mpz_class& plain) const;
  mpz_class MulPlaintext(const mpz_class& cipher, const mpz_class& plain) const;

  bool VerifyKeyPair() const;

  mpz_class modulus_n() const;
  mpz_class modulus_n2() const;
  mpz_class generator() const;

 private:
  mpz_class SampleZnStar() const;
  bool IsInZnStar(const mpz_class& value) const;
  void Cleanup();

  hcs_random* hr_ = nullptr;
  pcs_public_key* pk_ = nullptr;
  pcs_private_key* sk_ = nullptr;
};

}  // namespace tecdsa
