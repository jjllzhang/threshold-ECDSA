#include "tecdsa/crypto/paillier.hpp"

#include <stdexcept>
#include <utility>

namespace tecdsa {

PaillierProvider::PaillierProvider(unsigned long modulus_bits) {
  if (modulus_bits < 256) {
    throw std::invalid_argument("Paillier modulus_bits must be >= 256");
  }

  hr_ = hcs_init_random();
  pk_ = pcs_init_public_key();
  sk_ = pcs_init_private_key();

  if (hr_ == nullptr || pk_ == nullptr || sk_ == nullptr) {
    Cleanup();
    throw std::runtime_error("Failed to initialize libhcs Paillier structures");
  }

  pcs_generate_key_pair(pk_, sk_, hr_, modulus_bits);
  if (!VerifyKeyPair()) {
    Cleanup();
    throw std::runtime_error("libhcs generated invalid Paillier key pair");
  }
}

PaillierProvider::~PaillierProvider() {
  Cleanup();
}

PaillierProvider::PaillierProvider(PaillierProvider&& other) noexcept
    : hr_(other.hr_), pk_(other.pk_), sk_(other.sk_) {
  other.hr_ = nullptr;
  other.pk_ = nullptr;
  other.sk_ = nullptr;
}

PaillierProvider& PaillierProvider::operator=(PaillierProvider&& other) noexcept {
  if (this != &other) {
    Cleanup();
    hr_ = other.hr_;
    pk_ = other.pk_;
    sk_ = other.sk_;
    other.hr_ = nullptr;
    other.pk_ = nullptr;
    other.sk_ = nullptr;
  }
  return *this;
}

mpz_class PaillierProvider::Encrypt(const mpz_class& plaintext) const {
  mpz_class plain = plaintext;
  mpz_class out;
  pcs_encrypt(pk_, hr_, out.get_mpz_t(), plain.get_mpz_t());
  return out;
}

PaillierCiphertextWithRandom PaillierProvider::EncryptWithRandom(
    const mpz_class& plaintext) const {
  PaillierCiphertextWithRandom out;
  out.randomness = SampleZnStar();
  out.ciphertext = EncryptWithProvidedRandom(plaintext, out.randomness);
  return out;
}

mpz_class PaillierProvider::EncryptWithProvidedRandom(
    const mpz_class& plaintext,
    const mpz_class& randomness) const {
  if (!IsInZnStar(randomness)) {
    throw std::invalid_argument("Paillier randomness must be in Z*_N");
  }

  mpz_class plain = plaintext;
  mpz_class rand = randomness;
  mpz_class out;
  pcs_encrypt_r(pk_, out.get_mpz_t(), plain.get_mpz_t(), rand.get_mpz_t());
  return out;
}

mpz_class PaillierProvider::Decrypt(const mpz_class& ciphertext) const {
  mpz_class cipher = ciphertext;
  mpz_class out;
  pcs_decrypt(sk_, out.get_mpz_t(), cipher.get_mpz_t());
  return out;
}

mpz_class PaillierProvider::AddCiphertexts(const mpz_class& lhs_cipher,
                                           const mpz_class& rhs_cipher) const {
  mpz_class lhs = lhs_cipher;
  mpz_class rhs = rhs_cipher;
  mpz_class out;
  pcs_ee_add(pk_, out.get_mpz_t(), lhs.get_mpz_t(), rhs.get_mpz_t());
  return out;
}

mpz_class PaillierProvider::AddPlaintext(const mpz_class& cipher,
                                         const mpz_class& plain) const {
  mpz_class c = cipher;
  mpz_class p = plain;
  mpz_class out;
  pcs_ep_add(pk_, out.get_mpz_t(), c.get_mpz_t(), p.get_mpz_t());
  return out;
}

mpz_class PaillierProvider::MulPlaintext(const mpz_class& cipher,
                                         const mpz_class& plain) const {
  mpz_class c = cipher;
  mpz_class p = plain;
  mpz_class out;
  pcs_ep_mul(pk_, out.get_mpz_t(), c.get_mpz_t(), p.get_mpz_t());
  return out;
}

bool PaillierProvider::VerifyKeyPair() const {
  if (pk_ == nullptr || sk_ == nullptr) {
    return false;
  }
  return pcs_verify_key_pair(pk_, sk_) != 0;
}

mpz_class PaillierProvider::modulus_n() const {
  return mpz_class(pk_->n);
}

mpz_class PaillierProvider::modulus_n2() const {
  return mpz_class(pk_->n2);
}

mpz_class PaillierProvider::generator() const {
  return mpz_class(pk_->g);
}

mpz_class PaillierProvider::SampleZnStar() const {
  const mpz_class n = modulus_n();

  mpz_class candidate;
  mpz_class gcd;
  do {
    mpz_urandomm(candidate.get_mpz_t(), hr_->rstate, n.get_mpz_t());
    mpz_gcd(gcd.get_mpz_t(), candidate.get_mpz_t(), n.get_mpz_t());
  } while (candidate == 0 || gcd != 1);

  return candidate;
}

bool PaillierProvider::IsInZnStar(const mpz_class& value) const {
  if (value <= 0 || value >= modulus_n()) {
    return false;
  }

  mpz_class gcd;
  const mpz_class n = modulus_n();
  mpz_gcd(gcd.get_mpz_t(), value.get_mpz_t(), n.get_mpz_t());
  return gcd == 1;
}

void PaillierProvider::Cleanup() {
  if (sk_ != nullptr) {
    pcs_free_private_key(sk_);
    sk_ = nullptr;
  }
  if (pk_ != nullptr) {
    pcs_free_public_key(pk_);
    pk_ = nullptr;
  }
  if (hr_ != nullptr) {
    hcs_free_random(hr_);
    hr_ = nullptr;
  }
}

}  // namespace tecdsa
