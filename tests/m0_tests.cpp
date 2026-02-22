#include <array>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <vector>

#include <gmpxx.h>

#include "tecdsa/common/bytes.hpp"
#include "tecdsa/crypto/commitment.hpp"
#include "tecdsa/crypto/ec_point.hpp"
#include "tecdsa/crypto/encoding.hpp"
#include "tecdsa/crypto/hash.hpp"
#include "tecdsa/crypto/paillier.hpp"
#include "tecdsa/crypto/random.hpp"
#include "tecdsa/crypto/scalar.hpp"
#include "tecdsa/crypto/transcript.hpp"
#include "tecdsa/net/envelope.hpp"

namespace {

using tecdsa::Bytes;
using tecdsa::DecodeEnvelope;
using tecdsa::DecodeMpz;
using tecdsa::ECPoint;
using tecdsa::CommitMessage;
using tecdsa::ComputeCommitment;
using tecdsa::EncodeEnvelope;
using tecdsa::EncodeMpz;
using tecdsa::Envelope;
using tecdsa::PaillierProvider;
using tecdsa::Scalar;
using tecdsa::Sha256;
using tecdsa::VerifyCommitment;
using tecdsa::Transcript;

void Expect(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error("Test failed: " + message);
  }
}

void ExpectThrow(const std::function<void()>& fn, const std::string& message) {
  try {
    fn();
  } catch (const std::exception&) {
    return;
  }
  throw std::runtime_error("Expected exception: " + message);
}

std::array<uint8_t, 32> MpzTo32(const mpz_class& x) {
  std::array<uint8_t, 32> out{};
  size_t count = 0;
  mpz_export(out.data(), &count, 1, sizeof(uint8_t), 1, 0, x.get_mpz_t());
  if (count > out.size()) {
    throw std::runtime_error("Value too large for 32-byte encoding");
  }

  std::array<uint8_t, 32> aligned{};
  const size_t offset = aligned.size() - count;
  for (size_t i = 0; i < count; ++i) {
    aligned[offset + i] = out[i];
  }
  return aligned;
}

void TestMpzRoundTrip() {
  mpz_class huge = 1;
  huge <<= 1023;

  const std::vector<mpz_class> values = {
      mpz_class(0), mpz_class(1), mpz_class(255), mpz_class(256),
      mpz_class("123456789012345678901234567890"), huge};

  for (const auto& value : values) {
    const Bytes encoded = EncodeMpz(value);
    const mpz_class decoded = DecodeMpz(encoded);
    Expect(decoded == value, "mpz round-trip must preserve value");
  }

  Bytes bad = EncodeMpz(mpz_class(42));
  bad.pop_back();
  ExpectThrow([&]() { (void)DecodeMpz(bad); }, "DecodeMpz rejects malformed length");
}

void TestScalarEncodingAndReduction() {
  Scalar five(mpz_class(5));
  const auto five_bytes = five.ToCanonicalBytes();
  Expect(five_bytes[31] == 5, "Scalar canonical encoding should match value");

  Scalar reduced(Scalar::ModulusQ() + 7);
  Expect(reduced == Scalar(mpz_class(7)), "Scalar constructor must reduce mod q");

  const auto q_bytes = MpzTo32(Scalar::ModulusQ());
  ExpectThrow([&]() { (void)Scalar::FromCanonicalBytes(q_bytes); },
              "Canonical scalar decoding rejects >= q");

  Scalar zero = Scalar::FromBigEndianModQ(q_bytes);
  Expect(zero == Scalar(mpz_class(0)), "Non-canonical decoder should reduce mod q");
}

void TestPointEncoding() {
  const ECPoint g = ECPoint::GeneratorMultiply(Scalar::FromUint64(1));
  const Bytes compressed = g.ToCompressedBytes();
  const ECPoint parsed = ECPoint::FromCompressed(compressed);
  Expect(parsed == g, "ECPoint round-trip must preserve valid points");

  Bytes invalid_prefix = compressed;
  invalid_prefix[0] = 0x04;
  ExpectThrow([&]() { (void)ECPoint::FromCompressed(invalid_prefix); },
              "ECPoint rejects non-compressed prefix");

  Bytes invalid_len(32, 0x02);
  ExpectThrow([&]() { (void)ECPoint::FromCompressed(invalid_len); },
              "ECPoint rejects invalid length");

  Bytes invalid_curve(33, 0x00);
  invalid_curve[0] = 0x02;
  ExpectThrow([&]() { (void)ECPoint::FromCompressed(invalid_curve); },
              "ECPoint rejects bytes not on secp256k1 curve");
}

void TestPointArithmetic() {
  const Scalar one = Scalar::FromUint64(1);
  const Scalar two = Scalar::FromUint64(2);
  const Scalar three = Scalar::FromUint64(3);
  const Scalar six = Scalar::FromUint64(6);

  const ECPoint g = ECPoint::GeneratorMultiply(one);
  const ECPoint g2 = ECPoint::GeneratorMultiply(two);
  const ECPoint g3 = ECPoint::GeneratorMultiply(three);

  const ECPoint g_plus_g2 = g.Add(g2);
  Expect(g_plus_g2 == g3, "ECPoint::Add should match scalar multiplication");

  const ECPoint g3_mul_two = g3.Mul(two);
  const ECPoint g6 = ECPoint::GeneratorMultiply(six);
  Expect(g3_mul_two == g6, "ECPoint::Mul should match generator multiplication");

  ExpectThrow([&]() { (void)ECPoint::GeneratorMultiply(Scalar::FromUint64(0)); },
              "GeneratorMultiply rejects zero scalar");
}

void TestHashAndCommitment() {
  const Bytes msg = {'a', 'b', 'c'};
  const Bytes digest = Sha256(msg);
  const Bytes expected = {
      0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
      0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
      0xf2, 0x00, 0x15, 0xad};
  Expect(digest == expected, "SHA256 must match known test vector for 'abc'");

  const std::string domain = "keygen/phase1";
  const Bytes randomness = {1, 2, 3, 4, 5};
  const Bytes commitment = ComputeCommitment(domain, msg, randomness);
  Expect(VerifyCommitment(domain, msg, randomness, commitment), "Commitment verifies for valid open");

  Bytes tampered_msg = msg;
  tampered_msg[0] ^= 0x01;
  Expect(!VerifyCommitment(domain, tampered_msg, randomness, commitment),
         "Commitment verify fails for tampered message");

  Bytes tampered_r = randomness;
  tampered_r.back() ^= 0x01;
  Expect(!VerifyCommitment(domain, msg, tampered_r, commitment),
         "Commitment verify fails for tampered randomness");

  const auto generated = CommitMessage(domain, msg);
  Expect(generated.randomness.size() == 32, "CommitMessage default randomness length is 32");
  Expect(VerifyCommitment(domain, msg, generated.randomness, generated.commitment),
         "CommitMessage output should verify");
}

void TestCsprng() {
  const Bytes random16 = tecdsa::Csprng::RandomBytes(16);
  Expect(random16.size() == 16, "Csprng::RandomBytes should return requested length");

  const Scalar s = tecdsa::Csprng::RandomScalar();
  Expect(s.value() < Scalar::ModulusQ(), "Csprng::RandomScalar should return value in Z_q");
}

void TestEnvelopeRoundTrip() {
  Envelope envelope;
  envelope.session_id = Bytes{1, 2, 3, 4, 5, 6, 7, 8};
  envelope.from = 1;
  envelope.to = tecdsa::kBroadcastPartyId;
  envelope.type = 42;
  envelope.payload = Bytes{0xAA, 0xBB, 0xCC};

  const Bytes encoded = EncodeEnvelope(envelope);
  const Envelope decoded = DecodeEnvelope(encoded);

  Expect(decoded.session_id == envelope.session_id, "Envelope session_id round-trip");
  Expect(decoded.from == envelope.from, "Envelope from round-trip");
  Expect(decoded.to == envelope.to, "Envelope to round-trip");
  Expect(decoded.type == envelope.type, "Envelope type round-trip");
  Expect(decoded.payload == envelope.payload, "Envelope payload round-trip");

  Bytes truncated = encoded;
  truncated.pop_back();
  ExpectThrow([&]() { (void)DecodeEnvelope(truncated); }, "Envelope rejects truncation");

  Envelope too_large_session = envelope;
  too_large_session.session_id.assign(40, 0x11);
  const Bytes encoded_large_session = EncodeEnvelope(too_large_session);
  ExpectThrow([&]() { (void)DecodeEnvelope(encoded_large_session); },
              "Envelope rejects oversized session_id");
}

void TestTranscriptChallengeDeterminismAndOrder() {
  const Bytes first = {1, 2, 3};
  const Bytes second = {9, 8};

  Transcript t1;
  t1.append("field1", first);
  t1.append("field2", second);

  Transcript t2;
  t2.append("field1", first);
  t2.append("field2", second);

  Transcript t3;
  t3.append("field2", second);
  t3.append("field1", first);

  const Scalar c1 = t1.challenge_scalar_mod_q();
  const Scalar c2 = t2.challenge_scalar_mod_q();
  const Scalar c3 = t3.challenge_scalar_mod_q();

  Expect(c1 == c2, "Transcript challenge must be deterministic");
  Expect(c1 != c3, "Transcript challenge should depend on append order");
}

void TestPaillierViaLibhcs() {
  PaillierProvider paillier(/*modulus_bits=*/512);
  Expect(paillier.VerifyKeyPair(), "Paillier key pair generated by libhcs should verify");

  const mpz_class a = 50;
  const mpz_class b = 76;

  const mpz_class c_a = paillier.Encrypt(a);
  const mpz_class c_b = paillier.Encrypt(b);

  const mpz_class c_sum = paillier.AddCiphertexts(c_a, c_b);
  const mpz_class plain_sum = paillier.Decrypt(c_sum);
  Expect(plain_sum == a + b, "Paillier encrypted addition should decrypt to a+b");

  const mpz_class c_mul = paillier.MulPlaintext(c_a, b);
  const mpz_class plain_mul = paillier.Decrypt(c_mul);
  Expect(plain_mul == a * b, "Paillier encrypted/plain multiplication should decrypt to a*b");

  const auto enc_with_r = paillier.EncryptWithRandom(a);
  const mpz_class c_same = paillier.EncryptWithProvidedRandom(a, enc_with_r.randomness);
  Expect(enc_with_r.ciphertext == c_same,
         "EncryptWithRandom should be reproducible with the same randomness");
}

}  // namespace

int main() {
  try {
    TestMpzRoundTrip();
    TestScalarEncodingAndReduction();
    TestPointEncoding();
    TestPointArithmetic();
    TestHashAndCommitment();
    TestCsprng();
    TestEnvelopeRoundTrip();
    TestTranscriptChallengeDeterminismAndOrder();
    TestPaillierViaLibhcs();
  } catch (const std::exception& ex) {
    std::cerr << ex.what() << '\n';
    return 1;
  }

  std::cout << "M0 tests passed" << '\n';
  return 0;
}
