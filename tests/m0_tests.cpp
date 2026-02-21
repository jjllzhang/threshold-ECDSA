#include <array>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <vector>

#include <gmpxx.h>

#include "tecdsa/common/bytes.hpp"
#include "tecdsa/crypto/ec_point.hpp"
#include "tecdsa/crypto/encoding.hpp"
#include "tecdsa/crypto/paillier.hpp"
#include "tecdsa/crypto/scalar.hpp"
#include "tecdsa/crypto/transcript.hpp"
#include "tecdsa/net/envelope.hpp"

namespace {

using tecdsa::Bytes;
using tecdsa::DecodeEnvelope;
using tecdsa::DecodeMpz;
using tecdsa::ECPoint;
using tecdsa::EncodeEnvelope;
using tecdsa::EncodeMpz;
using tecdsa::Envelope;
using tecdsa::PaillierProvider;
using tecdsa::Scalar;
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
  Bytes compressed(33, 0);
  compressed[0] = 0x02;
  for (size_t i = 1; i < compressed.size(); ++i) {
    compressed[i] = static_cast<uint8_t>(i);
  }

  const ECPoint point = ECPoint::FromCompressed(compressed);
  Expect(point.ToCompressedBytes() == compressed, "ECPoint round-trip must preserve bytes");

  Bytes invalid_prefix = compressed;
  invalid_prefix[0] = 0x04;
  ExpectThrow([&]() { (void)ECPoint::FromCompressed(invalid_prefix); },
              "ECPoint rejects non-compressed prefix");

  Bytes invalid_len(32, 0x02);
  ExpectThrow([&]() { (void)ECPoint::FromCompressed(invalid_len); },
              "ECPoint rejects invalid length");
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
