#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include "tecdsa/crypto/random.hpp"
#include "tecdsa/net/envelope.hpp"
#include "tecdsa/protocol/keygen_session.hpp"
#include "tecdsa/protocol/sign_session.hpp"

namespace {

using tecdsa::Bytes;
using tecdsa::Envelope;
using tecdsa::KeygenPhase;
using tecdsa::KeygenResult;
using tecdsa::KeygenSession;
using tecdsa::KeygenSessionConfig;
using tecdsa::PartyIndex;
using tecdsa::SessionStatus;
using tecdsa::SignPhase;
using tecdsa::SignPhase5Stage;
using tecdsa::SignSession;
using tecdsa::SignSessionConfig;

struct BenchArgs {
  uint32_t n = 3;
  uint32_t t = 1;
  uint32_t keygen_iters = 1;
  uint32_t sign_iters = 10;
  uint32_t paillier_bits = 2048;
};

struct PhaseMetric {
  double total_ms = 0.0;
  uint64_t total_bytes = 0;
  uint64_t samples = 0;
};

struct KeygenMetrics {
  PhaseMetric phase1;
  PhaseMetric phase2;
  PhaseMetric phase3;
};

struct SignMetrics {
  PhaseMetric phase1;
  PhaseMetric phase2;
  PhaseMetric phase3;
  PhaseMetric phase4;
  PhaseMetric phase5a;
  PhaseMetric phase5b;
  PhaseMetric phase5c;
  PhaseMetric phase5d;
  PhaseMetric phase5e;
};

struct ByteMetric {
  uint64_t total_bytes = 0;
  uint64_t samples = 0;
};

struct StrictProofMetrics {
  PhaseMetric keygen_phase1_aux_param;
  PhaseMetric keygen_phase3_square_free;
  PhaseMetric sign_phase2_a_proofs;
  PhaseMetric sign_phase4_gamma_schnorr;
  PhaseMetric sign_phase5b_proofs;

  ByteMetric sign_phase2_a1;
  ByteMetric sign_phase2_a2;
  ByteMetric sign_phase2_a3;
  ByteMetric sign_phase5b_a_schnorr;
  ByteMetric sign_phase5b_v_relation;
};

struct SignPhase2ProofBytes {
  uint64_t a1 = 0;
  uint64_t a2 = 0;
  uint64_t a3 = 0;

  uint64_t Total() const {
    return a1 + a2 + a3;
  }
};

struct SignPhase5BProofBytes {
  uint64_t a_schnorr = 0;
  uint64_t v_relation = 0;

  uint64_t Total() const {
    return a_schnorr + v_relation;
  }
};

constexpr uint32_t kMtaTypeTimesGamma = 1;
constexpr uint32_t kMtaTypeTimesW = 2;
constexpr size_t kCommitmentLen = 32;

void Expect(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error(message);
  }
}

uint32_t ParsePositiveU32(const char* value, const char* flag) {
  try {
    const unsigned long parsed = std::stoul(value);
    if (parsed == 0 || parsed > UINT32_MAX) {
      throw std::out_of_range("out of range");
    }
    return static_cast<uint32_t>(parsed);
  } catch (const std::exception&) {
    throw std::invalid_argument(std::string("invalid value for ") + flag + ": " + value);
  }
}

BenchArgs ParseArgs(int argc, char** argv) {
  BenchArgs args;
  for (int i = 1; i < argc; ++i) {
    const std::string flag = argv[i];
    if (flag == "--n" && i + 1 < argc) {
      args.n = ParsePositiveU32(argv[++i], "--n");
    } else if (flag == "--t" && i + 1 < argc) {
      args.t = ParsePositiveU32(argv[++i], "--t");
    } else if (flag == "--keygen-iters" && i + 1 < argc) {
      args.keygen_iters = ParsePositiveU32(argv[++i], "--keygen-iters");
    } else if (flag == "--sign-iters" && i + 1 < argc) {
      args.sign_iters = ParsePositiveU32(argv[++i], "--sign-iters");
    } else if (flag == "--paillier-bits" && i + 1 < argc) {
      args.paillier_bits = ParsePositiveU32(argv[++i], "--paillier-bits");
    } else if (flag == "--help") {
      std::cout << "Usage: m9_bench [--n N] [--t T] [--keygen-iters K] [--sign-iters S] [--paillier-bits B]\n";
      std::exit(0);
    } else {
      throw std::invalid_argument("unknown argument: " + flag);
    }
  }

  if (args.n < 2) {
    throw std::invalid_argument("--n must be >= 2");
  }
  if (args.t >= args.n) {
    throw std::invalid_argument("--t must be < n");
  }
  if (args.sign_iters == 0) {
    throw std::invalid_argument("--sign-iters must be > 0");
  }
  if (args.keygen_iters == 0) {
    throw std::invalid_argument("--keygen-iters must be > 0");
  }
  if (args.paillier_bits < 2048) {
    throw std::invalid_argument("--paillier-bits must be >= 2048 for strict GG2019 checks");
  }

  return args;
}

std::vector<PartyIndex> BuildParticipants(uint32_t n) {
  std::vector<PartyIndex> out;
  out.reserve(n);
  for (PartyIndex id = 1; id <= n; ++id) {
    out.push_back(id);
  }
  return out;
}

size_t FindPartyIndexOrThrow(const std::vector<PartyIndex>& parties, PartyIndex party_id) {
  for (size_t i = 0; i < parties.size(); ++i) {
    if (parties[i] == party_id) {
      return i;
    }
  }
  throw std::runtime_error("party id not found");
}

Bytes MakeSessionId(uint8_t domain, uint32_t iteration) {
  Bytes out(8, 0);
  out[0] = domain;
  out[1] = static_cast<uint8_t>((iteration >> 24) & 0xFF);
  out[2] = static_cast<uint8_t>((iteration >> 16) & 0xFF);
  out[3] = static_cast<uint8_t>((iteration >> 8) & 0xFF);
  out[4] = static_cast<uint8_t>(iteration & 0xFF);
  const Bytes salt = tecdsa::Csprng::RandomBytes(3);
  out[5] = salt[0];
  out[6] = salt[1];
  out[7] = salt[2];
  return out;
}

uint64_t MeasureEnvelopeBytes(const std::vector<Envelope>& envelopes) {
  uint64_t total = 0;
  for (const Envelope& envelope : envelopes) {
    total += tecdsa::EncodeEnvelope(envelope).size();
  }
  return total;
}

void RecordMetric(PhaseMetric* metric,
                  std::chrono::steady_clock::time_point start,
                  std::chrono::steady_clock::time_point end,
                  uint64_t bytes) {
  metric->total_ms += std::chrono::duration<double, std::milli>(end - start).count();
  metric->total_bytes += bytes;
  metric->samples += 1;
}

void RecordBytesMetric(ByteMetric* metric, uint64_t bytes) {
  metric->total_bytes += bytes;
  metric->samples += 1;
}

double AverageMs(const PhaseMetric& metric) {
  if (metric.samples == 0) {
    return 0.0;
  }
  return metric.total_ms / static_cast<double>(metric.samples);
}

double AverageBytes(const PhaseMetric& metric) {
  if (metric.samples == 0) {
    return 0.0;
  }
  return static_cast<double>(metric.total_bytes) / static_cast<double>(metric.samples);
}

double AverageBytes(const ByteMetric& metric) {
  if (metric.samples == 0) {
    return 0.0;
  }
  return static_cast<double>(metric.total_bytes) / static_cast<double>(metric.samples);
}

size_t ScalarWireSize() {
  static const size_t kScalarLen = tecdsa::Scalar().ToCanonicalBytes().size();
  return kScalarLen;
}

size_t PointWireSize() {
  static const size_t kPointLen =
      tecdsa::ECPoint::GeneratorMultiply(tecdsa::Scalar::FromUint64(1)).ToCompressedBytes().size();
  return kPointLen;
}

uint32_t ReadU32Be(std::span<const uint8_t> input, size_t* offset) {
  if (*offset + 4 > input.size()) {
    throw std::runtime_error("payload underflow while reading u32");
  }
  const size_t i = *offset;
  *offset += 4;
  return (static_cast<uint32_t>(input[i]) << 24) |
         (static_cast<uint32_t>(input[i + 1]) << 16) |
         (static_cast<uint32_t>(input[i + 2]) << 8) |
         static_cast<uint32_t>(input[i + 3]);
}

void ConsumeFixedBytes(std::span<const uint8_t> input,
                       size_t* offset,
                       size_t len,
                       const char* field_name) {
  if (*offset + len > input.size()) {
    throw std::runtime_error(std::string("payload underflow while reading ") + field_name);
  }
  *offset += len;
}

size_t ConsumeLenPrefixedField(std::span<const uint8_t> input,
                               size_t* offset,
                               const char* field_name) {
  const uint32_t len = ReadU32Be(input, offset);
  if (*offset + len > input.size()) {
    throw std::runtime_error(std::string("payload underflow while reading ") + field_name);
  }
  *offset += len;
  return 4 + static_cast<size_t>(len);
}

uint64_t MeasureKeygenPhase1AuxProofBytes(const std::vector<Envelope>& envelopes) {
  uint64_t proof_bytes = 0;
  const uint32_t phase1_type = KeygenSession::MessageTypeForPhase(KeygenPhase::kPhase1);
  for (const Envelope& envelope : envelopes) {
    if (envelope.type != phase1_type) {
      continue;
    }

    const std::span<const uint8_t> payload(envelope.payload.data(), envelope.payload.size());
    size_t offset = 0;
    ConsumeFixedBytes(payload, &offset, kCommitmentLen, "keygen phase1 commitment");
    for (int i = 0; i < 4; ++i) {
      ConsumeLenPrefixedField(payload, &offset, "keygen phase1 mpz field");
    }
    proof_bytes += ConsumeLenPrefixedField(payload, &offset, "keygen phase1 aux proof");
    if (offset != payload.size()) {
      throw std::runtime_error("keygen phase1 payload has trailing bytes in bench parser");
    }
  }
  return proof_bytes;
}

uint64_t MeasureKeygenPhase3SquareFreeProofBytes(const std::vector<Envelope>& envelopes) {
  uint64_t proof_bytes = 0;
  const size_t point_len = PointWireSize();
  const size_t scalar_len = ScalarWireSize();
  const uint32_t phase3_type = KeygenSession::MessageTypeForPhase(KeygenPhase::kPhase3);
  for (const Envelope& envelope : envelopes) {
    if (envelope.type != phase3_type) {
      continue;
    }

    const std::span<const uint8_t> payload(envelope.payload.data(), envelope.payload.size());
    size_t offset = 0;
    ConsumeFixedBytes(payload, &offset, point_len, "keygen phase3 X_i");
    ConsumeFixedBytes(payload, &offset, point_len, "keygen phase3 schnorr.a");
    ConsumeFixedBytes(payload, &offset, scalar_len, "keygen phase3 schnorr.z");
    proof_bytes += ConsumeLenPrefixedField(payload, &offset, "keygen phase3 square-free proof");
    if (offset != payload.size()) {
      throw std::runtime_error("keygen phase3 payload has trailing bytes in bench parser");
    }
  }
  return proof_bytes;
}

SignPhase2ProofBytes MeasureSignPhase2ProofBytes(const std::vector<Envelope>& envelopes) {
  SignPhase2ProofBytes out;
  const uint32_t init_type = SignSession::MessageTypeForPhase(SignPhase::kPhase2);
  const uint32_t response_type = SignSession::Phase2ResponseMessageType();
  for (const Envelope& envelope : envelopes) {
    if (envelope.type != init_type && envelope.type != response_type) {
      continue;
    }

    const std::span<const uint8_t> payload(envelope.payload.data(), envelope.payload.size());
    size_t offset = 0;
    const uint32_t mta_type = ReadU32Be(payload, &offset);
    ConsumeLenPrefixedField(payload, &offset, "sign phase2 instance id");
    ConsumeLenPrefixedField(payload, &offset, "sign phase2 ciphertext");
    const uint64_t proof_bytes = static_cast<uint64_t>(payload.size() - offset);

    if (envelope.type == init_type) {
      out.a1 += proof_bytes;
      continue;
    }
    if (mta_type == kMtaTypeTimesGamma) {
      out.a3 += proof_bytes;
      continue;
    }
    if (mta_type == kMtaTypeTimesW) {
      out.a2 += proof_bytes;
      continue;
    }
    throw std::runtime_error("unknown sign phase2 MtA type in bench parser");
  }
  return out;
}

uint64_t MeasureSignPhase4GammaSchnorrProofBytes(const std::vector<Envelope>& envelopes) {
  uint64_t proof_bytes = 0;
  const size_t point_len = PointWireSize();
  const uint32_t phase4_type = SignSession::MessageTypeForPhase(SignPhase::kPhase4);
  for (const Envelope& envelope : envelopes) {
    if (envelope.type != phase4_type) {
      continue;
    }

    const std::span<const uint8_t> payload(envelope.payload.data(), envelope.payload.size());
    size_t offset = 0;
    ConsumeFixedBytes(payload, &offset, point_len, "sign phase4 gamma");
    ConsumeLenPrefixedField(payload, &offset, "sign phase4 open randomness");
    const size_t proof_offset = offset;
    ConsumeFixedBytes(payload, &offset, point_len, "sign phase4 schnorr.a");
    ConsumeFixedBytes(payload, &offset, ScalarWireSize(), "sign phase4 schnorr.z");
    if (offset != payload.size()) {
      throw std::runtime_error("sign phase4 payload has trailing bytes in bench parser");
    }
    proof_bytes += static_cast<uint64_t>(payload.size() - proof_offset);
  }
  return proof_bytes;
}

SignPhase5BProofBytes MeasureSignPhase5BProofBytes(const std::vector<Envelope>& envelopes) {
  SignPhase5BProofBytes out;
  const size_t point_len = PointWireSize();
  const size_t scalar_len = ScalarWireSize();
  const uint32_t phase5b_type = SignSession::MessageTypeForPhase5Stage(SignPhase5Stage::kPhase5B);
  for (const Envelope& envelope : envelopes) {
    if (envelope.type != phase5b_type) {
      continue;
    }

    const std::span<const uint8_t> payload(envelope.payload.data(), envelope.payload.size());
    size_t offset = 0;
    ConsumeFixedBytes(payload, &offset, point_len, "sign phase5B V_i");
    ConsumeFixedBytes(payload, &offset, point_len, "sign phase5B A_i");
    ConsumeLenPrefixedField(payload, &offset, "sign phase5B open randomness");
    const size_t schnorr_offset = offset;
    ConsumeFixedBytes(payload, &offset, point_len, "sign phase5B A schnorr.a");
    ConsumeFixedBytes(payload, &offset, scalar_len, "sign phase5B A schnorr.z");
    const size_t relation_offset = offset;
    ConsumeFixedBytes(payload, &offset, point_len, "sign phase5B relation.alpha");
    ConsumeFixedBytes(payload, &offset, scalar_len, "sign phase5B relation.t");
    ConsumeFixedBytes(payload, &offset, scalar_len, "sign phase5B relation.u");
    if (offset != payload.size()) {
      throw std::runtime_error("sign phase5B payload has trailing bytes in bench parser");
    }
    out.a_schnorr += static_cast<uint64_t>(relation_offset - schnorr_offset);
    out.v_relation += static_cast<uint64_t>(payload.size() - relation_offset);
  }
  return out;
}

bool DeliverKeygenEnvelope(const Envelope& envelope,
                           std::vector<std::unique_ptr<KeygenSession>>* sessions) {
  bool ok = true;
  if (envelope.to == tecdsa::kBroadcastPartyId) {
    for (size_t idx = 0; idx < sessions->size(); ++idx) {
      const PartyIndex receiver = static_cast<PartyIndex>(idx + 1);
      if (receiver == envelope.from) {
        continue;
      }
      if (!(*sessions)[idx]->HandleEnvelope(envelope)) {
        ok = false;
      }
    }
    return ok;
  }

  if (envelope.to == 0 || envelope.to > sessions->size()) {
    throw std::runtime_error("keygen recipient out of range");
  }
  if (!(*sessions)[envelope.to - 1]->HandleEnvelope(envelope)) {
    ok = false;
  }
  return ok;
}

void DeliverKeygenOrThrow(const std::vector<Envelope>& envelopes,
                          std::vector<std::unique_ptr<KeygenSession>>* sessions) {
  for (const Envelope& envelope : envelopes) {
    if (!DeliverKeygenEnvelope(envelope, sessions)) {
      throw std::runtime_error("keygen envelope delivery failed");
    }
  }
}

bool DeliverSignEnvelope(const Envelope& envelope,
                         const std::vector<PartyIndex>& signers,
                         std::vector<std::unique_ptr<SignSession>>* sessions) {
  bool ok = true;
  if (envelope.to == tecdsa::kBroadcastPartyId) {
    for (size_t idx = 0; idx < signers.size(); ++idx) {
      if (signers[idx] == envelope.from) {
        continue;
      }
      if (!(*sessions)[idx]->HandleEnvelope(envelope)) {
        ok = false;
      }
    }
    return ok;
  }

  const size_t receiver_idx = FindPartyIndexOrThrow(signers, envelope.to);
  if (!(*sessions)[receiver_idx]->HandleEnvelope(envelope)) {
    ok = false;
  }
  return ok;
}

void DeliverSignOrThrow(const std::vector<Envelope>& envelopes,
                        const std::vector<PartyIndex>& signers,
                        std::vector<std::unique_ptr<SignSession>>* sessions) {
  for (const Envelope& envelope : envelopes) {
    if (!DeliverSignEnvelope(envelope, signers, sessions)) {
      throw std::runtime_error("sign envelope delivery failed");
    }
  }
}

std::vector<Envelope> CollectSignPhase1(std::vector<std::unique_ptr<SignSession>>* sessions) {
  std::vector<Envelope> out;
  out.reserve(sessions->size());
  for (auto& session : *sessions) {
    out.push_back(session->BuildPhase1CommitEnvelope());
  }
  return out;
}

std::vector<Envelope> CollectSignPhase2(std::vector<std::unique_ptr<SignSession>>* sessions) {
  std::vector<Envelope> out;
  for (auto& session : *sessions) {
    if (session->phase() != SignPhase::kPhase2) {
      continue;
    }
    std::vector<Envelope> batch = session->BuildPhase2MtaEnvelopes();
    out.insert(out.end(), batch.begin(), batch.end());
  }
  return out;
}

std::vector<Envelope> CollectSignPhase3(std::vector<std::unique_ptr<SignSession>>* sessions) {
  std::vector<Envelope> out;
  out.reserve(sessions->size());
  for (auto& session : *sessions) {
    out.push_back(session->BuildPhase3DeltaEnvelope());
  }
  return out;
}

std::vector<Envelope> CollectSignPhase4(std::vector<std::unique_ptr<SignSession>>* sessions) {
  std::vector<Envelope> out;
  out.reserve(sessions->size());
  for (auto& session : *sessions) {
    out.push_back(session->BuildPhase4OpenGammaEnvelope());
  }
  return out;
}

std::vector<Envelope> CollectSignPhase5A(std::vector<std::unique_ptr<SignSession>>* sessions) {
  std::vector<Envelope> out;
  out.reserve(sessions->size());
  for (auto& session : *sessions) {
    out.push_back(session->BuildPhase5ACommitEnvelope());
  }
  return out;
}

std::vector<Envelope> CollectSignPhase5B(std::vector<std::unique_ptr<SignSession>>* sessions) {
  std::vector<Envelope> out;
  out.reserve(sessions->size());
  for (auto& session : *sessions) {
    out.push_back(session->BuildPhase5BOpenEnvelope());
  }
  return out;
}

std::vector<Envelope> CollectSignPhase5C(std::vector<std::unique_ptr<SignSession>>* sessions) {
  std::vector<Envelope> out;
  out.reserve(sessions->size());
  for (auto& session : *sessions) {
    out.push_back(session->BuildPhase5CCommitEnvelope());
  }
  return out;
}

std::vector<Envelope> CollectSignPhase5D(std::vector<std::unique_ptr<SignSession>>* sessions) {
  std::vector<Envelope> out;
  out.reserve(sessions->size());
  for (auto& session : *sessions) {
    out.push_back(session->BuildPhase5DOpenEnvelope());
  }
  return out;
}

std::vector<Envelope> CollectSignPhase5E(std::vector<std::unique_ptr<SignSession>>* sessions) {
  std::vector<Envelope> out;
  out.reserve(sessions->size());
  for (auto& session : *sessions) {
    out.push_back(session->BuildPhase5ERevealEnvelope());
  }
  return out;
}

template <typename SessionPtr>
bool AllSignSessionsInPhase(const std::vector<std::unique_ptr<SessionPtr>>& sessions,
                            SignPhase phase,
                            SignPhase5Stage stage = SignPhase5Stage::kPhase5A) {
  for (const auto& session : sessions) {
    if (session->phase() != phase) {
      return false;
    }
    if (phase == SignPhase::kPhase5 && session->phase5_stage() != stage) {
      return false;
    }
  }
  return true;
}

std::vector<std::unique_ptr<KeygenSession>> BuildKeygenSessions(const BenchArgs& args,
                                                                const Bytes& session_id) {
  std::vector<std::unique_ptr<KeygenSession>> sessions;
  const std::vector<PartyIndex> participants = BuildParticipants(args.n);
  sessions.reserve(participants.size());
  for (PartyIndex self_id : participants) {
    KeygenSessionConfig cfg;
    cfg.session_id = session_id;
    cfg.self_id = self_id;
    cfg.participants = participants;
    cfg.threshold = args.t;
    cfg.paillier_modulus_bits = args.paillier_bits;
    cfg.timeout = std::chrono::seconds(30);
    cfg.strict_mode = true;
    sessions.push_back(std::make_unique<KeygenSession>(std::move(cfg)));
  }
  return sessions;
}

std::unordered_map<PartyIndex, KeygenResult> RunKeygenRound(const BenchArgs& args,
                                                            uint32_t iteration,
                                                            KeygenMetrics* metrics,
                                                            StrictProofMetrics* strict_metrics) {
  auto sessions = BuildKeygenSessions(args, MakeSessionId(0xA1, iteration));

  {
    const auto start = std::chrono::steady_clock::now();
    std::vector<Envelope> phase1;
    phase1.reserve(sessions.size());
    for (auto& session : sessions) {
      phase1.push_back(session->BuildPhase1CommitEnvelope());
    }
    const uint64_t bytes = MeasureEnvelopeBytes(phase1);
    const uint64_t aux_proof_bytes = MeasureKeygenPhase1AuxProofBytes(phase1);
    DeliverKeygenOrThrow(phase1, &sessions);
    const auto end = std::chrono::steady_clock::now();
    RecordMetric(&metrics->phase1, start, end, bytes);
    if (strict_metrics != nullptr) {
      RecordMetric(&strict_metrics->keygen_phase1_aux_param, start, end, aux_proof_bytes);
    }
  }

  {
    const auto start = std::chrono::steady_clock::now();
    std::vector<Envelope> phase2;
    for (auto& session : sessions) {
      std::vector<Envelope> batch = session->BuildPhase2OpenAndShareEnvelopes();
      phase2.insert(phase2.end(), batch.begin(), batch.end());
    }
    const uint64_t bytes = MeasureEnvelopeBytes(phase2);
    DeliverKeygenOrThrow(phase2, &sessions);
    const auto end = std::chrono::steady_clock::now();
    RecordMetric(&metrics->phase2, start, end, bytes);
  }

  {
    const auto start = std::chrono::steady_clock::now();
    std::vector<Envelope> phase3;
    phase3.reserve(sessions.size());
    for (auto& session : sessions) {
      phase3.push_back(session->BuildPhase3XiProofEnvelope());
    }
    const uint64_t bytes = MeasureEnvelopeBytes(phase3);
    const uint64_t square_free_bytes = MeasureKeygenPhase3SquareFreeProofBytes(phase3);
    DeliverKeygenOrThrow(phase3, &sessions);
    const auto end = std::chrono::steady_clock::now();
    RecordMetric(&metrics->phase3, start, end, bytes);
    if (strict_metrics != nullptr) {
      RecordMetric(&strict_metrics->keygen_phase3_square_free, start, end, square_free_bytes);
    }
  }

  std::unordered_map<PartyIndex, KeygenResult> out;
  out.reserve(sessions.size());
  for (size_t i = 0; i < sessions.size(); ++i) {
    Expect(sessions[i]->status() == SessionStatus::kCompleted, "keygen did not complete");
    const PartyIndex party_id = static_cast<PartyIndex>(i + 1);
    out.emplace(party_id, sessions[i]->result());
  }
  return out;
}

std::vector<std::unique_ptr<SignSession>> BuildSignSessions(
    const std::vector<PartyIndex>& signers,
    const std::unordered_map<PartyIndex, KeygenResult>& keygen_results,
    const Bytes& sign_session_id,
    const Bytes& msg32) {
  std::vector<std::unique_ptr<SignSession>> sessions;
  sessions.reserve(signers.size());

  const auto baseline_it = keygen_results.find(signers.front());
  if (baseline_it == keygen_results.end()) {
    throw std::runtime_error("missing baseline keygen result");
  }

  std::unordered_map<PartyIndex, tecdsa::ECPoint> all_x_subset;
  std::unordered_map<PartyIndex, tecdsa::PaillierPublicKey> all_paillier_public;
  std::unordered_map<PartyIndex, SignSessionConfig::AuxRsaParams> all_aux_params;
  std::unordered_map<PartyIndex, SignSessionConfig::SquareFreeProof> all_square_free_proofs;
  std::unordered_map<PartyIndex, SignSessionConfig::AuxRsaParamProof> all_aux_param_proofs;
  std::unordered_map<PartyIndex, std::shared_ptr<tecdsa::PaillierProvider>> local_paillier_keys;

  all_x_subset.reserve(signers.size());
  all_paillier_public.reserve(signers.size());
  all_aux_params.reserve(signers.size());
  all_square_free_proofs.reserve(signers.size());
  all_aux_param_proofs.reserve(signers.size());
  local_paillier_keys.reserve(signers.size());

  for (PartyIndex party : signers) {
    const auto x_it = baseline_it->second.all_X_i.find(party);
    if (x_it == baseline_it->second.all_X_i.end()) {
      throw std::runtime_error("missing signer X_i in baseline keygen result");
    }
    all_x_subset.emplace(party, x_it->second);

    const auto party_result_it = keygen_results.find(party);
    if (party_result_it == keygen_results.end()) {
      throw std::runtime_error("missing signer keygen result");
    }
    const auto pub_it = party_result_it->second.all_paillier_public.find(party);
    if (pub_it == party_result_it->second.all_paillier_public.end()) {
      throw std::runtime_error("missing signer Paillier public key");
    }
    if (party_result_it->second.local_paillier == nullptr) {
      throw std::runtime_error("missing signer Paillier private key");
    }
    all_paillier_public.emplace(party, pub_it->second);
    local_paillier_keys.emplace(party, party_result_it->second.local_paillier);

    const auto aux_it = baseline_it->second.all_aux_rsa_params.find(party);
    const auto square_it = baseline_it->second.all_square_free_proofs.find(party);
    const auto aux_pf_it = baseline_it->second.all_aux_param_proofs.find(party);
    if (aux_it == baseline_it->second.all_aux_rsa_params.end() ||
        square_it == baseline_it->second.all_square_free_proofs.end() ||
        aux_pf_it == baseline_it->second.all_aux_param_proofs.end()) {
      throw std::runtime_error("missing strict proof artifacts for signer");
    }
    all_aux_params.emplace(party, aux_it->second);
    all_square_free_proofs.emplace(party, square_it->second);
    all_aux_param_proofs.emplace(party, aux_pf_it->second);
  }

  for (PartyIndex self_id : signers) {
    const auto self_result_it = keygen_results.find(self_id);
    if (self_result_it == keygen_results.end()) {
      throw std::runtime_error("missing signer keygen result for session build");
    }

    SignSessionConfig cfg;
    cfg.session_id = sign_session_id;
    cfg.keygen_session_id = baseline_it->second.keygen_session_id;
    cfg.self_id = self_id;
    cfg.participants = signers;
    cfg.timeout = std::chrono::seconds(30);
    cfg.x_i = self_result_it->second.x_i;
    cfg.y = baseline_it->second.y;
    cfg.all_X_i = all_x_subset;
    cfg.all_paillier_public = all_paillier_public;
    cfg.all_aux_rsa_params = all_aux_params;
    cfg.all_square_free_proofs = all_square_free_proofs;
    cfg.all_aux_param_proofs = all_aux_param_proofs;
    cfg.square_free_proof_profile = baseline_it->second.square_free_proof_profile;
    cfg.aux_param_proof_profile = baseline_it->second.aux_param_proof_profile;
    cfg.local_paillier = local_paillier_keys.at(self_id);
    cfg.msg32 = msg32;
    cfg.strict_mode = true;
    sessions.push_back(std::make_unique<SignSession>(std::move(cfg)));
  }

  return sessions;
}

void RunSignRound(const std::unordered_map<PartyIndex, KeygenResult>& keygen_results,
                  const std::vector<PartyIndex>& signers,
                  uint32_t iteration,
                  SignMetrics* metrics,
                  StrictProofMetrics* strict_metrics) {
  auto sessions = BuildSignSessions(
      signers, keygen_results, MakeSessionId(0xB1, iteration), tecdsa::Csprng::RandomBytes(32));

  {
    const auto start = std::chrono::steady_clock::now();
    std::vector<Envelope> phase1 = CollectSignPhase1(&sessions);
    const uint64_t bytes = MeasureEnvelopeBytes(phase1);
    DeliverSignOrThrow(phase1, signers, &sessions);
    const auto end = std::chrono::steady_clock::now();
    RecordMetric(&metrics->phase1, start, end, bytes);
  }

  {
    const auto start = std::chrono::steady_clock::now();
    uint64_t bytes = 0;
    SignPhase2ProofBytes phase2_proof_bytes;
    for (size_t round = 0; round < 64; ++round) {
      std::vector<Envelope> phase2 = CollectSignPhase2(&sessions);
      if (phase2.empty()) {
        throw std::runtime_error("sign phase2 stalled");
      }
      bytes += MeasureEnvelopeBytes(phase2);
      const SignPhase2ProofBytes batch_proof_bytes = MeasureSignPhase2ProofBytes(phase2);
      phase2_proof_bytes.a1 += batch_proof_bytes.a1;
      phase2_proof_bytes.a2 += batch_proof_bytes.a2;
      phase2_proof_bytes.a3 += batch_proof_bytes.a3;
      DeliverSignOrThrow(phase2, signers, &sessions);
      if (AllSignSessionsInPhase(sessions, SignPhase::kPhase3)) {
        break;
      }
    }
    Expect(AllSignSessionsInPhase(sessions, SignPhase::kPhase3), "sign did not finish phase2");
    const auto end = std::chrono::steady_clock::now();
    RecordMetric(&metrics->phase2, start, end, bytes);
    if (strict_metrics != nullptr) {
      RecordMetric(&strict_metrics->sign_phase2_a_proofs, start, end, phase2_proof_bytes.Total());
      RecordBytesMetric(&strict_metrics->sign_phase2_a1, phase2_proof_bytes.a1);
      RecordBytesMetric(&strict_metrics->sign_phase2_a2, phase2_proof_bytes.a2);
      RecordBytesMetric(&strict_metrics->sign_phase2_a3, phase2_proof_bytes.a3);
    }
  }

  {
    const auto start = std::chrono::steady_clock::now();
    std::vector<Envelope> phase3 = CollectSignPhase3(&sessions);
    const uint64_t bytes = MeasureEnvelopeBytes(phase3);
    DeliverSignOrThrow(phase3, signers, &sessions);
    Expect(AllSignSessionsInPhase(sessions, SignPhase::kPhase4), "sign did not advance to phase4");
    const auto end = std::chrono::steady_clock::now();
    RecordMetric(&metrics->phase3, start, end, bytes);
  }

  {
    const auto start = std::chrono::steady_clock::now();
    std::vector<Envelope> phase4 = CollectSignPhase4(&sessions);
    const uint64_t bytes = MeasureEnvelopeBytes(phase4);
    const uint64_t proof_bytes = MeasureSignPhase4GammaSchnorrProofBytes(phase4);
    DeliverSignOrThrow(phase4, signers, &sessions);
    Expect(AllSignSessionsInPhase(sessions, SignPhase::kPhase5, SignPhase5Stage::kPhase5A),
           "sign did not advance to phase5A");
    const auto end = std::chrono::steady_clock::now();
    RecordMetric(&metrics->phase4, start, end, bytes);
    if (strict_metrics != nullptr) {
      RecordMetric(&strict_metrics->sign_phase4_gamma_schnorr, start, end, proof_bytes);
    }
  }

  {
    const auto start = std::chrono::steady_clock::now();
    std::vector<Envelope> phase5a = CollectSignPhase5A(&sessions);
    const uint64_t bytes = MeasureEnvelopeBytes(phase5a);
    DeliverSignOrThrow(phase5a, signers, &sessions);
    Expect(AllSignSessionsInPhase(sessions, SignPhase::kPhase5, SignPhase5Stage::kPhase5B),
           "sign did not advance to phase5B");
    const auto end = std::chrono::steady_clock::now();
    RecordMetric(&metrics->phase5a, start, end, bytes);
  }

  {
    const auto start = std::chrono::steady_clock::now();
    std::vector<Envelope> phase5b = CollectSignPhase5B(&sessions);
    const uint64_t bytes = MeasureEnvelopeBytes(phase5b);
    const SignPhase5BProofBytes proof_bytes = MeasureSignPhase5BProofBytes(phase5b);
    DeliverSignOrThrow(phase5b, signers, &sessions);
    Expect(AllSignSessionsInPhase(sessions, SignPhase::kPhase5, SignPhase5Stage::kPhase5C),
           "sign did not advance to phase5C");
    const auto end = std::chrono::steady_clock::now();
    RecordMetric(&metrics->phase5b, start, end, bytes);
    if (strict_metrics != nullptr) {
      RecordMetric(&strict_metrics->sign_phase5b_proofs, start, end, proof_bytes.Total());
      RecordBytesMetric(&strict_metrics->sign_phase5b_a_schnorr, proof_bytes.a_schnorr);
      RecordBytesMetric(&strict_metrics->sign_phase5b_v_relation, proof_bytes.v_relation);
    }
  }

  {
    const auto start = std::chrono::steady_clock::now();
    std::vector<Envelope> phase5c = CollectSignPhase5C(&sessions);
    const uint64_t bytes = MeasureEnvelopeBytes(phase5c);
    DeliverSignOrThrow(phase5c, signers, &sessions);
    Expect(AllSignSessionsInPhase(sessions, SignPhase::kPhase5, SignPhase5Stage::kPhase5D),
           "sign did not advance to phase5D");
    const auto end = std::chrono::steady_clock::now();
    RecordMetric(&metrics->phase5c, start, end, bytes);
  }

  {
    const auto start = std::chrono::steady_clock::now();
    std::vector<Envelope> phase5d = CollectSignPhase5D(&sessions);
    const uint64_t bytes = MeasureEnvelopeBytes(phase5d);
    DeliverSignOrThrow(phase5d, signers, &sessions);
    Expect(AllSignSessionsInPhase(sessions, SignPhase::kPhase5, SignPhase5Stage::kPhase5E),
           "sign did not advance to phase5E");
    const auto end = std::chrono::steady_clock::now();
    RecordMetric(&metrics->phase5d, start, end, bytes);
  }

  {
    const auto start = std::chrono::steady_clock::now();
    std::vector<Envelope> phase5e = CollectSignPhase5E(&sessions);
    const uint64_t bytes = MeasureEnvelopeBytes(phase5e);
    DeliverSignOrThrow(phase5e, signers, &sessions);
    const auto end = std::chrono::steady_clock::now();
    RecordMetric(&metrics->phase5e, start, end, bytes);
  }

  for (const auto& session : sessions) {
    Expect(session->status() == SessionStatus::kCompleted, "sign session did not complete");
    Expect(session->HasResult(), "completed sign session has no result");
  }
}

void PrintMetricLine(const std::string& name, const PhaseMetric& metric) {
  const double avg_ms = AverageMs(metric);
  const double avg_bytes = AverageBytes(metric);
  std::cout << std::left << std::setw(14) << name << "  "
            << std::right << std::setw(12) << std::fixed << std::setprecision(3) << avg_ms << "  "
            << std::setw(14) << std::fixed << std::setprecision(1) << avg_bytes << '\n';
}

void PrintKeygenSummary(const KeygenMetrics& metrics) {
  std::cout << "\n[Keygen]\n";
  std::cout << std::left << std::setw(14) << "Phase"
            << "  " << std::right << std::setw(12) << "Avg ms"
            << "  " << std::setw(14) << "Avg bytes\n";
  PrintMetricLine("phase1", metrics.phase1);
  PrintMetricLine("phase2", metrics.phase2);
  PrintMetricLine("phase3", metrics.phase3);
}

void PrintSignSummary(const SignMetrics& metrics) {
  std::cout << "\n[Sign]\n";
  std::cout << std::left << std::setw(14) << "Phase"
            << "  " << std::right << std::setw(12) << "Avg ms"
            << "  " << std::setw(14) << "Avg bytes\n";
  PrintMetricLine("phase1", metrics.phase1);
  PrintMetricLine("phase2", metrics.phase2);
  PrintMetricLine("phase3", metrics.phase3);
  PrintMetricLine("phase4", metrics.phase4);
  PrintMetricLine("phase5A", metrics.phase5a);
  PrintMetricLine("phase5B", metrics.phase5b);
  PrintMetricLine("phase5C", metrics.phase5c);
  PrintMetricLine("phase5D", metrics.phase5d);
  PrintMetricLine("phase5E", metrics.phase5e);
}

void PrintStrictProofMetricLine(const std::string& component,
                                const PhaseMetric& proof_metric,
                                const PhaseMetric& phase_metric) {
  const double avg_ms = AverageMs(proof_metric);
  const double avg_proof_bytes = AverageBytes(proof_metric);
  const double avg_phase_bytes = AverageBytes(phase_metric);
  const double proof_ratio = (avg_phase_bytes > 0.0) ? (avg_proof_bytes * 100.0 / avg_phase_bytes) : 0.0;
  std::cout << std::left << std::setw(24) << component << "  "
            << std::right << std::setw(12) << std::fixed << std::setprecision(3) << avg_ms << "  "
            << std::setw(16) << std::fixed << std::setprecision(1) << avg_proof_bytes << "  "
            << std::setw(15) << std::fixed << std::setprecision(2) << proof_ratio << '\n';
}

void PrintByteMetricLine(const std::string& component, const ByteMetric& metric) {
  const double avg_bytes = AverageBytes(metric);
  std::cout << std::left << std::setw(24) << component << "  "
            << std::right << std::setw(16) << std::fixed << std::setprecision(1) << avg_bytes << '\n';
}

void PrintStrictProofSummary(const StrictProofMetrics& strict_metrics,
                             const KeygenMetrics& keygen_metrics,
                             const SignMetrics& sign_metrics) {
  std::cout << "\n[Strict-Proof Attribution]\n";
  std::cout << std::left << std::setw(24) << "Component"
            << "  " << std::right << std::setw(12) << "Avg ms"
            << "  " << std::setw(16) << "Proof bytes"
            << "  " << std::setw(15) << "Proof bytes %\n";

  PrintStrictProofMetricLine(
      "keygen.phase1 aux", strict_metrics.keygen_phase1_aux_param, keygen_metrics.phase1);
  PrintStrictProofMetricLine(
      "keygen.phase3 square", strict_metrics.keygen_phase3_square_free, keygen_metrics.phase3);
  PrintStrictProofMetricLine(
      "sign.phase2 A1/A2/A3", strict_metrics.sign_phase2_a_proofs, sign_metrics.phase2);
  PrintStrictProofMetricLine(
      "sign.phase4 schnorr", strict_metrics.sign_phase4_gamma_schnorr, sign_metrics.phase4);
  PrintStrictProofMetricLine(
      "sign.phase5B proofs", strict_metrics.sign_phase5b_proofs, sign_metrics.phase5b);

  const double keygen_strict_avg_ms =
      AverageMs(strict_metrics.keygen_phase1_aux_param) + AverageMs(strict_metrics.keygen_phase3_square_free);
  const double keygen_strict_avg_bytes =
      AverageBytes(strict_metrics.keygen_phase1_aux_param) + AverageBytes(strict_metrics.keygen_phase3_square_free);
  const double keygen_total_avg_bytes =
      AverageBytes(keygen_metrics.phase1) + AverageBytes(keygen_metrics.phase2) + AverageBytes(keygen_metrics.phase3);
  const double keygen_ratio =
      (keygen_total_avg_bytes > 0.0) ? (keygen_strict_avg_bytes * 100.0 / keygen_total_avg_bytes) : 0.0;

  const double sign_strict_avg_ms =
      AverageMs(strict_metrics.sign_phase2_a_proofs) + AverageMs(strict_metrics.sign_phase4_gamma_schnorr) +
      AverageMs(strict_metrics.sign_phase5b_proofs);
  const double sign_strict_avg_bytes =
      AverageBytes(strict_metrics.sign_phase2_a_proofs) + AverageBytes(strict_metrics.sign_phase4_gamma_schnorr) +
      AverageBytes(strict_metrics.sign_phase5b_proofs);
  const double sign_total_avg_bytes =
      AverageBytes(sign_metrics.phase1) + AverageBytes(sign_metrics.phase2) + AverageBytes(sign_metrics.phase3) +
      AverageBytes(sign_metrics.phase4) + AverageBytes(sign_metrics.phase5a) + AverageBytes(sign_metrics.phase5b) +
      AverageBytes(sign_metrics.phase5c) + AverageBytes(sign_metrics.phase5d) + AverageBytes(sign_metrics.phase5e);
  const double sign_ratio =
      (sign_total_avg_bytes > 0.0) ? (sign_strict_avg_bytes * 100.0 / sign_total_avg_bytes) : 0.0;

  std::cout << std::left << std::setw(24) << "keygen strict subtotal"
            << "  " << std::right << std::setw(12) << std::fixed << std::setprecision(3) << keygen_strict_avg_ms
            << "  " << std::setw(16) << std::fixed << std::setprecision(1) << keygen_strict_avg_bytes << "  "
            << std::setw(15) << std::fixed << std::setprecision(2) << keygen_ratio << '\n';
  std::cout << std::left << std::setw(24) << "sign strict subtotal"
            << "  " << std::right << std::setw(12) << std::fixed << std::setprecision(3) << sign_strict_avg_ms
            << "  " << std::setw(16) << std::fixed << std::setprecision(1) << sign_strict_avg_bytes << "  "
            << std::setw(15) << std::fixed << std::setprecision(2) << sign_ratio << '\n';

  std::cout << "\n[Strict-Proof Byte Detail]\n";
  std::cout << std::left << std::setw(24) << "Component"
            << "  " << std::right << std::setw(16) << "Avg bytes\n";
  PrintByteMetricLine("sign.phase2 A1", strict_metrics.sign_phase2_a1);
  PrintByteMetricLine("sign.phase2 A2", strict_metrics.sign_phase2_a2);
  PrintByteMetricLine("sign.phase2 A3", strict_metrics.sign_phase2_a3);
  PrintByteMetricLine("sign.phase5B schnorr", strict_metrics.sign_phase5b_a_schnorr);
  PrintByteMetricLine("sign.phase5B relation", strict_metrics.sign_phase5b_v_relation);
}

}  // namespace

int main(int argc, char** argv) {
  try {
    const BenchArgs args = ParseArgs(argc, argv);
    std::cout << "M9 benchmark config: n=" << args.n
              << ", t=" << args.t
              << ", keygen_iters=" << args.keygen_iters
              << ", sign_iters=" << args.sign_iters
              << ", paillier_bits=" << args.paillier_bits << '\n';

    KeygenMetrics keygen_metrics;
    StrictProofMetrics strict_metrics;
    std::unordered_map<PartyIndex, KeygenResult> baseline_keygen_results;
    for (uint32_t i = 0; i < args.keygen_iters; ++i) {
      baseline_keygen_results = RunKeygenRound(args, i, &keygen_metrics, &strict_metrics);
    }

    std::vector<PartyIndex> signers;
    signers.reserve(args.t + 1);
    for (PartyIndex id = 1; id <= args.t + 1; ++id) {
      signers.push_back(id);
    }

    SignMetrics sign_metrics;
    for (uint32_t i = 0; i < args.sign_iters; ++i) {
      RunSignRound(baseline_keygen_results, signers, i, &sign_metrics, &strict_metrics);
    }

    PrintKeygenSummary(keygen_metrics);
    PrintSignSummary(sign_metrics);
    PrintStrictProofSummary(strict_metrics, keygen_metrics, sign_metrics);
  } catch (const std::exception& ex) {
    std::cerr << "benchmark failed: " << ex.what() << '\n';
    return 1;
  }
  return 0;
}
