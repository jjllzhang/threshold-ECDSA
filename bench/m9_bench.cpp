#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <memory>
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
                                                            KeygenMetrics* metrics) {
  auto sessions = BuildKeygenSessions(args, MakeSessionId(0xA1, iteration));

  {
    const auto start = std::chrono::steady_clock::now();
    std::vector<Envelope> phase1;
    phase1.reserve(sessions.size());
    for (auto& session : sessions) {
      phase1.push_back(session->BuildPhase1CommitEnvelope());
    }
    const uint64_t bytes = MeasureEnvelopeBytes(phase1);
    DeliverKeygenOrThrow(phase1, &sessions);
    const auto end = std::chrono::steady_clock::now();
    RecordMetric(&metrics->phase1, start, end, bytes);
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
    DeliverKeygenOrThrow(phase3, &sessions);
    const auto end = std::chrono::steady_clock::now();
    RecordMetric(&metrics->phase3, start, end, bytes);
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
                  SignMetrics* metrics) {
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
    for (size_t round = 0; round < 64; ++round) {
      std::vector<Envelope> phase2 = CollectSignPhase2(&sessions);
      if (phase2.empty()) {
        throw std::runtime_error("sign phase2 stalled");
      }
      bytes += MeasureEnvelopeBytes(phase2);
      DeliverSignOrThrow(phase2, signers, &sessions);
      if (AllSignSessionsInPhase(sessions, SignPhase::kPhase3)) {
        break;
      }
    }
    Expect(AllSignSessionsInPhase(sessions, SignPhase::kPhase3), "sign did not finish phase2");
    const auto end = std::chrono::steady_clock::now();
    RecordMetric(&metrics->phase2, start, end, bytes);
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
    DeliverSignOrThrow(phase4, signers, &sessions);
    Expect(AllSignSessionsInPhase(sessions, SignPhase::kPhase5, SignPhase5Stage::kPhase5A),
           "sign did not advance to phase5A");
    const auto end = std::chrono::steady_clock::now();
    RecordMetric(&metrics->phase4, start, end, bytes);
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
    DeliverSignOrThrow(phase5b, signers, &sessions);
    Expect(AllSignSessionsInPhase(sessions, SignPhase::kPhase5, SignPhase5Stage::kPhase5C),
           "sign did not advance to phase5C");
    const auto end = std::chrono::steady_clock::now();
    RecordMetric(&metrics->phase5b, start, end, bytes);
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
  const double avg_ms = metric.total_ms / static_cast<double>(metric.samples);
  const double avg_bytes = static_cast<double>(metric.total_bytes) / static_cast<double>(metric.samples);
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
    std::unordered_map<PartyIndex, KeygenResult> baseline_keygen_results;
    for (uint32_t i = 0; i < args.keygen_iters; ++i) {
      baseline_keygen_results = RunKeygenRound(args, i, &keygen_metrics);
    }

    std::vector<PartyIndex> signers;
    signers.reserve(args.t + 1);
    for (PartyIndex id = 1; id <= args.t + 1; ++id) {
      signers.push_back(id);
    }

    SignMetrics sign_metrics;
    for (uint32_t i = 0; i < args.sign_iters; ++i) {
      RunSignRound(baseline_keygen_results, signers, i, &sign_metrics);
    }

    PrintKeygenSummary(keygen_metrics);
    PrintSignSummary(sign_metrics);
  } catch (const std::exception& ex) {
    std::cerr << "benchmark failed: " << ex.what() << '\n';
    return 1;
  }
  return 0;
}
