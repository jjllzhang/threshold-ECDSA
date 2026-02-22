#include <chrono>
#include <cstdint>
#include <functional>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

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
using tecdsa::Scalar;
using tecdsa::SessionStatus;
using tecdsa::SignPhase;
using tecdsa::PaillierPublicKey;
using tecdsa::SignPhase5Stage;
using tecdsa::SignSession;
using tecdsa::SignSessionConfig;

std::unordered_map<PartyIndex, SignSessionConfig::AuxRsaParams> BuildAuxParamsFromPaillier(
    const std::vector<PartyIndex>& signers,
    const std::unordered_map<PartyIndex, tecdsa::PaillierPublicKey>& paillier_public) {
  std::unordered_map<PartyIndex, SignSessionConfig::AuxRsaParams> out;
  out.reserve(signers.size());

  auto pick_coprime = [](const mpz_class& modulus, const mpz_class& seed) {
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
  };

  for (PartyIndex party : signers) {
    const auto pub_it = paillier_public.find(party);
    if (pub_it == paillier_public.end()) {
      throw std::runtime_error("missing Paillier public key while building aux params");
    }
    const mpz_class n_tilde = pub_it->second.n;
    const mpz_class h1 = pick_coprime(n_tilde, mpz_class(2 + 2 * party));
    mpz_class h2 = pick_coprime(n_tilde, mpz_class(3 + 2 * party));
    if (h2 == h1) {
      h2 = pick_coprime(n_tilde, h1 + 1);
    }
    out.emplace(party, SignSessionConfig::AuxRsaParams{
                          .n_tilde = n_tilde,
                          .h1 = h1,
                          .h2 = h2,
                      });
  }

  return out;
}

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
  throw std::runtime_error("party id not found in parties vector");
}

std::vector<std::unique_ptr<KeygenSession>> BuildKeygenSessions(uint32_t n,
                                                                uint32_t t,
                                                                const Bytes& session_id) {
  const std::vector<PartyIndex> participants = BuildParticipants(n);

  std::vector<std::unique_ptr<KeygenSession>> sessions;
  sessions.reserve(n);
  for (PartyIndex self_id : participants) {
    KeygenSessionConfig cfg;
    cfg.session_id = session_id;
    cfg.self_id = self_id;
    cfg.participants = participants;
    cfg.threshold = t;
    cfg.timeout = std::chrono::seconds(10);
    sessions.push_back(std::make_unique<KeygenSession>(std::move(cfg)));
  }
  return sessions;
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
    throw std::runtime_error("Envelope recipient is out of range");
  }

  if (!(*sessions)[envelope.to - 1]->HandleEnvelope(envelope)) {
    ok = false;
  }
  return ok;
}

void DeliverKeygenEnvelopesOrThrow(const std::vector<Envelope>& envelopes,
                                   std::vector<std::unique_ptr<KeygenSession>>* sessions) {
  for (const Envelope& envelope : envelopes) {
    if (!DeliverKeygenEnvelope(envelope, sessions)) {
      throw std::runtime_error("Unexpected keygen envelope delivery failure");
    }
  }
}

std::unordered_map<PartyIndex, KeygenResult> RunKeygenAndCollectResults(uint32_t n,
                                                                         uint32_t t,
                                                                         const Bytes& session_id) {
  auto sessions = BuildKeygenSessions(n, t, session_id);

  std::vector<Envelope> phase1;
  phase1.reserve(n);
  for (auto& session : sessions) {
    phase1.push_back(session->BuildPhase1CommitEnvelope());
  }
  DeliverKeygenEnvelopesOrThrow(phase1, &sessions);

  std::vector<Envelope> phase2;
  for (auto& session : sessions) {
    const std::vector<Envelope> messages = session->BuildPhase2OpenAndShareEnvelopes();
    phase2.insert(phase2.end(), messages.begin(), messages.end());
  }
  DeliverKeygenEnvelopesOrThrow(phase2, &sessions);

  std::vector<Envelope> phase3;
  phase3.reserve(n);
  for (auto& session : sessions) {
    phase3.push_back(session->BuildPhase3XiProofEnvelope());
  }
  DeliverKeygenEnvelopesOrThrow(phase3, &sessions);

  std::unordered_map<PartyIndex, KeygenResult> results;
  for (size_t idx = 0; idx < sessions.size(); ++idx) {
    const PartyIndex party_id = static_cast<PartyIndex>(idx + 1);
    Expect(sessions[idx]->status() == SessionStatus::kCompleted,
           "Keygen session should complete for party " + std::to_string(party_id));
    results.emplace(party_id, sessions[idx]->result());
  }

  return results;
}

struct SignFixture {
  std::vector<PartyIndex> signers;
  Bytes msg32;
  std::unordered_map<PartyIndex, Scalar> fixed_k;
  std::unordered_map<PartyIndex, Scalar> fixed_gamma;
};

SignFixture BuildSignFixture(const std::vector<PartyIndex>& signers) {
  SignFixture fixture;
  fixture.signers = signers;
  fixture.msg32 = Bytes{
      0x4d, 0x34, 0x2d, 0x73, 0x69, 0x67, 0x6e, 0x2d,
      0x74, 0x65, 0x73, 0x74, 0x2d, 0x30, 0x30, 0x31,
      0xaa, 0xbb, 0xcc, 0xdd, 0x10, 0x20, 0x30, 0x40,
      0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
  };
  for (PartyIndex party : signers) {
    const Scalar gamma_i = Scalar::FromUint64(20 + 2 * party);
    fixture.fixed_gamma.emplace(party, gamma_i);
  }

  for (PartyIndex party : signers) {
    const Scalar k_i = Scalar::FromUint64(10 + party);
    fixture.fixed_k.emplace(party, k_i);
  }

  return fixture;
}

std::vector<std::unique_ptr<SignSession>> BuildSignSessions(
    const SignFixture& fixture,
    const std::unordered_map<PartyIndex, KeygenResult>& keygen_results,
    const Bytes& sign_session_id) {
  std::vector<std::unique_ptr<SignSession>> sessions;
  sessions.reserve(fixture.signers.size());

  const auto baseline_it = keygen_results.find(fixture.signers.front());
  if (baseline_it == keygen_results.end()) {
    throw std::runtime_error("missing baseline keygen result");
  }

  std::unordered_map<PartyIndex, tecdsa::ECPoint> all_X_i_subset;
  all_X_i_subset.reserve(fixture.signers.size());
  for (PartyIndex party : fixture.signers) {
    const auto x_it = baseline_it->second.all_X_i.find(party);
    if (x_it == baseline_it->second.all_X_i.end()) {
      throw std::runtime_error("baseline keygen result missing X_i for signer");
    }
    all_X_i_subset.emplace(party, x_it->second);
  }

  std::unordered_map<PartyIndex, std::shared_ptr<tecdsa::PaillierProvider>> paillier_private;
  std::unordered_map<PartyIndex, tecdsa::PaillierPublicKey> paillier_public;
  paillier_private.reserve(fixture.signers.size());
  paillier_public.reserve(fixture.signers.size());
  for (PartyIndex party : fixture.signers) {
    const auto party_result_it = keygen_results.find(party);
    if (party_result_it == keygen_results.end()) {
      throw std::runtime_error("missing keygen result for signer Paillier key");
    }
    if (party_result_it->second.local_paillier == nullptr) {
      throw std::runtime_error("missing local Paillier private key in keygen result");
    }
    const auto paillier_pub_it = party_result_it->second.all_paillier_public.find(party);
    if (paillier_pub_it == party_result_it->second.all_paillier_public.end()) {
      throw std::runtime_error("missing self Paillier public key in keygen result");
    }

    paillier_public.emplace(party, paillier_pub_it->second);
    paillier_private.emplace(party, party_result_it->second.local_paillier);
  }
  const auto aux_params = BuildAuxParamsFromPaillier(fixture.signers, paillier_public);

  for (PartyIndex self_id : fixture.signers) {
    const auto keygen_it = keygen_results.find(self_id);
    if (keygen_it == keygen_results.end()) {
      throw std::runtime_error("missing keygen result for signer");
    }

    SignSessionConfig cfg;
    cfg.session_id = sign_session_id;
    cfg.self_id = self_id;
    cfg.participants = fixture.signers;
    cfg.timeout = std::chrono::seconds(10);
    cfg.x_i = keygen_it->second.x_i;
    cfg.y = baseline_it->second.y;
    cfg.all_X_i = all_X_i_subset;
    cfg.all_paillier_public = paillier_public;
    cfg.all_aux_rsa_params = aux_params;
    cfg.local_paillier = paillier_private.at(self_id);
    cfg.msg32 = fixture.msg32;
    cfg.fixed_k_i = fixture.fixed_k.at(self_id);
    cfg.fixed_gamma_i = fixture.fixed_gamma.at(self_id);

    sessions.push_back(std::make_unique<SignSession>(std::move(cfg)));
  }

  return sessions;
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

void DeliverSignEnvelopesOrThrow(const std::vector<Envelope>& envelopes,
                                 const std::vector<PartyIndex>& signers,
                                 std::vector<std::unique_ptr<SignSession>>* sessions) {
  for (const Envelope& envelope : envelopes) {
    if (!DeliverSignEnvelope(envelope, signers, sessions)) {
      throw std::runtime_error("Unexpected sign envelope delivery failure");
    }
  }
}

std::vector<Envelope> CollectPhase1Messages(std::vector<std::unique_ptr<SignSession>>* sessions) {
  std::vector<Envelope> out;
  out.reserve(sessions->size());
  for (auto& session : *sessions) {
    out.push_back(session->BuildPhase1CommitEnvelope());
  }
  return out;
}

std::vector<Envelope> CollectPhase2Messages(std::vector<std::unique_ptr<SignSession>>* sessions) {
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

std::vector<Envelope> CollectPhase3Messages(std::vector<std::unique_ptr<SignSession>>* sessions) {
  std::vector<Envelope> out;
  out.reserve(sessions->size());
  for (auto& session : *sessions) {
    out.push_back(session->BuildPhase3DeltaEnvelope());
  }
  return out;
}

std::vector<Envelope> CollectPhase4Messages(std::vector<std::unique_ptr<SignSession>>* sessions) {
  std::vector<Envelope> out;
  out.reserve(sessions->size());
  for (auto& session : *sessions) {
    out.push_back(session->BuildPhase4OpenGammaEnvelope());
  }
  return out;
}

std::vector<Envelope> CollectPhase5AMessages(std::vector<std::unique_ptr<SignSession>>* sessions) {
  std::vector<Envelope> out;
  out.reserve(sessions->size());
  for (auto& session : *sessions) {
    out.push_back(session->BuildPhase5ACommitEnvelope());
  }
  return out;
}

std::vector<Envelope> CollectPhase5BMessages(std::vector<std::unique_ptr<SignSession>>* sessions) {
  std::vector<Envelope> out;
  out.reserve(sessions->size());
  for (auto& session : *sessions) {
    out.push_back(session->BuildPhase5BOpenEnvelope());
  }
  return out;
}

std::vector<Envelope> CollectPhase5CMessages(std::vector<std::unique_ptr<SignSession>>* sessions) {
  std::vector<Envelope> out;
  out.reserve(sessions->size());
  for (auto& session : *sessions) {
    out.push_back(session->BuildPhase5CCommitEnvelope());
  }
  return out;
}

std::vector<Envelope> CollectPhase5DMessages(std::vector<std::unique_ptr<SignSession>>* sessions) {
  std::vector<Envelope> out;
  out.reserve(sessions->size());
  for (auto& session : *sessions) {
    out.push_back(session->BuildPhase5DOpenEnvelope());
  }
  return out;
}

std::vector<Envelope> CollectPhase5EMessages(std::vector<std::unique_ptr<SignSession>>* sessions) {
  std::vector<Envelope> out;
  out.reserve(sessions->size());
  for (auto& session : *sessions) {
    out.push_back(session->BuildPhase5ERevealEnvelope());
  }
  return out;
}

void EnsureAllSessionsInPhase(const std::vector<std::unique_ptr<SignSession>>& sessions,
                              SignPhase phase,
                              SignPhase5Stage phase5_stage = SignPhase5Stage::kPhase5A) {
  for (size_t idx = 0; idx < sessions.size(); ++idx) {
    Expect(sessions[idx]->status() == SessionStatus::kRunning,
           "Sign session should be running before completion/abort");
    Expect(sessions[idx]->phase() == phase,
           "Sign session has unexpected protocol phase");
    if (phase == SignPhase::kPhase5) {
      Expect(sessions[idx]->phase5_stage() == phase5_stage,
             "Sign session has unexpected phase5 sub-stage");
    }
  }
}

void RunToPhase5B(std::vector<std::unique_ptr<SignSession>>* sessions,
                  const std::vector<PartyIndex>& signers) {
  DeliverSignEnvelopesOrThrow(CollectPhase1Messages(sessions), signers, sessions);
  EnsureAllSessionsInPhase(*sessions, SignPhase::kPhase2);

  for (size_t round = 0; round < 32; ++round) {
    const std::vector<Envelope> phase2_messages = CollectPhase2Messages(sessions);
    if (phase2_messages.empty()) {
      throw std::runtime_error("phase2 stalled before MtA/MtAwc completion");
    }
    DeliverSignEnvelopesOrThrow(phase2_messages, signers, sessions);

    bool all_phase3 = true;
    for (const auto& session : *sessions) {
      if (session->phase() != SignPhase::kPhase3) {
        all_phase3 = false;
        break;
      }
    }
    if (all_phase3) {
      break;
    }
  }
  EnsureAllSessionsInPhase(*sessions, SignPhase::kPhase3);

  DeliverSignEnvelopesOrThrow(CollectPhase3Messages(sessions), signers, sessions);
  EnsureAllSessionsInPhase(*sessions, SignPhase::kPhase4);

  DeliverSignEnvelopesOrThrow(CollectPhase4Messages(sessions), signers, sessions);
  EnsureAllSessionsInPhase(*sessions, SignPhase::kPhase5, SignPhase5Stage::kPhase5A);

  DeliverSignEnvelopesOrThrow(CollectPhase5AMessages(sessions), signers, sessions);
  EnsureAllSessionsInPhase(*sessions, SignPhase::kPhase5, SignPhase5Stage::kPhase5B);
}

void RunToPhase5D(std::vector<std::unique_ptr<SignSession>>* sessions,
                  const std::vector<PartyIndex>& signers) {
  RunToPhase5B(sessions, signers);

  DeliverSignEnvelopesOrThrow(CollectPhase5BMessages(sessions), signers, sessions);
  EnsureAllSessionsInPhase(*sessions, SignPhase::kPhase5, SignPhase5Stage::kPhase5C);

  DeliverSignEnvelopesOrThrow(CollectPhase5CMessages(sessions), signers, sessions);
  EnsureAllSessionsInPhase(*sessions, SignPhase::kPhase5, SignPhase5Stage::kPhase5D);
}

uint32_t ReadU32Be(const Bytes& input, size_t offset) {
  if (offset + 4 > input.size()) {
    throw std::runtime_error("payload is too short to parse u32");
  }
  return (static_cast<uint32_t>(input[offset]) << 24) |
         (static_cast<uint32_t>(input[offset + 1]) << 16) |
         (static_cast<uint32_t>(input[offset + 2]) << 8) |
         static_cast<uint32_t>(input[offset + 3]);
}

bool TamperPhase5BSchnorrProof(Envelope* envelope) {
  if (envelope == nullptr) {
    return false;
  }
  size_t offset = 0;
  constexpr size_t kPointLen = 33;
  constexpr size_t kScalarLen = 32;

  if (envelope->payload.size() < kPointLen * 2 + 4 + kPointLen + kScalarLen) {
    return false;
  }
  offset += kPointLen;  // V_i
  offset += kPointLen;  // A_i
  const uint32_t randomness_len = ReadU32Be(envelope->payload, offset);
  offset += 4;
  if (offset + randomness_len + kPointLen + kScalarLen > envelope->payload.size()) {
    return false;
  }
  offset += randomness_len;
  offset += kPointLen;  // Schnorr A

  envelope->payload[offset + kScalarLen - 1] ^= 0x01;  // Schnorr z
  return true;
}

void TestM4SignEndToEndProducesVerifiableSignature() {
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD1, 0x03, 0x01});

  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  auto sessions = BuildSignSessions(fixture, keygen_results, Bytes{0xE1, 0x02, 0x01});

  RunToPhase5D(&sessions, signers);

  DeliverSignEnvelopesOrThrow(CollectPhase5DMessages(&sessions), signers, &sessions);
  EnsureAllSessionsInPhase(sessions, SignPhase::kPhase5, SignPhase5Stage::kPhase5E);

  DeliverSignEnvelopesOrThrow(CollectPhase5EMessages(&sessions), signers, &sessions);

  const auto& first_result = sessions.front()->result();
  Expect(first_result.r.value() != 0, "Final signature r must be non-zero");
  Expect(first_result.s.value() != 0, "Final signature s must be non-zero");

  for (size_t idx = 0; idx < sessions.size(); ++idx) {
    Expect(sessions[idx]->status() == SessionStatus::kCompleted,
           "Sign session should complete after phase5E");
    Expect(sessions[idx]->phase() == SignPhase::kCompleted,
           "Sign session should be in completed phase");
    Expect(sessions[idx]->HasResult(),
           "Completed sign session should expose result");

    const auto& result = sessions[idx]->result();
    Expect(result.r == first_result.r, "All signers must derive same r");
    Expect(result.s == first_result.s, "All signers must derive same s");
    Expect(result.R == first_result.R, "All signers must derive same R");
    Expect(result.W_points.size() == signers.size(),
           "Result should expose W_i for all signing parties");
  }
}

void TestM4Phase5DFailurePreventsPhase5EReveal() {
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD2, 0x03, 0x01});

  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture bad_fixture = BuildSignFixture(signers);
  auto sessions = BuildSignSessions(bad_fixture, keygen_results, Bytes{0xE2, 0x02, 0x01});

  RunToPhase5D(&sessions, signers);

  std::vector<Envelope> phase5d = CollectPhase5DMessages(&sessions);
  if (!phase5d.empty() && !phase5d.front().payload.empty()) {
    phase5d.front().payload.back() ^= 0x01;
  }
  for (const Envelope& envelope : phase5d) {
    (void)DeliverSignEnvelope(envelope, signers, &sessions);
  }

  bool any_aborted = false;
  for (const auto& session : sessions) {
    if (session->status() == SessionStatus::kAborted) {
      any_aborted = true;
    }
  }
  Expect(any_aborted, "At least one party must abort at phase5D when open payload is tampered");

  for (auto& session : sessions) {
    if (session->status() == SessionStatus::kAborted) {
      Expect(session->phase() == SignPhase::kPhase5,
             "Aborted session should remain in phase5");
      Expect(session->phase5_stage() == SignPhase5Stage::kPhase5D,
             "Aborted session must stay at phase5D");
      ExpectThrow([&]() { (void)session->BuildPhase5ERevealEnvelope(); },
                  "Aborted session cannot build phase5E reveal envelope");
    } else {
      Expect(session->status() == SessionStatus::kRunning,
             "Non-aborted peers should remain running after remote phase5D failure");
      Expect(session->phase() == SignPhase::kPhase5,
             "Non-aborted peers should remain in phase5");
      Expect(session->phase5_stage() == SignPhase5Stage::kPhase5D ||
                 session->phase5_stage() == SignPhase5Stage::kPhase5E,
             "Non-aborted peers may stay at phase5D or wait in phase5E");
    }
    Expect(!session->HasResult(), "Failure path must not expose final signature");
  }
}

void TestM5Phase2InstanceIdMismatchAborts() {
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD3, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  auto sessions = BuildSignSessions(fixture, keygen_results, Bytes{0xE3, 0x02, 0x01});

  DeliverSignEnvelopesOrThrow(CollectPhase1Messages(&sessions), signers, &sessions);
  EnsureAllSessionsInPhase(sessions, SignPhase::kPhase2);

  DeliverSignEnvelopesOrThrow(CollectPhase2Messages(&sessions), signers, &sessions);

  std::vector<Envelope> phase2_round2 = CollectPhase2Messages(&sessions);
  bool tampered = false;
  for (Envelope& envelope : phase2_round2) {
    if (envelope.type == SignSession::Phase2ResponseMessageType() && envelope.payload.size() > 8) {
      envelope.payload[8] ^= 0x01;
      tampered = true;
      break;
    }
  }
  Expect(tampered, "Test setup failed to locate a phase2 response envelope to tamper");

  for (const Envelope& envelope : phase2_round2) {
    (void)DeliverSignEnvelope(envelope, signers, &sessions);
  }

  bool any_aborted = false;
  for (const auto& session : sessions) {
    if (session->status() == SessionStatus::kAborted) {
      any_aborted = true;
    }
    Expect(!session->HasResult(), "Phase2-aborted session must not expose final signature");
  }
  Expect(any_aborted, "At least one signer must abort on mismatched phase2 instance id");
}

void TestM7TamperedPhase2A1ProofAbortsResponder() {
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD7, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  auto sessions = BuildSignSessions(fixture, keygen_results, Bytes{0xE7, 0x02, 0x01});

  DeliverSignEnvelopesOrThrow(CollectPhase1Messages(&sessions), signers, &sessions);
  EnsureAllSessionsInPhase(sessions, SignPhase::kPhase2);

  std::vector<Envelope> phase2_init = CollectPhase2Messages(&sessions);
  bool tampered = false;
  for (Envelope& envelope : phase2_init) {
    if (envelope.type == SignSession::MessageTypeForPhase(SignPhase::kPhase2) &&
        envelope.from == 1 &&
        envelope.to == 2 &&
        !envelope.payload.empty()) {
      envelope.payload.back() ^= 0x01;
      tampered = true;
      break;
    }
  }
  Expect(tampered, "Test setup failed to locate phase2 init A1 proof payload to tamper");

  for (const Envelope& envelope : phase2_init) {
    (void)DeliverSignEnvelope(envelope, signers, &sessions);
  }

  const size_t receiver_idx = FindPartyIndexOrThrow(signers, 2);
  Expect(sessions[receiver_idx]->status() == SessionStatus::kAborted,
         "Responder must abort when phase2 A1 proof is tampered");
  for (const auto& session : sessions) {
    Expect(!session->HasResult(), "Phase2 A1 proof failure must not expose signature");
  }
}

void TestM7TamperedPhase2A3ProofAbortsInitiator() {
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD8, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  auto sessions = BuildSignSessions(fixture, keygen_results, Bytes{0xE8, 0x02, 0x01});

  DeliverSignEnvelopesOrThrow(CollectPhase1Messages(&sessions), signers, &sessions);
  EnsureAllSessionsInPhase(sessions, SignPhase::kPhase2);
  DeliverSignEnvelopesOrThrow(CollectPhase2Messages(&sessions), signers, &sessions);

  std::vector<Envelope> phase2_responses = CollectPhase2Messages(&sessions);
  bool tampered = false;
  for (Envelope& envelope : phase2_responses) {
    if (envelope.type != SignSession::Phase2ResponseMessageType() ||
        envelope.from != 2 ||
        envelope.to != 1 ||
        envelope.payload.size() < 4) {
      continue;
    }
    const uint32_t raw_type = ReadU32Be(envelope.payload, 0);
    if (raw_type != 1) {  // MtA (times-gamma) uses A3
      continue;
    }
    envelope.payload.back() ^= 0x01;
    tampered = true;
    break;
  }
  Expect(tampered, "Test setup failed to locate phase2 response A3 proof payload to tamper");

  for (const Envelope& envelope : phase2_responses) {
    (void)DeliverSignEnvelope(envelope, signers, &sessions);
  }

  const size_t initiator_idx = FindPartyIndexOrThrow(signers, 1);
  Expect(sessions[initiator_idx]->status() == SessionStatus::kAborted,
         "Initiator must abort when phase2 A3 proof is tampered");
  for (const auto& session : sessions) {
    Expect(!session->HasResult(), "Phase2 A3 proof failure must not expose signature");
  }
}

void TestM7TamperedPhase2A2ProofAbortsInitiator() {
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD9, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  auto sessions = BuildSignSessions(fixture, keygen_results, Bytes{0xE9, 0x02, 0x01});

  DeliverSignEnvelopesOrThrow(CollectPhase1Messages(&sessions), signers, &sessions);
  EnsureAllSessionsInPhase(sessions, SignPhase::kPhase2);
  DeliverSignEnvelopesOrThrow(CollectPhase2Messages(&sessions), signers, &sessions);

  std::vector<Envelope> phase2_responses = CollectPhase2Messages(&sessions);
  bool tampered = false;
  for (Envelope& envelope : phase2_responses) {
    if (envelope.type != SignSession::Phase2ResponseMessageType() ||
        envelope.from != 2 ||
        envelope.to != 1 ||
        envelope.payload.size() < 4) {
      continue;
    }
    const uint32_t raw_type = ReadU32Be(envelope.payload, 0);
    if (raw_type != 2) {  // MtAwc (times-w) uses A2
      continue;
    }
    envelope.payload.back() ^= 0x01;
    tampered = true;
    break;
  }
  Expect(tampered, "Test setup failed to locate phase2 response A2 proof payload to tamper");

  for (const Envelope& envelope : phase2_responses) {
    (void)DeliverSignEnvelope(envelope, signers, &sessions);
  }

  const size_t initiator_idx = FindPartyIndexOrThrow(signers, 1);
  Expect(sessions[initiator_idx]->status() == SessionStatus::kAborted,
         "Initiator must abort when phase2 A2 proof is tampered");
  for (const auto& session : sessions) {
    Expect(!session->HasResult(), "Phase2 A2 proof failure must not expose signature");
  }
}

void TestM6TamperedPhase4GammaSchnorrAbortsReceiver() {
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD4, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  auto sessions = BuildSignSessions(fixture, keygen_results, Bytes{0xE4, 0x02, 0x01});

  DeliverSignEnvelopesOrThrow(CollectPhase1Messages(&sessions), signers, &sessions);
  EnsureAllSessionsInPhase(sessions, SignPhase::kPhase2);

  for (size_t round = 0; round < 32; ++round) {
    const std::vector<Envelope> phase2_messages = CollectPhase2Messages(&sessions);
    if (phase2_messages.empty()) {
      throw std::runtime_error("phase2 stalled before MtA/MtAwc completion");
    }
    DeliverSignEnvelopesOrThrow(phase2_messages, signers, &sessions);

    bool all_phase3 = true;
    for (const auto& session : sessions) {
      if (session->phase() != SignPhase::kPhase3) {
        all_phase3 = false;
        break;
      }
    }
    if (all_phase3) {
      break;
    }
  }
  EnsureAllSessionsInPhase(sessions, SignPhase::kPhase3);

  DeliverSignEnvelopesOrThrow(CollectPhase3Messages(&sessions), signers, &sessions);
  EnsureAllSessionsInPhase(sessions, SignPhase::kPhase4);

  std::vector<Envelope> phase4_messages = CollectPhase4Messages(&sessions);
  bool tampered = false;
  for (Envelope& envelope : phase4_messages) {
    if (envelope.from == 1 && !envelope.payload.empty()) {
      envelope.payload.back() ^= 0x01;
      tampered = true;
      break;
    }
  }
  Expect(tampered, "Test setup failed to locate phase4 proof payload to tamper");

  for (const Envelope& envelope : phase4_messages) {
    (void)DeliverSignEnvelope(envelope, signers, &sessions);
  }

  const size_t receiver_idx = FindPartyIndexOrThrow(signers, 2);
  Expect(sessions[receiver_idx]->status() == SessionStatus::kAborted,
         "Receiver must abort when phase4 gamma Schnorr proof is tampered");
  Expect(sessions[receiver_idx]->phase() == SignPhase::kPhase4,
         "Phase4 proof failure should abort in phase4");
  for (const auto& session : sessions) {
    Expect(!session->HasResult(), "Phase4 proof failure must not expose signature result");
  }
}

void TestM6TamperedPhase5BASchnorrAbortsReceiver() {
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD5, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  auto sessions = BuildSignSessions(fixture, keygen_results, Bytes{0xE5, 0x02, 0x01});

  RunToPhase5B(&sessions, signers);

  std::vector<Envelope> phase5b_messages = CollectPhase5BMessages(&sessions);
  bool tampered = false;
  for (Envelope& envelope : phase5b_messages) {
    if (envelope.from == 1) {
      tampered = TamperPhase5BSchnorrProof(&envelope);
      if (tampered) {
        break;
      }
    }
  }
  Expect(tampered, "Test setup failed to locate phase5B Schnorr proof payload to tamper");

  for (const Envelope& envelope : phase5b_messages) {
    (void)DeliverSignEnvelope(envelope, signers, &sessions);
  }

  const size_t receiver_idx = FindPartyIndexOrThrow(signers, 2);
  Expect(sessions[receiver_idx]->status() == SessionStatus::kAborted,
         "Receiver must abort when phase5B A_i Schnorr proof is tampered");
  Expect(sessions[receiver_idx]->phase() == SignPhase::kPhase5,
         "Phase5B proof failure should abort in phase5");
  Expect(sessions[receiver_idx]->phase5_stage() == SignPhase5Stage::kPhase5B,
         "Phase5B A_i proof failure should abort in stage5B");
  for (const auto& session : sessions) {
    Expect(!session->HasResult(), "Phase5B Schnorr proof failure must not expose signature result");
  }
}

void TestM6TamperedPhase5BVRelationAbortsReceiver() {
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD6, 0x03, 0x01});
  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers);
  auto sessions = BuildSignSessions(fixture, keygen_results, Bytes{0xE6, 0x02, 0x01});

  RunToPhase5B(&sessions, signers);

  std::vector<Envelope> phase5b_messages = CollectPhase5BMessages(&sessions);
  bool tampered = false;
  for (Envelope& envelope : phase5b_messages) {
    if (envelope.from == 1 && !envelope.payload.empty()) {
      envelope.payload.back() ^= 0x01;
      tampered = true;
      break;
    }
  }
  Expect(tampered, "Test setup failed to locate phase5B relation proof payload to tamper");

  for (const Envelope& envelope : phase5b_messages) {
    (void)DeliverSignEnvelope(envelope, signers, &sessions);
  }

  const size_t receiver_idx = FindPartyIndexOrThrow(signers, 2);
  Expect(sessions[receiver_idx]->status() == SessionStatus::kAborted,
         "Receiver must abort when phase5B V relation proof is tampered");
  Expect(sessions[receiver_idx]->phase() == SignPhase::kPhase5,
         "Phase5B proof failure should abort in phase5");
  Expect(sessions[receiver_idx]->phase5_stage() == SignPhase5Stage::kPhase5B,
         "Phase5B relation proof failure should abort in stage5B");
  for (const auto& session : sessions) {
    Expect(!session->HasResult(), "Phase5B relation proof failure must not expose signature result");
  }
}

}  // namespace

int main() {
  try {
    TestM4SignEndToEndProducesVerifiableSignature();
    TestM4Phase5DFailurePreventsPhase5EReveal();
    TestM5Phase2InstanceIdMismatchAborts();
    TestM7TamperedPhase2A1ProofAbortsResponder();
    TestM7TamperedPhase2A3ProofAbortsInitiator();
    TestM7TamperedPhase2A2ProofAbortsInitiator();
    TestM6TamperedPhase4GammaSchnorrAbortsReceiver();
    TestM6TamperedPhase5BASchnorrAbortsReceiver();
    TestM6TamperedPhase5BVRelationAbortsReceiver();
  } catch (const std::exception& ex) {
    std::cerr << ex.what() << '\n';
    return 1;
  }

  std::cout << "M4/M5/M6/M7 tests passed" << '\n';
  return 0;
}
