#include <chrono>
#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "tecdsa/crypto/encoding.hpp"
#include "tecdsa/net/envelope.hpp"
#include "tecdsa/protocol/keygen_session.hpp"

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

void Expect(bool condition, const std::string& message) {
  if (!condition) {
    throw std::runtime_error("Test failed: " + message);
  }
}

std::vector<PartyIndex> BuildParticipants(uint32_t n) {
  std::vector<PartyIndex> out;
  out.reserve(n);
  for (PartyIndex id = 1; id <= n; ++id) {
    out.push_back(id);
  }
  return out;
}

std::vector<std::unique_ptr<KeygenSession>> BuildSessions(uint32_t n,
                                                          uint32_t t,
                                                          const Bytes& session_id) {
  std::vector<std::unique_ptr<KeygenSession>> sessions;
  sessions.reserve(n);
  const std::vector<PartyIndex> participants = BuildParticipants(n);

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

bool DeliverEnvelope(const Envelope& envelope,
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

std::vector<Envelope> BuildAndCollectPhase1(
    std::vector<std::unique_ptr<KeygenSession>>* sessions) {
  std::vector<Envelope> out;
  out.reserve(sessions->size());
  for (auto& session : *sessions) {
    out.push_back(session->BuildPhase1CommitEnvelope());
  }
  return out;
}

std::vector<Envelope> BuildAndCollectPhase2(
    std::vector<std::unique_ptr<KeygenSession>>* sessions) {
  std::vector<Envelope> out;
  for (auto& session : *sessions) {
    const std::vector<Envelope> phase2 = session->BuildPhase2OpenAndShareEnvelopes();
    out.insert(out.end(), phase2.begin(), phase2.end());
  }
  return out;
}

std::vector<Envelope> BuildAndCollectPhase3(
    std::vector<std::unique_ptr<KeygenSession>>* sessions) {
  std::vector<Envelope> out;
  out.reserve(sessions->size());
  for (auto& session : *sessions) {
    out.push_back(session->BuildPhase3XiProofEnvelope());
  }
  return out;
}

void EnsureAllSessionsInPhase(const std::vector<std::unique_ptr<KeygenSession>>& sessions,
                              KeygenPhase phase) {
  for (size_t idx = 0; idx < sessions.size(); ++idx) {
    const PartyIndex id = static_cast<PartyIndex>(idx + 1);
    Expect(sessions[idx]->status() == SessionStatus::kRunning,
           "Session " + std::to_string(id) + " must be running");
    Expect(sessions[idx]->phase() == phase,
           "Session " + std::to_string(id) + " has unexpected phase");
  }
}

void EnsureAllSessionsCompleted(const std::vector<std::unique_ptr<KeygenSession>>& sessions) {
  for (size_t idx = 0; idx < sessions.size(); ++idx) {
    const PartyIndex id = static_cast<PartyIndex>(idx + 1);
    Expect(sessions[idx]->status() == SessionStatus::kCompleted,
           "Session " + std::to_string(id) + " must complete");
    Expect(sessions[idx]->phase() == KeygenPhase::kCompleted,
           "Session " + std::to_string(id) + " must be in completed phase");
    Expect(sessions[idx]->HasResult(),
           "Session " + std::to_string(id) + " must expose a completed keygen result");
  }
}

void DeliverEnvelopesOrThrow(const std::vector<Envelope>& messages,
                             std::vector<std::unique_ptr<KeygenSession>>* sessions) {
  for (const Envelope& envelope : messages) {
    if (!DeliverEnvelope(envelope, sessions)) {
      throw std::runtime_error("Envelope delivery failed unexpectedly");
    }
  }
}

void AssertKeygenOutputsConsistent(const std::vector<std::unique_ptr<KeygenSession>>& sessions,
                                   uint32_t n) {
  const KeygenResult& baseline = sessions.front()->result();
  Expect(baseline.all_X_i.size() == n, "Baseline keygen result must contain all X_i values");
  Expect(baseline.all_paillier_public.size() == n,
         "Baseline keygen result must contain all Paillier public keys");
  Expect(baseline.local_paillier != nullptr,
         "Baseline keygen result must expose local Paillier provider");

  mpz_class min_paillier_n;
  mpz_pow_ui(min_paillier_n.get_mpz_t(), Scalar::ModulusQ().get_mpz_t(), 8);

  for (size_t idx = 0; idx < sessions.size(); ++idx) {
    const PartyIndex self_id = static_cast<PartyIndex>(idx + 1);
    const KeygenResult& current = sessions[idx]->result();

    Expect(current.y == baseline.y,
           "All sessions must derive the same group public key y");
    Expect(current.all_X_i.size() == baseline.all_X_i.size(),
           "All sessions must agree on the number of public shares");
    Expect(current.all_paillier_public.size() == baseline.all_paillier_public.size(),
           "All sessions must agree on the number of Paillier public keys");
    Expect(current.local_paillier != nullptr,
           "Each session result must expose local Paillier provider");

    for (const auto& [party_id, expected_x_i] : baseline.all_X_i) {
      const auto it = current.all_X_i.find(party_id);
      Expect(it != current.all_X_i.end(),
             "Session result is missing X_i for party " + std::to_string(party_id));
      Expect(it->second == expected_x_i,
             "Session result has mismatched X_i for party " + std::to_string(party_id));
    }

    const auto self_it = current.all_X_i.find(self_id);
    Expect(self_it != current.all_X_i.end(),
           "Session result must contain its own X_i entry");
    Expect(self_it->second == current.X_i,
           "Session result must expose X_i equal to all_X_i[self]");

    for (const auto& [party_id, expected_pub] : baseline.all_paillier_public) {
      const auto it = current.all_paillier_public.find(party_id);
      Expect(it != current.all_paillier_public.end(),
             "Session result is missing Paillier public key for party " + std::to_string(party_id));
      Expect(it->second.n == expected_pub.n,
             "Session result has mismatched Paillier modulus for party " + std::to_string(party_id));
      Expect(it->second.n > min_paillier_n,
             "Session result has Paillier modulus that does not satisfy N > q^8");
    }

    const auto self_paillier_it = current.all_paillier_public.find(self_id);
    Expect(self_paillier_it != current.all_paillier_public.end(),
           "Session result must contain its own Paillier public key entry");
    Expect(self_paillier_it->second.n == current.local_paillier->modulus_n(),
           "Session local Paillier private key must match broadcast public key");
  }
}

void RunHonestKeygenAndAssertConsistency(uint32_t n, uint32_t t, const Bytes& session_id) {
  auto sessions = BuildSessions(n, t, session_id);

  const std::vector<Envelope> phase1 = BuildAndCollectPhase1(&sessions);
  DeliverEnvelopesOrThrow(phase1, &sessions);
  EnsureAllSessionsInPhase(sessions, KeygenPhase::kPhase2);

  const std::vector<Envelope> phase2 = BuildAndCollectPhase2(&sessions);
  DeliverEnvelopesOrThrow(phase2, &sessions);
  EnsureAllSessionsInPhase(sessions, KeygenPhase::kPhase3);

  const std::vector<Envelope> phase3 = BuildAndCollectPhase3(&sessions);
  DeliverEnvelopesOrThrow(phase3, &sessions);
  EnsureAllSessionsCompleted(sessions);
  AssertKeygenOutputsConsistent(sessions, n);
}

void TestKeygenConsistencyN3T1() {
  RunHonestKeygenAndAssertConsistency(/*n=*/3, /*t=*/1, Bytes{0xA1, 0x03, 0x01});
}

void TestKeygenConsistencyN5T2() {
  RunHonestKeygenAndAssertConsistency(/*n=*/5, /*t=*/2, Bytes{0xA1, 0x05, 0x02});
}

void TestTamperedPhase2ShareAbortsReceiver() {
  auto sessions = BuildSessions(/*n=*/3, /*t=*/1, Bytes{0xB1, 0x03, 0x01});

  const std::vector<Envelope> phase1 = BuildAndCollectPhase1(&sessions);
  DeliverEnvelopesOrThrow(phase1, &sessions);
  EnsureAllSessionsInPhase(sessions, KeygenPhase::kPhase2);

  std::vector<Envelope> phase2 = BuildAndCollectPhase2(&sessions);
  bool tampered = false;
  for (Envelope& envelope : phase2) {
    if (envelope.type == KeygenSession::Phase2ShareMessageType() && envelope.from == 1 &&
        envelope.to == 2) {
      envelope.payload.back() ^= 0x01;
      tampered = true;
      break;
    }
  }
  Expect(tampered, "Test setup failed to locate a phase2 share to tamper");

  for (const Envelope& envelope : phase2) {
    (void)DeliverEnvelope(envelope, &sessions);
  }

  Expect(sessions[1]->status() == SessionStatus::kAborted,
         "Receiver must abort when a dealer share is tampered");
}

void TestTamperedPhase1PaillierModulusAbortsReceiver() {
  auto sessions = BuildSessions(/*n=*/3, /*t=*/1, Bytes{0xB2, 0x03, 0x01});

  std::vector<Envelope> phase1 = BuildAndCollectPhase1(&sessions);
  bool tampered = false;
  for (Envelope& envelope : phase1) {
    if (envelope.from != 1) {
      continue;
    }

    Bytes malformed_payload;
    malformed_payload.insert(malformed_payload.end(), envelope.payload.begin(), envelope.payload.begin() + 32);

    const Bytes tiny_n = tecdsa::EncodeMpz(mpz_class(17));
    auto append_u32 = [](uint32_t value, Bytes* out) {
      out->push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
      out->push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
      out->push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
      out->push_back(static_cast<uint8_t>(value & 0xFF));
    };
    append_u32(static_cast<uint32_t>(tiny_n.size()), &malformed_payload);
    malformed_payload.insert(malformed_payload.end(), tiny_n.begin(), tiny_n.end());

    envelope.payload = std::move(malformed_payload);
    tampered = true;
    break;
  }
  Expect(tampered, "Test setup failed to locate a phase1 payload to tamper");

  for (const Envelope& envelope : phase1) {
    (void)DeliverEnvelope(envelope, &sessions);
  }

  Expect(sessions[1]->status() == SessionStatus::kAborted,
         "Peer 2 must abort when phase1 Paillier modulus is too small");
  Expect(sessions[2]->status() == SessionStatus::kAborted,
         "Peer 3 must abort when phase1 Paillier modulus is too small");
}

void TestTamperedPhase3SchnorrAbortsPeers() {
  auto sessions = BuildSessions(/*n=*/3, /*t=*/1, Bytes{0xC1, 0x03, 0x01});

  const std::vector<Envelope> phase1 = BuildAndCollectPhase1(&sessions);
  DeliverEnvelopesOrThrow(phase1, &sessions);
  const std::vector<Envelope> phase2 = BuildAndCollectPhase2(&sessions);
  DeliverEnvelopesOrThrow(phase2, &sessions);
  EnsureAllSessionsInPhase(sessions, KeygenPhase::kPhase3);

  std::vector<Envelope> phase3 = BuildAndCollectPhase3(&sessions);
  bool tampered = false;
  for (Envelope& envelope : phase3) {
    if (envelope.from == 1 &&
        envelope.type == KeygenSession::MessageTypeForPhase(KeygenPhase::kPhase3)) {
      envelope.payload.back() ^= 0x01;
      tampered = true;
      break;
    }
  }
  Expect(tampered, "Test setup failed to locate a phase3 proof to tamper");

  for (const Envelope& envelope : phase3) {
    (void)DeliverEnvelope(envelope, &sessions);
  }

  Expect(sessions[1]->status() == SessionStatus::kAborted,
         "Peer 2 must abort when Schnorr proof is tampered");
  Expect(sessions[2]->status() == SessionStatus::kAborted,
         "Peer 3 must abort when Schnorr proof is tampered");
}

}  // namespace

int main() {
  try {
    TestKeygenConsistencyN3T1();
    TestKeygenConsistencyN5T2();
    TestTamperedPhase1PaillierModulusAbortsReceiver();
    TestTamperedPhase2ShareAbortsReceiver();
    TestTamperedPhase3SchnorrAbortsPeers();
  } catch (const std::exception& ex) {
    std::cerr << ex.what() << '\n';
    return 1;
  }

  std::cout << "M3 tests passed" << '\n';
  return 0;
}
