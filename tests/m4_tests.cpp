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
using tecdsa::SignPhase2StubShare;
using tecdsa::SignPhase5Stage;
using tecdsa::SignSession;
using tecdsa::SignSessionConfig;

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

mpz_class NormalizeModQ(const mpz_class& value) {
  mpz_class normalized = value % Scalar::ModulusQ();
  if (normalized < 0) {
    normalized += Scalar::ModulusQ();
  }
  return normalized;
}

std::unordered_map<PartyIndex, Scalar> ComputeLagrangeAtZero(const std::vector<PartyIndex>& participants) {
  std::unordered_map<PartyIndex, Scalar> out;
  out.reserve(participants.size());

  for (PartyIndex i : participants) {
    mpz_class numerator = 1;
    mpz_class denominator = 1;

    for (PartyIndex j : participants) {
      if (j == i) {
        continue;
      }

      numerator *= NormalizeModQ(-mpz_class(j));
      numerator %= Scalar::ModulusQ();

      const mpz_class diff = NormalizeModQ(mpz_class(i) - mpz_class(j));
      if (diff == 0) {
        throw std::runtime_error("lagrange denominator is zero");
      }
      denominator *= diff;
      denominator %= Scalar::ModulusQ();
    }

    mpz_class denominator_inv;
    if (mpz_invert(denominator_inv.get_mpz_t(),
                   denominator.get_mpz_t(),
                   Scalar::ModulusQ().get_mpz_t()) == 0) {
      throw std::runtime_error("failed to invert lagrange denominator");
    }

    out.emplace(i, Scalar(numerator * denominator_inv));
  }

  return out;
}

Scalar ComputeSigningSecretXForSubset(const std::vector<PartyIndex>& signers,
                                      const std::unordered_map<PartyIndex, KeygenResult>& keygen_results) {
  const std::unordered_map<PartyIndex, Scalar> lagrange = ComputeLagrangeAtZero(signers);

  Scalar x;
  for (PartyIndex party : signers) {
    const auto lagrange_it = lagrange.find(party);
    const auto keygen_it = keygen_results.find(party);
    if (lagrange_it == lagrange.end() || keygen_it == keygen_results.end()) {
      throw std::runtime_error("missing input for signing secret reconstruction");
    }
    x = x + (lagrange_it->second * keygen_it->second.x_i);
  }
  return x;
}

struct SignFixture {
  std::vector<PartyIndex> signers;
  Bytes msg32;
  std::unordered_map<PartyIndex, Scalar> fixed_k;
  std::unordered_map<PartyIndex, Scalar> fixed_gamma;
  std::unordered_map<PartyIndex, SignPhase2StubShare> stub_shares;
};

SignFixture BuildSignFixture(const std::vector<PartyIndex>& signers,
                             const std::unordered_map<PartyIndex, KeygenResult>& keygen_results,
                             bool break_phase5d_check) {
  SignFixture fixture;
  fixture.signers = signers;
  fixture.msg32 = Bytes{
      0x4d, 0x34, 0x2d, 0x73, 0x69, 0x67, 0x6e, 0x2d,
      0x74, 0x65, 0x73, 0x74, 0x2d, 0x30, 0x30, 0x31,
      0xaa, 0xbb, 0xcc, 0xdd, 0x10, 0x20, 0x30, 0x40,
      0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
  };

  const Scalar x = ComputeSigningSecretXForSubset(signers, keygen_results);

  Scalar gamma_sum;
  for (PartyIndex party : signers) {
    const Scalar gamma_i = Scalar::FromUint64(20 + 2 * party);
    fixture.fixed_gamma.emplace(party, gamma_i);
    gamma_sum = gamma_sum + gamma_i;
  }
  Expect(gamma_sum.value() != 0, "gamma sum must be non-zero for phase3 inversion");

  PartyIndex first_signer = 0;
  if (!signers.empty()) {
    first_signer = signers.front();
  }

  for (PartyIndex party : signers) {
    const Scalar k_i = Scalar::FromUint64(10 + party);
    fixture.fixed_k.emplace(party, k_i);

    SignPhase2StubShare stub;
    stub.delta_i = k_i * gamma_sum;
    stub.sigma_i = k_i * x;

    if (break_phase5d_check && party == first_signer) {
      stub.sigma_i = stub.sigma_i + Scalar::FromUint64(1);
    }

    fixture.stub_shares.emplace(party, stub);
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
    cfg.msg32 = fixture.msg32;
    cfg.phase2_stub_shares = fixture.stub_shares;
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
  out.reserve(sessions->size());
  for (auto& session : *sessions) {
    out.push_back(session->BuildPhase2StubEnvelope());
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

void RunToPhase5D(std::vector<std::unique_ptr<SignSession>>* sessions,
                  const std::vector<PartyIndex>& signers) {
  DeliverSignEnvelopesOrThrow(CollectPhase1Messages(sessions), signers, sessions);
  EnsureAllSessionsInPhase(*sessions, SignPhase::kPhase2);

  DeliverSignEnvelopesOrThrow(CollectPhase2Messages(sessions), signers, sessions);
  EnsureAllSessionsInPhase(*sessions, SignPhase::kPhase3);

  DeliverSignEnvelopesOrThrow(CollectPhase3Messages(sessions), signers, sessions);
  EnsureAllSessionsInPhase(*sessions, SignPhase::kPhase4);

  DeliverSignEnvelopesOrThrow(CollectPhase4Messages(sessions), signers, sessions);
  EnsureAllSessionsInPhase(*sessions, SignPhase::kPhase5, SignPhase5Stage::kPhase5A);

  DeliverSignEnvelopesOrThrow(CollectPhase5AMessages(sessions), signers, sessions);
  EnsureAllSessionsInPhase(*sessions, SignPhase::kPhase5, SignPhase5Stage::kPhase5B);

  DeliverSignEnvelopesOrThrow(CollectPhase5BMessages(sessions), signers, sessions);
  EnsureAllSessionsInPhase(*sessions, SignPhase::kPhase5, SignPhase5Stage::kPhase5C);

  DeliverSignEnvelopesOrThrow(CollectPhase5CMessages(sessions), signers, sessions);
  EnsureAllSessionsInPhase(*sessions, SignPhase::kPhase5, SignPhase5Stage::kPhase5D);
}

void TestM4SignEndToEndProducesVerifiableSignature() {
  const auto keygen_results = RunKeygenAndCollectResults(/*n=*/3, /*t=*/1, Bytes{0xD1, 0x03, 0x01});

  const std::vector<PartyIndex> signers = {1, 2};
  const SignFixture fixture = BuildSignFixture(signers, keygen_results, /*break_phase5d_check=*/false);
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
  const SignFixture bad_fixture = BuildSignFixture(signers, keygen_results, /*break_phase5d_check=*/true);
  auto sessions = BuildSignSessions(bad_fixture, keygen_results, Bytes{0xE2, 0x02, 0x01});

  RunToPhase5D(&sessions, signers);

  const std::vector<Envelope> phase5d = CollectPhase5DMessages(&sessions);
  for (const Envelope& envelope : phase5d) {
    (void)DeliverSignEnvelope(envelope, signers, &sessions);
  }

  bool any_aborted = false;
  for (const auto& session : sessions) {
    if (session->status() == SessionStatus::kAborted) {
      any_aborted = true;
    }
  }
  Expect(any_aborted, "At least one party must abort at phase5D when sigma stub is wrong");

  for (auto& session : sessions) {
    Expect(session->status() == SessionStatus::kAborted,
           "Session must abort on phase5D consistency failure");
    Expect(session->phase() == SignPhase::kPhase5,
           "Session should remain in phase5 after abort");
    Expect(session->phase5_stage() == SignPhase5Stage::kPhase5D,
           "Session must not advance to phase5E after phase5D failure");
    Expect(!session->HasResult(), "Aborted session must not expose final signature");
    ExpectThrow([&]() { (void)session->BuildPhase5ERevealEnvelope(); },
                "Aborted session cannot build phase5E reveal envelope");
  }
}

}  // namespace

int main() {
  try {
    TestM4SignEndToEndProducesVerifiableSignature();
    TestM4Phase5DFailurePreventsPhase5EReveal();
  } catch (const std::exception& ex) {
    std::cerr << ex.what() << '\n';
    return 1;
  }

  std::cout << "M4 tests passed" << '\n';
  return 0;
}
