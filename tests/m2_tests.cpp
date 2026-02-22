#include <chrono>
#include <functional>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#include "tecdsa/net/in_memory_transport.hpp"
#include "tecdsa/protocol/keygen_session.hpp"
#include "tecdsa/protocol/session_router.hpp"
#include "tecdsa/protocol/sign_session.hpp"

namespace {

using tecdsa::Bytes;
using tecdsa::Envelope;
using tecdsa::InMemoryNetwork;
using tecdsa::KeygenPhase;
using tecdsa::KeygenSession;
using tecdsa::KeygenSessionConfig;
using tecdsa::SessionRouter;
using tecdsa::SessionStatus;
using tecdsa::SignPhase;
using tecdsa::PaillierPublicKey;
using tecdsa::SignPhase5Stage;
using tecdsa::SignSession;
using tecdsa::SignSessionConfig;
using tecdsa::Scalar;

std::unordered_map<tecdsa::PartyIndex, SignSessionConfig::AuxRsaParams> BuildAuxParamsFromPaillier(
    const std::vector<tecdsa::PartyIndex>& participants,
    const std::unordered_map<tecdsa::PartyIndex, PaillierPublicKey>& paillier_public) {
  std::unordered_map<tecdsa::PartyIndex, SignSessionConfig::AuxRsaParams> out;
  out.reserve(participants.size());

  for (tecdsa::PartyIndex party : participants) {
    const auto pub_it = paillier_public.find(party);
    if (pub_it == paillier_public.end()) {
      throw std::runtime_error("missing Paillier public key while building aux params");
    }
    out.emplace(party, tecdsa::DeriveAuxRsaParamsFromModulus(pub_it->second.n, party));
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

Envelope MakeEnvelope(Bytes session_id,
                      uint32_t type,
                      uint32_t from,
                      uint32_t to = tecdsa::kBroadcastPartyId,
                      Bytes payload = {}) {
  Envelope e;
  e.session_id = std::move(session_id);
  e.type = type;
  e.from = from;
  e.to = to;
  e.payload = std::move(payload);
  return e;
}

void TestInMemoryTransportSendBroadcast() {
  auto network = std::make_shared<InMemoryNetwork>();
  auto t1 = network->CreateEndpoint(1);
  auto t2 = network->CreateEndpoint(2);
  auto t3 = network->CreateEndpoint(3);

  std::vector<Envelope> recv2;
  std::vector<Envelope> recv3;
  t2->RegisterHandler([&](const Envelope& e) { recv2.push_back(e); });
  t3->RegisterHandler([&](const Envelope& e) { recv3.push_back(e); });

  const Bytes sid = {0xAA};
  t1->Send(2, MakeEnvelope(sid, 10, 1, 2, {1}));
  Expect(recv2.size() == 1, "Send should deliver exactly once to target");
  Expect(recv2[0].to == 2 && recv2[0].from == 1, "Send should preserve from/to binding");

  t1->Broadcast(MakeEnvelope(sid, 11, 1, tecdsa::kBroadcastPartyId, {2}));
  Expect(recv2.size() == 2, "Broadcast should reach peer 2");
  Expect(recv3.size() == 1, "Broadcast should reach peer 3");
  Expect(recv2[1].to == tecdsa::kBroadcastPartyId,
         "Broadcast envelope should be marked as broadcast");

  ExpectThrow([&]() { t1->Send(2, MakeEnvelope(sid, 12, 3, 2)); },
              "Transport rejects envelope.from mismatch");
}

void TestSessionRouterFiltering() {
  SessionRouter router(2);

  size_t handled = 0;
  const Bytes sid = {1, 2, 3};
  router.RegisterSession(sid, [&](const Envelope&) { ++handled; });

  Expect(router.Route(MakeEnvelope(sid, 100, 1, 2)),
         "Router should accept matching session and recipient");
  Expect(handled == 1, "Router should invoke handler");

  Expect(!router.Route(MakeEnvelope(Bytes{9, 9}, 100, 1, 2)),
         "Router should reject unknown session_id");
  Expect(!router.Route(MakeEnvelope(sid, 0, 1, 2)),
         "Router should reject invalid type=0");
  Expect(!router.Route(MakeEnvelope(sid, 100, 1, 3)),
         "Router should reject wrong recipient");
  Expect(!router.Route(MakeEnvelope(Bytes{}, 100, 1, 2)),
         "Router should reject empty session_id");

  Expect(router.rejected_count() == 4, "Router should track rejected envelopes");
}

void TestKeygenSessionSkeleton() {
  KeygenSessionConfig self_cfg;
  self_cfg.session_id = {1, 1, 1};
  self_cfg.self_id = 1;
  self_cfg.participants = {1, 2, 3};
  self_cfg.threshold = 1;
  self_cfg.timeout = std::chrono::seconds(5);

  KeygenSessionConfig peer2_cfg;
  peer2_cfg.session_id = {1, 1, 1};
  peer2_cfg.self_id = 2;
  peer2_cfg.participants = {1, 2, 3};
  peer2_cfg.threshold = 1;
  peer2_cfg.timeout = std::chrono::seconds(5);

  KeygenSessionConfig peer3_cfg;
  peer3_cfg.session_id = {1, 1, 1};
  peer3_cfg.self_id = 3;
  peer3_cfg.participants = {1, 2, 3};
  peer3_cfg.threshold = 1;
  peer3_cfg.timeout = std::chrono::seconds(5);

  KeygenSession session(std::move(self_cfg));
  KeygenSession peer2(std::move(peer2_cfg));
  KeygenSession peer3(std::move(peer3_cfg));
  Expect(session.phase() == KeygenPhase::kPhase1, "Keygen starts at phase1");
  (void)session.BuildPhase1CommitEnvelope();

  Expect(session.HandleEnvelope(peer2.BuildPhase1CommitEnvelope()),
         "Keygen should accept phase1 msg from peer2");
  Expect(session.received_peer_count_in_phase() == 1, "Peer count in phase should increase");

  Expect(session.HandleEnvelope(peer3.BuildPhase1CommitEnvelope()),
         "Keygen should accept phase1 msg from peer3");
  Expect(session.phase() == KeygenPhase::kPhase2, "Keygen advances to phase2 when all peers sent");

  const uint32_t wrong_type = KeygenSession::MessageTypeForPhase(KeygenPhase::kPhase3);
  Expect(!session.HandleEnvelope(MakeEnvelope({1, 1, 1}, wrong_type, 2)),
         "Wrong type should not be accepted in current phase");
  Expect(session.status() == SessionStatus::kAborted,
         "Unexpected phase message should abort keygen skeleton");
}

void TestSignSessionSkeletonAndTimeout() {
  const std::vector<tecdsa::PartyIndex> participants = {1, 2};

  std::unordered_map<tecdsa::PartyIndex, tecdsa::ECPoint> all_x_i;
  all_x_i.emplace(1, tecdsa::ECPoint::GeneratorMultiply(Scalar::FromUint64(3)));
  all_x_i.emplace(2, tecdsa::ECPoint::GeneratorMultiply(Scalar::FromUint64(5)));
  const tecdsa::ECPoint y = tecdsa::ECPoint::GeneratorMultiply(Scalar::FromUint64(1));

  auto paillier_1 = std::make_shared<tecdsa::PaillierProvider>(/*modulus_bits=*/2048);
  auto paillier_2 = std::make_shared<tecdsa::PaillierProvider>(/*modulus_bits=*/2048);
  std::unordered_map<tecdsa::PartyIndex, PaillierPublicKey> paillier_public;
  paillier_public.emplace(1, PaillierPublicKey{.n = paillier_1->modulus_n()});
  paillier_public.emplace(2, PaillierPublicKey{.n = paillier_2->modulus_n()});
  const auto aux_params = BuildAuxParamsFromPaillier(participants, paillier_public);
  std::unordered_map<tecdsa::PartyIndex, SignSessionConfig::SquareFreeProof> square_free_proofs;
  std::unordered_map<tecdsa::PartyIndex, SignSessionConfig::AuxRsaParamProof> aux_param_proofs;
  for (tecdsa::PartyIndex party : participants) {
    const auto pub_it = paillier_public.find(party);
    const auto aux_it = aux_params.find(party);
    if (pub_it == paillier_public.end() || aux_it == aux_params.end()) {
      throw std::runtime_error("failed to build strict proofs for sign skeleton");
    }
    square_free_proofs.emplace(party, tecdsa::BuildSquareFreeProof(pub_it->second.n));
    aux_param_proofs.emplace(party, tecdsa::BuildAuxRsaParamProof(aux_it->second));
  }

  auto build_cfg = [&](tecdsa::PartyIndex self_id,
                       uint64_t x_i_value,
                       uint64_t fixed_k,
                       uint64_t fixed_gamma,
                       const Bytes& session_id,
                       std::chrono::milliseconds timeout,
                       std::shared_ptr<tecdsa::PaillierProvider> local_paillier) {
    SignSessionConfig cfg;
    cfg.session_id = session_id;
    cfg.self_id = self_id;
    cfg.participants = participants;
    cfg.timeout = timeout;
    cfg.x_i = Scalar::FromUint64(x_i_value);
    cfg.y = y;
    cfg.all_X_i = all_x_i;
    cfg.all_paillier_public = paillier_public;
    cfg.all_aux_rsa_params = aux_params;
    cfg.all_square_free_proofs = square_free_proofs;
    cfg.all_aux_param_proofs = aux_param_proofs;
    cfg.local_paillier = std::move(local_paillier);
    cfg.msg32 = Bytes{
        0x4d, 0x32, 0x2d, 0x73, 0x69, 0x67, 0x6e, 0x2d,
        0x73, 0x6b, 0x65, 0x6c, 0x65, 0x74, 0x6f, 0x6e,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    };
    cfg.strict_mode = true;
    cfg.fixed_k_i = Scalar::FromUint64(fixed_k);
    cfg.fixed_gamma_i = Scalar::FromUint64(fixed_gamma);
    return cfg;
  };

  SignSession session1(build_cfg(/*self_id=*/1,
                                 /*x_i_value=*/3,
                                 /*fixed_k=*/11,
                                 /*fixed_gamma=*/22,
                                 Bytes{2, 2, 2},
                                 std::chrono::seconds(5),
                                 paillier_1));
  SignSession session2(build_cfg(/*self_id=*/2,
                                 /*x_i_value=*/5,
                                 /*fixed_k=*/12,
                                 /*fixed_gamma=*/24,
                                 Bytes{2, 2, 2},
                                 std::chrono::seconds(5),
                                 paillier_2));

  auto deliver_between_two = [&](const Envelope& envelope) {
    if (envelope.from == 1) {
      return session2.HandleEnvelope(envelope);
    }
    if (envelope.from == 2) {
      return session1.HandleEnvelope(envelope);
    }
    return false;
  };

  auto deliver_stage = [&](const Envelope& from1, const Envelope& from2, const std::string& stage_name) {
    Expect(deliver_between_two(from1), stage_name + ": peer2 should accept party1 message");
    Expect(deliver_between_two(from2), stage_name + ": peer1 should accept party2 message");
  };

  deliver_stage(session1.BuildPhase1CommitEnvelope(), session2.BuildPhase1CommitEnvelope(), "phase1");
  Expect(session1.phase() == SignPhase::kPhase2 && session2.phase() == SignPhase::kPhase2,
         "Sign sessions should enter phase2");

  auto drive_phase2 = [&]() {
    for (size_t round = 0; round < 12; ++round) {
      std::vector<Envelope> outbox;
      if (session1.phase() == SignPhase::kPhase2) {
        std::vector<Envelope> batch = session1.BuildPhase2MtaEnvelopes();
        outbox.insert(outbox.end(), batch.begin(), batch.end());
      }
      if (session2.phase() == SignPhase::kPhase2) {
        std::vector<Envelope> batch = session2.BuildPhase2MtaEnvelopes();
        outbox.insert(outbox.end(), batch.begin(), batch.end());
      }

      for (const Envelope& envelope : outbox) {
        Expect(deliver_between_two(envelope), "phase2: peer should accept MtA/MtAwc envelope");
      }

      if (session1.phase() == SignPhase::kPhase3 && session2.phase() == SignPhase::kPhase3) {
        return;
      }
      if (outbox.empty()) {
        throw std::runtime_error("phase2 stalled before all MtA/MtAwc messages completed");
      }
    }
    throw std::runtime_error("phase2 exceeded maximum rounds in skeleton test");
  };
  drive_phase2();
  Expect(session1.phase() == SignPhase::kPhase3 && session2.phase() == SignPhase::kPhase3,
         "Sign sessions should enter phase3");

  deliver_stage(session1.BuildPhase3DeltaEnvelope(), session2.BuildPhase3DeltaEnvelope(), "phase3");
  Expect(session1.phase() == SignPhase::kPhase4 && session2.phase() == SignPhase::kPhase4,
         "Sign sessions should enter phase4");

  deliver_stage(session1.BuildPhase4OpenGammaEnvelope(), session2.BuildPhase4OpenGammaEnvelope(), "phase4");
  Expect(session1.phase() == SignPhase::kPhase5 && session2.phase() == SignPhase::kPhase5,
         "Sign sessions should enter phase5");
  Expect(session1.phase5_stage() == SignPhase5Stage::kPhase5A &&
             session2.phase5_stage() == SignPhase5Stage::kPhase5A,
         "Sign sessions should start at phase5A");

  deliver_stage(session1.BuildPhase5ACommitEnvelope(), session2.BuildPhase5ACommitEnvelope(), "phase5A");
  Expect(session1.phase5_stage() == SignPhase5Stage::kPhase5B &&
             session2.phase5_stage() == SignPhase5Stage::kPhase5B,
         "Sign sessions should advance to phase5B");

  deliver_stage(session1.BuildPhase5BOpenEnvelope(), session2.BuildPhase5BOpenEnvelope(), "phase5B");
  Expect(session1.phase5_stage() == SignPhase5Stage::kPhase5C &&
             session2.phase5_stage() == SignPhase5Stage::kPhase5C,
         "Sign sessions should advance to phase5C");

  deliver_stage(session1.BuildPhase5CCommitEnvelope(), session2.BuildPhase5CCommitEnvelope(), "phase5C");
  Expect(session1.phase5_stage() == SignPhase5Stage::kPhase5D &&
             session2.phase5_stage() == SignPhase5Stage::kPhase5D,
         "Sign sessions should advance to phase5D");

  deliver_stage(session1.BuildPhase5DOpenEnvelope(), session2.BuildPhase5DOpenEnvelope(), "phase5D");
  Expect(session1.phase5_stage() == SignPhase5Stage::kPhase5E &&
             session2.phase5_stage() == SignPhase5Stage::kPhase5E,
         "Sign sessions should advance to phase5E");

  deliver_stage(session1.BuildPhase5ERevealEnvelope(), session2.BuildPhase5ERevealEnvelope(), "phase5E");
  if (!(session1.status() == SessionStatus::kCompleted &&
        session2.status() == SessionStatus::kCompleted)) {
    throw std::runtime_error(
        "Sign sessions should complete after phase5E (status1=" +
        std::to_string(static_cast<int>(session1.status())) +
        ", status2=" + std::to_string(static_cast<int>(session2.status())) +
        ", abort1='" + session1.abort_reason() +
        "', abort2='" + session2.abort_reason() + "')");
  }
  Expect(session1.HasResult() && session2.HasResult(),
         "Completed sessions should expose sign results");
  Expect(session1.result().r == session2.result().r && session1.result().s == session2.result().s,
         "Completed sign sessions should agree on signature");

  SignSessionConfig timeout_cfg;
  timeout_cfg = build_cfg(/*self_id=*/1,
                          /*x_i_value=*/3,
                          /*fixed_k=*/11,
                          /*fixed_gamma=*/22,
                          Bytes{3, 3, 3},
                          std::chrono::milliseconds(1),
                          paillier_1);

  SignSession timeout_session(std::move(timeout_cfg));
  const auto far_future = std::chrono::steady_clock::now() + std::chrono::seconds(1);
  Expect(timeout_session.PollTimeout(far_future), "PollTimeout should trigger timeout status");
  Expect(timeout_session.status() == SessionStatus::kTimedOut,
         "Session status should be timed out after deadline");

  SignSessionConfig strict_missing_proof_cfg = build_cfg(/*self_id=*/1,
                                                         /*x_i_value=*/3,
                                                         /*fixed_k=*/11,
                                                         /*fixed_gamma=*/22,
                                                         Bytes{4, 4, 4},
                                                         std::chrono::seconds(5),
                                                         paillier_1);
  strict_missing_proof_cfg.all_square_free_proofs.clear();
  strict_missing_proof_cfg.all_aux_param_proofs.clear();
  ExpectThrow([&]() { (void)SignSession(std::move(strict_missing_proof_cfg)); },
              "strict mode sign session must reject missing square-free/aux proofs");

  SignSessionConfig dev_missing_proof_cfg = build_cfg(/*self_id=*/1,
                                                      /*x_i_value=*/3,
                                                      /*fixed_k=*/11,
                                                      /*fixed_gamma=*/22,
                                                      Bytes{5, 5, 5},
                                                      std::chrono::seconds(5),
                                                      paillier_1);
  dev_missing_proof_cfg.strict_mode = false;
  dev_missing_proof_cfg.all_square_free_proofs.clear();
  dev_missing_proof_cfg.all_aux_param_proofs.clear();
  SignSession dev_session(std::move(dev_missing_proof_cfg));
  Expect(dev_session.phase() == SignPhase::kPhase1,
         "dev mode sign session should allow missing strict proofs and stay runnable");

  SignSessionConfig small_n_cfg = build_cfg(/*self_id=*/1,
                                            /*x_i_value=*/3,
                                            /*fixed_k=*/11,
                                            /*fixed_gamma=*/22,
                                            Bytes{6, 6, 6},
                                            std::chrono::seconds(5),
                                            paillier_1);
  small_n_cfg.all_paillier_public[2].n = 17;
  ExpectThrow([&]() { (void)SignSession(std::move(small_n_cfg)); },
              "sign session must reject participant Paillier modulus not satisfying N > q^8");
}

void TestSessionIdAndRecipientMismatchRejected() {
  KeygenSessionConfig cfg;
  cfg.session_id = {8, 8, 8};
  cfg.self_id = 2;
  cfg.participants = {1, 2, 3};
  cfg.timeout = std::chrono::seconds(5);

  KeygenSession session(std::move(cfg));
  const uint32_t type = KeygenSession::MessageTypeForPhase(KeygenPhase::kPhase1);

  Expect(!session.HandleEnvelope(MakeEnvelope({9, 9, 9}, type, 1, 2)),
         "Session should reject mismatched session_id");
  Expect(session.status() == SessionStatus::kRunning,
         "Session mismatch should not change running state");

  Expect(!session.HandleEnvelope(MakeEnvelope({8, 8, 8}, type, 1, 4)),
         "Session should reject wrong recipient");
  Expect(session.status() == SessionStatus::kRunning,
         "Recipient mismatch should not abort session");
}

}  // namespace

int main() {
  try {
    TestInMemoryTransportSendBroadcast();
    TestSessionRouterFiltering();
    TestKeygenSessionSkeleton();
    TestSignSessionSkeletonAndTimeout();
    TestSessionIdAndRecipientMismatchRejected();
  } catch (const std::exception& ex) {
    std::cerr << ex.what() << '\n';
    return 1;
  }

  std::cout << "M2 tests passed" << '\n';
  return 0;
}
