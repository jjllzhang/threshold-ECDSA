#include <chrono>
#include <functional>
#include <iostream>
#include <stdexcept>
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
  KeygenSessionConfig cfg;
  cfg.session_id = {1, 1, 1};
  cfg.self_id = 1;
  cfg.participants = {1, 2, 3};
  cfg.timeout = std::chrono::seconds(5);

  KeygenSession session(std::move(cfg));
  Expect(session.phase() == KeygenPhase::kPhase1, "Keygen starts at phase1");

  const uint32_t phase1_type = KeygenSession::MessageTypeForPhase(KeygenPhase::kPhase1);
  Expect(session.HandleEnvelope(MakeEnvelope({1, 1, 1}, phase1_type, 2)),
         "Keygen should accept phase1 msg from peer2");
  Expect(session.received_peer_count_in_phase() == 1, "Peer count in phase should increase");

  Expect(session.HandleEnvelope(MakeEnvelope({1, 1, 1}, phase1_type, 3)),
         "Keygen should accept phase1 msg from peer3");
  Expect(session.phase() == KeygenPhase::kPhase2, "Keygen advances to phase2 when all peers sent");

  const uint32_t wrong_type = KeygenSession::MessageTypeForPhase(KeygenPhase::kPhase3);
  Expect(!session.HandleEnvelope(MakeEnvelope({1, 1, 1}, wrong_type, 2)),
         "Wrong type should not be accepted in current phase");
  Expect(session.status() == SessionStatus::kAborted,
         "Unexpected phase message should abort keygen skeleton");
}

void TestSignSessionSkeletonAndTimeout() {
  SignSessionConfig cfg;
  cfg.session_id = {2, 2, 2};
  cfg.self_id = 1;
  cfg.participants = {1, 2, 3};
  cfg.timeout = std::chrono::seconds(5);

  SignSession session(std::move(cfg));

  for (SignPhase phase :
       {SignPhase::kPhase1, SignPhase::kPhase2, SignPhase::kPhase3, SignPhase::kPhase4, SignPhase::kPhase5}) {
    const uint32_t type = SignSession::MessageTypeForPhase(phase);
    Expect(session.phase() == phase, "Sign phase should match expected progression");
    Expect(session.HandleEnvelope(MakeEnvelope({2, 2, 2}, type, 2)),
           "Sign should accept message from peer2");
    Expect(session.HandleEnvelope(MakeEnvelope({2, 2, 2}, type, 3)),
           "Sign should accept message from peer3");
  }

  Expect(session.status() == SessionStatus::kCompleted,
         "Sign skeleton should complete after phase5");

  SignSessionConfig timeout_cfg;
  timeout_cfg.session_id = {3, 3, 3};
  timeout_cfg.self_id = 1;
  timeout_cfg.participants = {1, 2};
  timeout_cfg.timeout = std::chrono::milliseconds(1);

  SignSession timeout_session(std::move(timeout_cfg));
  const auto far_future = std::chrono::steady_clock::now() + std::chrono::seconds(1);
  Expect(timeout_session.PollTimeout(far_future), "PollTimeout should trigger timeout status");
  Expect(timeout_session.status() == SessionStatus::kTimedOut,
         "Session status should be timed out after deadline");
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
