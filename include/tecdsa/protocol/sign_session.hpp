#pragma once

#include <unordered_set>
#include <vector>

#include "tecdsa/net/envelope.hpp"
#include "tecdsa/protocol/session.hpp"

namespace tecdsa {

enum class SignPhase : uint32_t {
  kPhase1 = 1,
  kPhase2 = 2,
  kPhase3 = 3,
  kPhase4 = 4,
  kPhase5 = 5,
  kCompleted = 6,
};

enum class SignMessageType : uint32_t {
  kPhase1 = 2001,
  kPhase2 = 2002,
  kPhase3 = 2003,
  kPhase4 = 2004,
  kPhase5 = 2005,
  kAbort = 2099,
};

struct SignSessionConfig {
  Bytes session_id;
  PartyIndex self_id = 0;
  std::vector<PartyIndex> participants;
  std::chrono::milliseconds timeout = std::chrono::seconds(30);
};

class SignSession : public Session {
 public:
  explicit SignSession(SignSessionConfig cfg);

  SignPhase phase() const;
  size_t received_peer_count_in_phase() const;

  bool HandleEnvelope(const Envelope& envelope);
  Envelope MakePhaseBroadcastEnvelope(const Bytes& payload) const;

  static uint32_t MessageTypeForPhase(SignPhase phase);

 private:
  void AdvanceIfPhaseDone();

  std::vector<PartyIndex> participants_;
  std::unordered_set<PartyIndex> peers_;
  std::unordered_set<PartyIndex> seen_in_phase_;
  SignPhase phase_ = SignPhase::kPhase1;
};

}  // namespace tecdsa
