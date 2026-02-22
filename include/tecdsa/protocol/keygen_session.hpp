#pragma once

#include <unordered_set>
#include <vector>

#include "tecdsa/net/envelope.hpp"
#include "tecdsa/protocol/session.hpp"

namespace tecdsa {

enum class KeygenPhase : uint32_t {
  kPhase1 = 1,
  kPhase2 = 2,
  kPhase3 = 3,
  kCompleted = 4,
};

enum class KeygenMessageType : uint32_t {
  kPhase1 = 1001,
  kPhase2 = 1002,
  kPhase3 = 1003,
  kAbort = 1099,
};

struct KeygenSessionConfig {
  Bytes session_id;
  PartyIndex self_id = 0;
  std::vector<PartyIndex> participants;
  std::chrono::milliseconds timeout = std::chrono::seconds(30);
};

class KeygenSession : public Session {
 public:
  explicit KeygenSession(KeygenSessionConfig cfg);

  KeygenPhase phase() const;
  size_t received_peer_count_in_phase() const;

  bool HandleEnvelope(const Envelope& envelope);
  Envelope MakePhaseBroadcastEnvelope(const Bytes& payload) const;

  static uint32_t MessageTypeForPhase(KeygenPhase phase);

 private:
  void AdvanceIfPhaseDone();

  std::vector<PartyIndex> participants_;
  std::unordered_set<PartyIndex> peers_;
  std::unordered_set<PartyIndex> seen_in_phase_;
  KeygenPhase phase_ = KeygenPhase::kPhase1;
};

}  // namespace tecdsa
