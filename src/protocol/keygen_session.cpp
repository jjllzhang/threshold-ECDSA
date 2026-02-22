#include "tecdsa/protocol/keygen_session.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace tecdsa {
namespace {

std::unordered_set<PartyIndex> BuildPeerSet(const std::vector<PartyIndex>& participants,
                                            PartyIndex self_id) {
  std::unordered_set<PartyIndex> peers;
  for (PartyIndex id : participants) {
    if (id == 0) {
      throw std::invalid_argument("participants must not contain 0");
    }
    if (id != self_id) {
      peers.insert(id);
    }
  }
  return peers;
}

}  // namespace

KeygenSession::KeygenSession(KeygenSessionConfig cfg)
    : Session(std::move(cfg.session_id), cfg.self_id, cfg.timeout),
      participants_(std::move(cfg.participants)),
      peers_(BuildPeerSet(participants_, cfg.self_id)) {
  if (participants_.size() < 2) {
    throw std::invalid_argument("KeygenSession requires at least 2 participants");
  }
  if (std::find(participants_.begin(), participants_.end(), cfg.self_id) == participants_.end()) {
    throw std::invalid_argument("self_id must be in participants");
  }
}

KeygenPhase KeygenSession::phase() const {
  return phase_;
}

size_t KeygenSession::received_peer_count_in_phase() const {
  return seen_in_phase_.size();
}

bool KeygenSession::HandleEnvelope(const Envelope& envelope) {
  if (PollTimeout()) {
    return false;
  }
  if (IsTerminal()) {
    return false;
  }

  std::string error;
  if (!ValidateSessionBinding(envelope.session_id, envelope.to, &error)) {
    return false;
  }

  if (!peers_.contains(envelope.from)) {
    return false;
  }

  if (envelope.type != MessageTypeForPhase(phase_)) {
    Abort("unexpected envelope type for current keygen phase");
    return false;
  }

  const bool inserted = seen_in_phase_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  Touch();
  AdvanceIfPhaseDone();
  return true;
}

Envelope KeygenSession::MakePhaseBroadcastEnvelope(const Bytes& payload) const {
  if (IsTerminal()) {
    throw std::logic_error("cannot create envelope for terminal session");
  }

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase(phase_);
  out.payload = payload;
  return out;
}

uint32_t KeygenSession::MessageTypeForPhase(KeygenPhase phase) {
  switch (phase) {
    case KeygenPhase::kPhase1:
      return static_cast<uint32_t>(KeygenMessageType::kPhase1);
    case KeygenPhase::kPhase2:
      return static_cast<uint32_t>(KeygenMessageType::kPhase2);
    case KeygenPhase::kPhase3:
      return static_cast<uint32_t>(KeygenMessageType::kPhase3);
    case KeygenPhase::kCompleted:
      return static_cast<uint32_t>(KeygenMessageType::kAbort);
  }
  throw std::invalid_argument("invalid keygen phase");
}

void KeygenSession::AdvanceIfPhaseDone() {
  if (seen_in_phase_.size() != peers_.size()) {
    return;
  }

  seen_in_phase_.clear();

  if (phase_ == KeygenPhase::kPhase3) {
    phase_ = KeygenPhase::kCompleted;
    Complete();
    return;
  }

  phase_ = static_cast<KeygenPhase>(static_cast<uint32_t>(phase_) + 1);
}

}  // namespace tecdsa
