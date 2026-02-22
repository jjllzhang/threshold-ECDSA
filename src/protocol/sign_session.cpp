#include "tecdsa/protocol/sign_session.hpp"

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

SignSession::SignSession(SignSessionConfig cfg)
    : Session(std::move(cfg.session_id), cfg.self_id, cfg.timeout),
      participants_(std::move(cfg.participants)),
      peers_(BuildPeerSet(participants_, cfg.self_id)) {
  if (participants_.size() < 2) {
    throw std::invalid_argument("SignSession requires at least 2 participants");
  }
  if (std::find(participants_.begin(), participants_.end(), cfg.self_id) == participants_.end()) {
    throw std::invalid_argument("self_id must be in participants");
  }
}

SignPhase SignSession::phase() const {
  return phase_;
}

size_t SignSession::received_peer_count_in_phase() const {
  return seen_in_phase_.size();
}

bool SignSession::HandleEnvelope(const Envelope& envelope) {
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
    Abort("unexpected envelope type for current sign phase");
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

Envelope SignSession::MakePhaseBroadcastEnvelope(const Bytes& payload) const {
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

uint32_t SignSession::MessageTypeForPhase(SignPhase phase) {
  switch (phase) {
    case SignPhase::kPhase1:
      return static_cast<uint32_t>(SignMessageType::kPhase1);
    case SignPhase::kPhase2:
      return static_cast<uint32_t>(SignMessageType::kPhase2);
    case SignPhase::kPhase3:
      return static_cast<uint32_t>(SignMessageType::kPhase3);
    case SignPhase::kPhase4:
      return static_cast<uint32_t>(SignMessageType::kPhase4);
    case SignPhase::kPhase5:
      return static_cast<uint32_t>(SignMessageType::kPhase5);
    case SignPhase::kCompleted:
      return static_cast<uint32_t>(SignMessageType::kAbort);
  }
  throw std::invalid_argument("invalid sign phase");
}

void SignSession::AdvanceIfPhaseDone() {
  if (seen_in_phase_.size() != peers_.size()) {
    return;
  }

  seen_in_phase_.clear();

  if (phase_ == SignPhase::kPhase5) {
    phase_ = SignPhase::kCompleted;
    Complete();
    return;
  }

  phase_ = static_cast<SignPhase>(static_cast<uint32_t>(phase_) + 1);
}

}  // namespace tecdsa
