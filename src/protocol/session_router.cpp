#include "tecdsa/protocol/session_router.hpp"

#include <stdexcept>
#include <utility>

#include "tecdsa/net/envelope.hpp"

namespace tecdsa {

SessionRouter::SessionRouter(PartyIndex self_id) : self_id_(self_id) {
  if (self_id_ == 0) {
    throw std::invalid_argument("SessionRouter self_id must be non-zero");
  }
}

void SessionRouter::RegisterSession(const Bytes& session_id, EnvelopeHandler handler) {
  if (session_id.empty()) {
    throw std::invalid_argument("session_id must not be empty");
  }
  if (!handler) {
    throw std::invalid_argument("handler must not be empty");
  }

  handlers_[SessionKey(session_id)] = std::move(handler);
}

void SessionRouter::UnregisterSession(const Bytes& session_id) {
  handlers_.erase(SessionKey(session_id));
}

bool SessionRouter::Route(const Envelope& envelope) {
  if (envelope.session_id.empty()) {
    ++rejected_count_;
    return false;
  }
  if (envelope.type == 0) {
    ++rejected_count_;
    return false;
  }
  if (envelope.to != self_id_ && envelope.to != kBroadcastPartyId) {
    ++rejected_count_;
    return false;
  }

  const auto it = handlers_.find(SessionKey(envelope.session_id));
  if (it == handlers_.end()) {
    ++rejected_count_;
    return false;
  }

  it->second(envelope);
  return true;
}

size_t SessionRouter::rejected_count() const {
  return rejected_count_;
}

std::string SessionRouter::SessionKey(const Bytes& session_id) {
  return std::string(reinterpret_cast<const char*>(session_id.data()), session_id.size());
}

}  // namespace tecdsa
