#pragma once

#include <cstdint>
#include <span>

#include "tecdsa/common/bytes.hpp"
#include "tecdsa/protocol/types.hpp"

namespace tecdsa {

constexpr PartyIndex kBroadcastPartyId = 0;

struct Envelope {
  Bytes session_id;
  PartyIndex from = 0;
  PartyIndex to = 0;
  uint32_t type = 0;
  Bytes payload;
};

Bytes EncodeEnvelope(const Envelope& envelope);
Envelope DecodeEnvelope(std::span<const uint8_t> encoded,
                        size_t max_session_id_len = 32,
                        size_t max_payload_len = 1 << 20);

}  // namespace tecdsa
