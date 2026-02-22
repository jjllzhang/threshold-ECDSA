#include "tecdsa/protocol/keygen_session.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>

#include "tecdsa/crypto/commitment.hpp"
#include "tecdsa/crypto/encoding.hpp"
#include "tecdsa/crypto/random.hpp"
#include "tecdsa/crypto/transcript.hpp"

namespace tecdsa {
namespace {

constexpr size_t kCommitmentLen = 32;
constexpr size_t kPointCompressedLen = 33;
constexpr size_t kScalarLen = 32;
constexpr size_t kMaxOpenRandomnessLen = 1024;
constexpr char kPhase1CommitDomain[] = "GG2019/keygen/phase1";
constexpr char kSchnorrProofId[] = "GG2019/Schnorr/v1";

void ValidateParticipantsOrThrow(const std::vector<PartyIndex>& participants, PartyIndex self_id) {
  if (participants.size() < 2) {
    throw std::invalid_argument("KeygenSession requires at least 2 participants");
  }

  std::unordered_set<PartyIndex> dedup;
  bool self_present = false;
  for (PartyIndex id : participants) {
    if (id == 0) {
      throw std::invalid_argument("participants must not contain 0");
    }
    if (!dedup.insert(id).second) {
      throw std::invalid_argument("participants must be unique");
    }
    if (id == self_id) {
      self_present = true;
    }
  }

  if (!self_present) {
    throw std::invalid_argument("self_id must be in participants");
  }
}

std::unordered_set<PartyIndex> BuildPeerSet(const std::vector<PartyIndex>& participants,
                                            PartyIndex self_id) {
  std::unordered_set<PartyIndex> peers;
  for (PartyIndex id : participants) {
    if (id != self_id) {
      peers.insert(id);
    }
  }
  return peers;
}

void AppendU32Be(uint32_t value, Bytes* out) {
  out->push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
  out->push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
  out->push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
  out->push_back(static_cast<uint8_t>(value & 0xFF));
}

uint32_t ReadU32Be(std::span<const uint8_t> input, size_t* offset) {
  if (*offset + 4 > input.size()) {
    throw std::invalid_argument("Not enough bytes to read u32");
  }

  const size_t i = *offset;
  *offset += 4;
  return (static_cast<uint32_t>(input[i]) << 24) |
         (static_cast<uint32_t>(input[i + 1]) << 16) |
         (static_cast<uint32_t>(input[i + 2]) << 8) |
         static_cast<uint32_t>(input[i + 3]);
}

void AppendSizedField(std::span<const uint8_t> field, Bytes* out) {
  if (field.size() > UINT32_MAX) {
    throw std::invalid_argument("Sized field exceeds uint32 length");
  }
  AppendU32Be(static_cast<uint32_t>(field.size()), out);
  out->insert(out->end(), field.begin(), field.end());
}

Bytes ReadSizedField(std::span<const uint8_t> input,
                     size_t* offset,
                     size_t max_len,
                     const char* field_name) {
  const uint32_t len = ReadU32Be(input, offset);
  if (len > max_len) {
    throw std::invalid_argument(std::string(field_name) + " exceeds maximum length");
  }
  if (*offset + len > input.size()) {
    throw std::invalid_argument(std::string(field_name) + " has inconsistent length");
  }

  Bytes out(input.begin() + static_cast<std::ptrdiff_t>(*offset),
            input.begin() + static_cast<std::ptrdiff_t>(*offset + len));
  *offset += len;
  return out;
}

void AppendPoint(const ECPoint& point, Bytes* out) {
  const Bytes encoded = EncodePoint(point);
  if (encoded.size() != kPointCompressedLen) {
    throw std::runtime_error("Encoded secp256k1 point must be 33 bytes");
  }
  out->insert(out->end(), encoded.begin(), encoded.end());
}

ECPoint ReadPoint(std::span<const uint8_t> input, size_t* offset) {
  if (*offset + kPointCompressedLen > input.size()) {
    throw std::invalid_argument("Not enough bytes for compressed secp256k1 point");
  }

  const std::span<const uint8_t> view =
      input.subspan(*offset, kPointCompressedLen);
  *offset += kPointCompressedLen;
  return DecodePoint(view);
}

void AppendScalar(const Scalar& scalar, Bytes* out) {
  const std::array<uint8_t, kScalarLen> encoded = scalar.ToCanonicalBytes();
  out->insert(out->end(), encoded.begin(), encoded.end());
}

Scalar ReadScalar(std::span<const uint8_t> input, size_t* offset) {
  if (*offset + kScalarLen > input.size()) {
    throw std::invalid_argument("Not enough bytes for scalar");
  }
  const std::span<const uint8_t> view = input.subspan(*offset, kScalarLen);
  *offset += kScalarLen;
  return Scalar::FromCanonicalBytes(view);
}

Bytes PartyIdToBytes(PartyIndex id) {
  Bytes out;
  out.reserve(4);
  AppendU32Be(id, &out);
  return out;
}

Scalar RandomNonZeroScalar() {
  while (true) {
    const Scalar candidate = Csprng::RandomScalar();
    if (candidate.value() != 0) {
      return candidate;
    }
  }
}

Scalar EvaluatePolynomialAt(const std::vector<Scalar>& coefficients, PartyIndex party_id) {
  if (coefficients.empty()) {
    throw std::invalid_argument("Polynomial coefficients must not be empty");
  }

  const mpz_class q = Scalar::ModulusQ();
  const mpz_class x = mpz_class(party_id) % q;

  mpz_class acc = 0;
  mpz_class power = 1;
  for (const Scalar& coefficient : coefficients) {
    acc += coefficient.value() * power;
    acc %= q;
    power *= x;
    power %= q;
  }
  return Scalar(acc);
}

Scalar BuildSchnorrChallenge(const Bytes& session_id,
                             PartyIndex party_id,
                             const ECPoint& statement,
                             const ECPoint& a) {
  Transcript transcript;

  const std::span<const uint8_t> proof_id(
      reinterpret_cast<const uint8_t*>(kSchnorrProofId), std::strlen(kSchnorrProofId));
  transcript.append("proof_id", proof_id);
  transcript.append("session_id", session_id);
  const Bytes party_bytes = PartyIdToBytes(party_id);
  transcript.append("party_id", party_bytes);
  const Bytes statement_bytes = EncodePoint(statement);
  transcript.append("X", statement_bytes);
  const Bytes a_bytes = EncodePoint(a);
  transcript.append("A", a_bytes);

  return transcript.challenge_scalar_mod_q();
}

}  // namespace

KeygenSession::KeygenSession(KeygenSessionConfig cfg)
    : Session(std::move(cfg.session_id), cfg.self_id, cfg.timeout),
      participants_(std::move(cfg.participants)),
      threshold_(cfg.threshold),
      peers_(BuildPeerSet(participants_, cfg.self_id)) {
  ValidateParticipantsOrThrow(participants_, cfg.self_id);
  if (threshold_ >= participants_.size()) {
    throw std::invalid_argument("threshold must be less than participant count");
  }
}

KeygenPhase KeygenSession::phase() const {
  return phase_;
}

size_t KeygenSession::received_peer_count_in_phase() const {
  switch (phase_) {
    case KeygenPhase::kPhase1:
      return seen_phase1_.size();
    case KeygenPhase::kPhase2: {
      size_t complete = 0;
      for (PartyIndex peer : peers_) {
        if (seen_phase2_opens_.contains(peer) && seen_phase2_shares_.contains(peer)) {
          ++complete;
        }
      }
      return complete;
    }
    case KeygenPhase::kPhase3:
      return seen_phase3_.size();
    case KeygenPhase::kCompleted:
      return peers_.size();
  }
  throw std::invalid_argument("invalid keygen phase");
}

uint32_t KeygenSession::threshold() const {
  return threshold_;
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

  switch (phase_) {
    case KeygenPhase::kPhase1:
      if (envelope.type != MessageTypeForPhase(KeygenPhase::kPhase1)) {
        Abort("unexpected envelope type for keygen phase1");
        return false;
      }
      return HandlePhase1CommitEnvelope(envelope);
    case KeygenPhase::kPhase2:
      if (envelope.type == MessageTypeForPhase(KeygenPhase::kPhase2)) {
        return HandlePhase2OpenEnvelope(envelope);
      }
      if (envelope.type == Phase2ShareMessageType()) {
        return HandlePhase2ShareEnvelope(envelope);
      }
      Abort("unexpected envelope type for keygen phase2");
      return false;
    case KeygenPhase::kPhase3:
      if (envelope.type != MessageTypeForPhase(KeygenPhase::kPhase3)) {
        Abort("unexpected envelope type for keygen phase3");
        return false;
      }
      return HandlePhase3XiProofEnvelope(envelope);
    case KeygenPhase::kCompleted:
      return false;
  }
  throw std::invalid_argument("invalid keygen phase");
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

uint32_t KeygenSession::Phase2ShareMessageType() {
  return static_cast<uint32_t>(KeygenMessageType::kPhase2Share);
}

Envelope KeygenSession::BuildPhase1CommitEnvelope() {
  if (IsTerminal()) {
    throw std::logic_error("cannot build phase1 envelope for terminal keygen session");
  }
  if (phase_ != KeygenPhase::kPhase1) {
    throw std::logic_error("BuildPhase1CommitEnvelope must be called in keygen phase1");
  }

  EnsureLocalPolynomialPrepared();
  phase1_commitments_[self_id()] = local_commitment_;

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase(KeygenPhase::kPhase1);
  out.payload = local_commitment_;
  return out;
}

std::vector<Envelope> KeygenSession::BuildPhase2OpenAndShareEnvelopes() {
  if (IsTerminal()) {
    throw std::logic_error("cannot build phase2 envelopes for terminal keygen session");
  }
  if (phase_ != KeygenPhase::kPhase2) {
    throw std::logic_error("BuildPhase2OpenAndShareEnvelopes must be called in keygen phase2");
  }

  EnsureLocalPolynomialPrepared();
  local_phase2_ready_ = true;
  phase2_open_data_[self_id()] = Phase2OpenData{local_y_i_, local_open_randomness_, local_vss_commitments_};
  phase2_verified_shares_[self_id()] = local_shares_.at(self_id());

  Bytes open_payload;
  open_payload.reserve(kPointCompressedLen + 4 + local_open_randomness_.size() +
                       4 + kPointCompressedLen * local_vss_commitments_.size());
  AppendPoint(local_y_i_, &open_payload);
  AppendSizedField(local_open_randomness_, &open_payload);
  AppendU32Be(static_cast<uint32_t>(local_vss_commitments_.size()), &open_payload);
  for (const ECPoint& commitment : local_vss_commitments_) {
    AppendPoint(commitment, &open_payload);
  }

  std::vector<Envelope> out;
  out.reserve(1 + peers_.size());

  Envelope open_msg;
  open_msg.session_id = session_id();
  open_msg.from = self_id();
  open_msg.to = kBroadcastPartyId;
  open_msg.type = MessageTypeForPhase(KeygenPhase::kPhase2);
  open_msg.payload = std::move(open_payload);
  out.push_back(std::move(open_msg));

  for (PartyIndex peer : participants_) {
    if (peer == self_id()) {
      continue;
    }
    Envelope share_msg;
    share_msg.session_id = session_id();
    share_msg.from = self_id();
    share_msg.to = peer;
    share_msg.type = Phase2ShareMessageType();
    AppendScalar(local_shares_.at(peer), &share_msg.payload);
    out.push_back(std::move(share_msg));
  }

  MaybeAdvanceAfterPhase2();
  return out;
}

Envelope KeygenSession::BuildPhase3XiProofEnvelope() {
  if (IsTerminal()) {
    throw std::logic_error("cannot build phase3 envelope for terminal keygen session");
  }
  if (phase_ != KeygenPhase::kPhase3) {
    throw std::logic_error("BuildPhase3XiProofEnvelope must be called in keygen phase3");
  }
  if (!phase2_aggregates_ready_) {
    throw std::logic_error("phase2 aggregates are not ready");
  }

  if (!local_phase3_payload_.has_value()) {
    if (result_.x_i.value() == 0) {
      Abort("aggregated local share is zero");
      throw std::runtime_error("aggregated local share is zero");
    }

    Phase3BroadcastData payload;
    payload.X_i = ECPoint::GeneratorMultiply(result_.x_i);
    payload.proof = BuildSchnorrProof(payload.X_i, result_.x_i);
    local_phase3_payload_ = payload;

    local_phase3_ready_ = true;
    phase3_broadcasts_[self_id()] = payload;
    result_.X_i = payload.X_i;
    result_.all_X_i[self_id()] = payload.X_i;
  }

  Bytes serialized;
  serialized.reserve(kPointCompressedLen + kPointCompressedLen + kScalarLen);
  AppendPoint(local_phase3_payload_->X_i, &serialized);
  AppendPoint(local_phase3_payload_->proof.a, &serialized);
  AppendScalar(local_phase3_payload_->proof.z, &serialized);

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase(KeygenPhase::kPhase3);
  out.payload = std::move(serialized);

  MaybeAdvanceAfterPhase3();
  return out;
}

bool KeygenSession::HasResult() const {
  return status() == SessionStatus::kCompleted && phase_ == KeygenPhase::kCompleted &&
         phase2_aggregates_ready_ && local_phase3_ready_ &&
         result_.all_X_i.size() == participants_.size();
}

const KeygenResult& KeygenSession::result() const {
  if (!HasResult()) {
    throw std::logic_error("keygen result is not ready");
  }
  return result_;
}

void KeygenSession::EnsureLocalPolynomialPrepared() {
  if (!local_poly_coefficients_.empty()) {
    return;
  }

  while (true) {
    std::vector<Scalar> candidate_coefficients;
    candidate_coefficients.reserve(threshold_ + 1);
    candidate_coefficients.push_back(RandomNonZeroScalar());
    for (uint32_t i = 0; i < threshold_; ++i) {
      candidate_coefficients.push_back(RandomNonZeroScalar());
    }

    std::unordered_map<PartyIndex, Scalar> candidate_shares;
    candidate_shares.reserve(participants_.size());
    bool has_zero_share = false;
    for (PartyIndex party : participants_) {
      const Scalar share = EvaluatePolynomialAt(candidate_coefficients, party);
      if (share.value() == 0) {
        has_zero_share = true;
        break;
      }
      candidate_shares[party] = share;
    }
    if (has_zero_share) {
      continue;
    }

    local_poly_coefficients_ = std::move(candidate_coefficients);
    local_shares_ = std::move(candidate_shares);
    break;
  }

  local_y_i_ = ECPoint::GeneratorMultiply(local_poly_coefficients_[0]);

  local_vss_commitments_.clear();
  local_vss_commitments_.reserve(local_poly_coefficients_.size());
  for (const Scalar& coefficient : local_poly_coefficients_) {
    local_vss_commitments_.push_back(ECPoint::GeneratorMultiply(coefficient));
  }

  const Bytes y_i_bytes = EncodePoint(local_y_i_);
  const CommitmentResult commit = CommitMessage(kPhase1CommitDomain, y_i_bytes);
  local_commitment_ = commit.commitment;
  local_open_randomness_ = commit.randomness;
}

bool KeygenSession::HandlePhase1CommitEnvelope(const Envelope& envelope) {
  if (envelope.payload.size() != kCommitmentLen) {
    Abort("invalid keygen phase1 commitment payload length");
    return false;
  }

  const bool inserted = seen_phase1_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  phase1_commitments_[envelope.from] = envelope.payload;
  Touch();
  MaybeAdvanceAfterPhase1();
  return true;
}

bool KeygenSession::HandlePhase2OpenEnvelope(const Envelope& envelope) {
  if (envelope.to != kBroadcastPartyId) {
    Abort("keygen phase2 open message must be broadcast");
    return false;
  }

  const bool inserted = seen_phase2_opens_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  try {
    size_t offset = 0;
    const ECPoint y_i = ReadPoint(envelope.payload, &offset);
    const Bytes randomness = ReadSizedField(
        envelope.payload, &offset, kMaxOpenRandomnessLen, "keygen phase2 open randomness");
    const uint32_t commitment_count = ReadU32Be(envelope.payload, &offset);
    if (commitment_count != threshold_ + 1) {
      throw std::invalid_argument("keygen phase2 commitments count does not match threshold");
    }

    std::vector<ECPoint> commitments;
    commitments.reserve(commitment_count);
    for (uint32_t i = 0; i < commitment_count; ++i) {
      commitments.push_back(ReadPoint(envelope.payload, &offset));
    }

    if (offset != envelope.payload.size()) {
      throw std::invalid_argument("keygen phase2 open payload has trailing bytes");
    }

    const auto commitment_it = phase1_commitments_.find(envelope.from);
    if (commitment_it == phase1_commitments_.end()) {
      throw std::invalid_argument("missing phase1 commitment for dealer");
    }

    const Bytes y_i_bytes = EncodePoint(y_i);
    if (!VerifyCommitment(
            kPhase1CommitDomain, y_i_bytes, randomness, commitment_it->second)) {
      throw std::invalid_argument("phase2 open does not match phase1 commitment");
    }
    if (commitments.empty() || commitments.front() != y_i) {
      throw std::invalid_argument("phase2 Feldman commitments do not match opened Y_i");
    }

    phase2_open_data_[envelope.from] = Phase2OpenData{
        .y_i = y_i,
        .randomness = randomness,
        .commitments = commitments,
    };

    const auto pending_it = pending_phase2_shares_.find(envelope.from);
    if (pending_it != pending_phase2_shares_.end()) {
      if (!VerifyDealerShareForSelf(envelope.from, pending_it->second)) {
        throw std::invalid_argument("phase2 Feldman share verification failed");
      }
      phase2_verified_shares_[envelope.from] = pending_it->second;
      pending_phase2_shares_.erase(pending_it);
    }
  } catch (const std::exception& ex) {
    Abort(std::string("invalid keygen phase2 open: ") + ex.what());
    return false;
  }

  Touch();
  MaybeAdvanceAfterPhase2();
  return true;
}

bool KeygenSession::HandlePhase2ShareEnvelope(const Envelope& envelope) {
  if (envelope.to != self_id()) {
    Abort("keygen phase2 share message must target receiver directly");
    return false;
  }

  const bool inserted = seen_phase2_shares_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  try {
    size_t offset = 0;
    const Scalar share = ReadScalar(envelope.payload, &offset);
    if (offset != envelope.payload.size()) {
      throw std::invalid_argument("keygen phase2 share payload has trailing bytes");
    }

    if (phase2_open_data_.contains(envelope.from)) {
      if (!VerifyDealerShareForSelf(envelope.from, share)) {
        throw std::invalid_argument("phase2 Feldman share verification failed");
      }
      phase2_verified_shares_[envelope.from] = share;
    } else {
      pending_phase2_shares_[envelope.from] = share;
    }
  } catch (const std::exception& ex) {
    Abort(std::string("invalid keygen phase2 share: ") + ex.what());
    return false;
  }

  Touch();
  MaybeAdvanceAfterPhase2();
  return true;
}

bool KeygenSession::HandlePhase3XiProofEnvelope(const Envelope& envelope) {
  if (envelope.to != kBroadcastPartyId) {
    Abort("keygen phase3 message must be broadcast");
    return false;
  }

  const bool inserted = seen_phase3_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  try {
    size_t offset = 0;
    const ECPoint X_i = ReadPoint(envelope.payload, &offset);
    const ECPoint a = ReadPoint(envelope.payload, &offset);
    const Scalar z = ReadScalar(envelope.payload, &offset);
    if (offset != envelope.payload.size()) {
      throw std::invalid_argument("keygen phase3 payload has trailing bytes");
    }

    const SchnorrProof proof{.a = a, .z = z};
    if (!VerifySchnorrProof(envelope.from, X_i, proof)) {
      throw std::invalid_argument("schnorr proof verification failed");
    }

    phase3_broadcasts_[envelope.from] = Phase3BroadcastData{.X_i = X_i, .proof = proof};
    result_.all_X_i[envelope.from] = X_i;
  } catch (const std::exception& ex) {
    Abort(std::string("invalid keygen phase3 payload: ") + ex.what());
    return false;
  }

  Touch();
  MaybeAdvanceAfterPhase3();
  return true;
}

bool KeygenSession::VerifyDealerShareForSelf(PartyIndex dealer, const Scalar& share) const {
  if (share.value() == 0) {
    return false;
  }

  const auto open_it = phase2_open_data_.find(dealer);
  if (open_it == phase2_open_data_.end()) {
    return false;
  }

  const std::vector<ECPoint>& commitments = open_it->second.commitments;
  if (commitments.size() != threshold_ + 1 || commitments.empty()) {
    return false;
  }

  try {
    ECPoint rhs = commitments[0];
    mpz_class power = mpz_class(self_id()) % Scalar::ModulusQ();
    for (size_t k = 1; k < commitments.size(); ++k) {
      rhs = rhs.Add(commitments[k].Mul(Scalar(power)));
      power *= self_id();
      power %= Scalar::ModulusQ();
    }

    const ECPoint lhs = ECPoint::GeneratorMultiply(share);
    return lhs == rhs;
  } catch (const std::exception&) {
    return false;
  }
}

void KeygenSession::MaybeAdvanceAfterPhase1() {
  if (phase_ != KeygenPhase::kPhase1) {
    return;
  }
  if (seen_phase1_.size() != peers_.size()) {
    return;
  }
  phase_ = KeygenPhase::kPhase2;
}

void KeygenSession::MaybeAdvanceAfterPhase2() {
  if (phase_ != KeygenPhase::kPhase2) {
    return;
  }
  if (!local_phase2_ready_) {
    return;
  }
  if (seen_phase2_opens_.size() != peers_.size()) {
    return;
  }
  if (seen_phase2_shares_.size() != peers_.size()) {
    return;
  }
  if (!pending_phase2_shares_.empty()) {
    return;
  }
  if (phase2_open_data_.size() != participants_.size()) {
    return;
  }
  if (phase2_verified_shares_.size() != participants_.size()) {
    return;
  }

  ComputePhase2Aggregates();
  if (IsTerminal()) {
    return;
  }
  phase_ = KeygenPhase::kPhase3;
}

void KeygenSession::MaybeAdvanceAfterPhase3() {
  if (phase_ != KeygenPhase::kPhase3) {
    return;
  }
  if (!local_phase3_ready_) {
    return;
  }
  if (seen_phase3_.size() != peers_.size()) {
    return;
  }
  if (phase3_broadcasts_.size() != participants_.size()) {
    return;
  }
  if (result_.all_X_i.size() != participants_.size()) {
    return;
  }

  phase_ = KeygenPhase::kCompleted;
  Complete();
}

void KeygenSession::ComputePhase2Aggregates() {
  Scalar x_sum;
  for (const auto& [dealer, share] : phase2_verified_shares_) {
    (void)dealer;
    x_sum = x_sum + share;
  }
  if (x_sum.value() == 0) {
    Abort("aggregated local share is zero");
    return;
  }

  bool first = true;
  ECPoint y_sum;
  for (PartyIndex party : participants_) {
    const auto open_it = phase2_open_data_.find(party);
    if (open_it == phase2_open_data_.end()) {
      Abort("missing phase2 open data");
      return;
    }
    if (first) {
      y_sum = open_it->second.y_i;
      first = false;
      continue;
    }
    try {
      y_sum = y_sum.Add(open_it->second.y_i);
    } catch (const std::exception& ex) {
      Abort(std::string("failed to aggregate keygen public key points: ") + ex.what());
      return;
    }
  }

  result_.x_i = x_sum;
  result_.y = y_sum;
  phase2_aggregates_ready_ = true;
}

SchnorrProof KeygenSession::BuildSchnorrProof(const ECPoint& statement,
                                              const Scalar& witness) const {
  if (witness.value() == 0) {
    throw std::invalid_argument("schnorr witness must be non-zero");
  }

  while (true) {
    const Scalar r = RandomNonZeroScalar();
    const ECPoint a = ECPoint::GeneratorMultiply(r);
    const Scalar e = BuildSchnorrChallenge(session_id(), self_id(), statement, a);
    const Scalar z = r + (e * witness);
    if (z.value() == 0) {
      continue;
    }
    return SchnorrProof{.a = a, .z = z};
  }
}

bool KeygenSession::VerifySchnorrProof(PartyIndex prover_id,
                                       const ECPoint& statement,
                                       const SchnorrProof& proof) const {
  if (proof.z.value() == 0) {
    return false;
  }

  try {
    const Scalar e = BuildSchnorrChallenge(session_id(), prover_id, statement, proof.a);
    const ECPoint lhs = ECPoint::GeneratorMultiply(proof.z);

    ECPoint rhs = proof.a;
    if (e.value() != 0) {
      rhs = rhs.Add(statement.Mul(e));
    }
    return lhs == rhs;
  } catch (const std::exception&) {
    return false;
  }
}

}  // namespace tecdsa
