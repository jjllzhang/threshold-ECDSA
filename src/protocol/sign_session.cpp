#include "tecdsa/protocol/sign_session.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

extern "C" {
#include <secp256k1.h>
}

#include "tecdsa/crypto/commitment.hpp"
#include "tecdsa/crypto/random.hpp"

namespace tecdsa {
namespace {

constexpr size_t kCommitmentLen = 32;
constexpr size_t kPointCompressedLen = 33;
constexpr size_t kScalarLen = 32;
constexpr size_t kMaxOpenRandomnessLen = 1024;
constexpr char kPhase1CommitDomain[] = "GG2019/sign/phase1";
constexpr char kPhase5ACommitDomain[] = "GG2019/sign/phase5A";
constexpr char kPhase5CCommitDomain[] = "GG2019/sign/phase5C";

void ValidateParticipantsOrThrow(const std::vector<PartyIndex>& participants, PartyIndex self_id) {
  if (participants.size() < 2) {
    throw std::invalid_argument("SignSession requires at least 2 participants");
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
    throw std::invalid_argument("sized field exceeds uint32 length");
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
  const Bytes encoded = point.ToCompressedBytes();
  if (encoded.size() != kPointCompressedLen) {
    throw std::runtime_error("Encoded secp256k1 point must be 33 bytes");
  }
  out->insert(out->end(), encoded.begin(), encoded.end());
}

ECPoint ReadPoint(std::span<const uint8_t> input, size_t* offset) {
  if (*offset + kPointCompressedLen > input.size()) {
    throw std::invalid_argument("Not enough bytes for compressed secp256k1 point");
  }

  const std::span<const uint8_t> view = input.subspan(*offset, kPointCompressedLen);
  *offset += kPointCompressedLen;
  return ECPoint::FromCompressed(view);
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

Scalar RandomNonZeroScalar() {
  while (true) {
    const Scalar candidate = Csprng::RandomScalar();
    if (candidate.value() != 0) {
      return candidate;
    }
  }
}

mpz_class NormalizeModQ(const mpz_class& value) {
  mpz_class out = value % Scalar::ModulusQ();
  if (out < 0) {
    out += Scalar::ModulusQ();
  }
  return out;
}

std::optional<Scalar> InvertScalar(const Scalar& scalar) {
  if (scalar.value() == 0) {
    return std::nullopt;
  }

  mpz_class inv;
  if (mpz_invert(inv.get_mpz_t(), scalar.value().get_mpz_t(), Scalar::ModulusQ().get_mpz_t()) == 0) {
    return std::nullopt;
  }
  return Scalar(inv);
}

bool IsHighScalar(const Scalar& scalar) {
  static const mpz_class kHalfOrder = Scalar::ModulusQ() >> 1;
  return scalar.value() > kHalfOrder;
}

std::unordered_map<PartyIndex, Scalar> ComputeLagrangeAtZero(
    const std::vector<PartyIndex>& participants) {
  std::unordered_map<PartyIndex, Scalar> out;
  out.reserve(participants.size());

  for (PartyIndex i : participants) {
    mpz_class numerator = 1;
    mpz_class denominator = 1;

    for (PartyIndex j : participants) {
      if (j == i) {
        continue;
      }

      const mpz_class neg_j = NormalizeModQ(-mpz_class(j));
      numerator *= neg_j;
      numerator %= Scalar::ModulusQ();

      const mpz_class diff = NormalizeModQ(mpz_class(i) - mpz_class(j));
      if (diff == 0) {
        throw std::invalid_argument("duplicate participant id in lagrange coefficient set");
      }
      denominator *= diff;
      denominator %= Scalar::ModulusQ();
    }

    mpz_class denominator_inv;
    if (mpz_invert(denominator_inv.get_mpz_t(), denominator.get_mpz_t(), Scalar::ModulusQ().get_mpz_t()) ==
        0) {
      throw std::invalid_argument("failed to invert lagrange denominator");
    }

    mpz_class lambda = numerator * denominator_inv;
    lambda %= Scalar::ModulusQ();
    out.emplace(i, Scalar(lambda));
  }

  return out;
}

ECPoint SumPointsOrThrow(const std::vector<ECPoint>& points) {
  if (points.empty()) {
    throw std::invalid_argument("cannot sum empty point vector");
  }

  ECPoint sum = points.front();
  for (size_t i = 1; i < points.size(); ++i) {
    sum = sum.Add(points[i]);
  }
  return sum;
}

Bytes SerializePointPair(const ECPoint& first, const ECPoint& second) {
  Bytes out;
  out.reserve(kPointCompressedLen * 2);
  AppendPoint(first, &out);
  AppendPoint(second, &out);
  return out;
}

secp256k1_context* GetSecpVerifyContext() {
  static secp256k1_context* ctx = []() {
    secp256k1_context* created = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    if (created == nullptr) {
      throw std::runtime_error("Failed to create secp256k1 verify context");
    }
    return created;
  }();
  return ctx;
}

bool VerifyEcdsaSignature(const ECPoint& public_key,
                          std::span<const uint8_t> msg32,
                          const Scalar& r,
                          const Scalar& s) {
  if (msg32.size() != 32) {
    return false;
  }
  if (r.value() == 0 || s.value() == 0) {
    return false;
  }

  secp256k1_pubkey pubkey;
  const Bytes compressed = public_key.ToCompressedBytes();
  if (compressed.size() != kPointCompressedLen) {
    return false;
  }
  if (secp256k1_ec_pubkey_parse(GetSecpVerifyContext(),
                                &pubkey,
                                compressed.data(),
                                compressed.size()) != 1) {
    return false;
  }

  std::array<uint8_t, 64> compact_sig{};
  const std::array<uint8_t, 32> r_bytes = r.ToCanonicalBytes();
  const std::array<uint8_t, 32> s_bytes = s.ToCanonicalBytes();
  std::copy(r_bytes.begin(), r_bytes.end(), compact_sig.begin());
  std::copy(s_bytes.begin(), s_bytes.end(), compact_sig.begin() + 32);

  secp256k1_ecdsa_signature signature;
  if (secp256k1_ecdsa_signature_parse_compact(GetSecpVerifyContext(), &signature, compact_sig.data()) != 1) {
    return false;
  }

  return secp256k1_ecdsa_verify(GetSecpVerifyContext(),
                                &signature,
                                msg32.data(),
                                &pubkey) == 1;
}

Scalar XCoordinateModQ(const ECPoint& point) {
  const Bytes compressed = point.ToCompressedBytes();
  if (compressed.size() != kPointCompressedLen) {
    throw std::invalid_argument("invalid compressed point length");
  }

  const std::span<const uint8_t> x_bytes(compressed.data() + 1, 32);
  return Scalar::FromBigEndianModQ(x_bytes);
}

}  // namespace

SignSession::SignSession(SignSessionConfig cfg)
    : Session(std::move(cfg.session_id), cfg.self_id, cfg.timeout),
      participants_(std::move(cfg.participants)),
      peers_(BuildPeerSet(participants_, cfg.self_id)),
      all_X_i_(std::move(cfg.all_X_i)),
      phase2_stub_shares_(std::move(cfg.phase2_stub_shares)),
      local_x_i_(cfg.x_i),
      public_key_y_(cfg.y),
      msg32_(std::move(cfg.msg32)),
      fixed_k_i_(cfg.fixed_k_i),
      fixed_gamma_i_(cfg.fixed_gamma_i) {
  ValidateParticipantsOrThrow(participants_, cfg.self_id);

  if (msg32_.size() != 32) {
    throw std::invalid_argument("msg32 must be exactly 32 bytes for SignSession");
  }
  if (local_x_i_.value() == 0) {
    throw std::invalid_argument("local x_i share must be non-zero");
  }

  for (PartyIndex party : participants_) {
    if (!all_X_i_.contains(party)) {
      throw std::invalid_argument("all_X_i is missing participant public share");
    }
    if (!phase2_stub_shares_.contains(party)) {
      throw std::invalid_argument("phase2_stub_shares must include all participants");
    }
  }

  message_scalar_ = Scalar::FromBigEndianModQ(msg32_);
  PrepareResharedSigningShares();
}

SignPhase SignSession::phase() const {
  return phase_;
}

SignPhase5Stage SignSession::phase5_stage() const {
  return phase5_stage_;
}

size_t SignSession::received_peer_count_in_phase() const {
  switch (phase_) {
    case SignPhase::kPhase1:
      return seen_phase1_.size();
    case SignPhase::kPhase2:
      return seen_phase2_.size();
    case SignPhase::kPhase3:
      return seen_phase3_.size();
    case SignPhase::kPhase4:
      return seen_phase4_.size();
    case SignPhase::kPhase5:
      switch (phase5_stage_) {
        case SignPhase5Stage::kPhase5A:
          return seen_phase5a_.size();
        case SignPhase5Stage::kPhase5B:
          return seen_phase5b_.size();
        case SignPhase5Stage::kPhase5C:
          return seen_phase5c_.size();
        case SignPhase5Stage::kPhase5D:
          return seen_phase5d_.size();
        case SignPhase5Stage::kPhase5E:
          return seen_phase5e_.size();
        case SignPhase5Stage::kCompleted:
          return peers_.size();
      }
      throw std::invalid_argument("invalid phase5 stage");
    case SignPhase::kCompleted:
      return peers_.size();
  }
  throw std::invalid_argument("invalid sign phase");
}

Envelope SignSession::BuildPhase1CommitEnvelope() {
  if (IsTerminal()) {
    throw std::logic_error("cannot build phase1 envelope for terminal sign session");
  }
  if (phase_ != SignPhase::kPhase1) {
    throw std::logic_error("BuildPhase1CommitEnvelope must be called in sign phase1");
  }

  PreparePhase1SecretsIfNeeded();

  local_phase1_ready_ = true;
  phase1_commitments_[self_id()] = local_phase1_commitment_;

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase(SignPhase::kPhase1);
  out.payload = local_phase1_commitment_;

  MaybeAdvanceAfterPhase1();
  return out;
}

Envelope SignSession::BuildPhase2StubEnvelope() {
  if (IsTerminal()) {
    throw std::logic_error("cannot build phase2 envelope for terminal sign session");
  }
  if (phase_ != SignPhase::kPhase2) {
    throw std::logic_error("BuildPhase2StubEnvelope must be called in sign phase2");
  }

  const auto local_stub_it = phase2_stub_shares_.find(self_id());
  if (local_stub_it == phase2_stub_shares_.end()) {
    throw std::logic_error("missing local phase2 stub share");
  }

  local_delta_i_ = local_stub_it->second.delta_i;
  local_sigma_i_ = local_stub_it->second.sigma_i;

  local_phase2_ready_ = true;
  phase2_received_shares_[self_id()] = local_stub_it->second;

  Bytes payload;
  payload.reserve(kScalarLen * 2);
  AppendScalar(local_stub_it->second.delta_i, &payload);
  AppendScalar(local_stub_it->second.sigma_i, &payload);

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase(SignPhase::kPhase2);
  out.payload = std::move(payload);

  MaybeAdvanceAfterPhase2();
  return out;
}

Envelope SignSession::BuildPhase3DeltaEnvelope() {
  if (IsTerminal()) {
    throw std::logic_error("cannot build phase3 envelope for terminal sign session");
  }
  if (phase_ != SignPhase::kPhase3) {
    throw std::logic_error("BuildPhase3DeltaEnvelope must be called in sign phase3");
  }

  local_phase3_ready_ = true;
  phase3_delta_shares_[self_id()] = local_delta_i_;

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase(SignPhase::kPhase3);
  AppendScalar(local_delta_i_, &out.payload);

  MaybeAdvanceAfterPhase3();
  return out;
}

Envelope SignSession::BuildPhase4OpenGammaEnvelope() {
  if (IsTerminal()) {
    throw std::logic_error("cannot build phase4 envelope for terminal sign session");
  }
  if (phase_ != SignPhase::kPhase4) {
    throw std::logic_error("BuildPhase4OpenGammaEnvelope must be called in sign phase4");
  }

  PreparePhase1SecretsIfNeeded();

  local_phase4_ready_ = true;
  phase4_open_data_[self_id()] = Phase4OpenData{.gamma_i = local_Gamma_i_, .randomness = local_phase1_randomness_};

  Bytes payload;
  payload.reserve(kPointCompressedLen + 4 + local_phase1_randomness_.size());
  AppendPoint(local_Gamma_i_, &payload);
  AppendSizedField(local_phase1_randomness_, &payload);

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase(SignPhase::kPhase4);
  out.payload = std::move(payload);

  MaybeAdvanceAfterPhase4();
  return out;
}

Envelope SignSession::BuildPhase5ACommitEnvelope() {
  if (IsTerminal()) {
    throw std::logic_error("cannot build phase5A envelope for terminal sign session");
  }
  if (phase_ != SignPhase::kPhase5 || phase5_stage_ != SignPhase5Stage::kPhase5A) {
    throw std::logic_error("BuildPhase5ACommitEnvelope must be called in sign phase5A");
  }

  local_s_i_ = (message_scalar_ * local_k_i_) + (r_ * local_sigma_i_);
  local_l_i_ = RandomNonZeroScalar();
  local_rho_i_ = RandomNonZeroScalar();

  ECPoint V_i = ECPoint::GeneratorMultiply(local_l_i_);
  if (local_s_i_.value() != 0) {
    V_i = V_i.Add(R_.Mul(local_s_i_));
  }
  local_V_i_ = V_i;
  local_A_i_ = ECPoint::GeneratorMultiply(local_rho_i_);

  const Bytes commit_message = SerializePointPair(local_V_i_, local_A_i_);
  const CommitmentResult commitment = CommitMessage(kPhase5ACommitDomain, commit_message);

  local_phase5a_randomness_ = commitment.randomness;
  local_phase5a_commitment_ = commitment.commitment;

  local_phase5a_ready_ = true;
  phase5a_commitments_[self_id()] = local_phase5a_commitment_;

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase5Stage(SignPhase5Stage::kPhase5A);
  out.payload = local_phase5a_commitment_;

  MaybeAdvanceAfterPhase5A();
  return out;
}

Envelope SignSession::BuildPhase5BOpenEnvelope() {
  if (IsTerminal()) {
    throw std::logic_error("cannot build phase5B envelope for terminal sign session");
  }
  if (phase_ != SignPhase::kPhase5 || phase5_stage_ != SignPhase5Stage::kPhase5B) {
    throw std::logic_error("BuildPhase5BOpenEnvelope must be called in sign phase5B");
  }

  local_phase5b_ready_ = true;
  phase5b_open_data_[self_id()] =
      Phase5BOpenData{.V_i = local_V_i_, .A_i = local_A_i_, .randomness = local_phase5a_randomness_};

  Bytes payload;
  payload.reserve(kPointCompressedLen * 2 + 4 + local_phase5a_randomness_.size());
  AppendPoint(local_V_i_, &payload);
  AppendPoint(local_A_i_, &payload);
  AppendSizedField(local_phase5a_randomness_, &payload);

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase5Stage(SignPhase5Stage::kPhase5B);
  out.payload = std::move(payload);

  MaybeAdvanceAfterPhase5B();
  return out;
}

Envelope SignSession::BuildPhase5CCommitEnvelope() {
  if (IsTerminal()) {
    throw std::logic_error("cannot build phase5C envelope for terminal sign session");
  }
  if (phase_ != SignPhase::kPhase5 || phase5_stage_ != SignPhase5Stage::kPhase5C) {
    throw std::logic_error("BuildPhase5CCommitEnvelope must be called in sign phase5C");
  }

  local_U_i_ = V_.Mul(local_rho_i_);
  local_T_i_ = A_.Mul(local_l_i_);

  const Bytes commit_message = SerializePointPair(local_U_i_, local_T_i_);
  const CommitmentResult commitment = CommitMessage(kPhase5CCommitDomain, commit_message);
  local_phase5c_randomness_ = commitment.randomness;
  local_phase5c_commitment_ = commitment.commitment;

  local_phase5c_ready_ = true;
  phase5c_commitments_[self_id()] = local_phase5c_commitment_;

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase5Stage(SignPhase5Stage::kPhase5C);
  out.payload = local_phase5c_commitment_;

  MaybeAdvanceAfterPhase5C();
  return out;
}

Envelope SignSession::BuildPhase5DOpenEnvelope() {
  if (IsTerminal()) {
    throw std::logic_error("cannot build phase5D envelope for terminal sign session");
  }
  if (phase_ != SignPhase::kPhase5 || phase5_stage_ != SignPhase5Stage::kPhase5D) {
    throw std::logic_error("BuildPhase5DOpenEnvelope must be called in sign phase5D");
  }

  local_phase5d_ready_ = true;
  phase5d_open_data_[self_id()] =
      Phase5DOpenData{.U_i = local_U_i_, .T_i = local_T_i_, .randomness = local_phase5c_randomness_};

  Bytes payload;
  payload.reserve(kPointCompressedLen * 2 + 4 + local_phase5c_randomness_.size());
  AppendPoint(local_U_i_, &payload);
  AppendPoint(local_T_i_, &payload);
  AppendSizedField(local_phase5c_randomness_, &payload);

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase5Stage(SignPhase5Stage::kPhase5D);
  out.payload = std::move(payload);

  MaybeAdvanceAfterPhase5D();
  return out;
}

Envelope SignSession::BuildPhase5ERevealEnvelope() {
  if (IsTerminal()) {
    throw std::logic_error("cannot build phase5E envelope for terminal sign session");
  }
  if (phase_ != SignPhase::kPhase5 || phase5_stage_ != SignPhase5Stage::kPhase5E) {
    throw std::logic_error("BuildPhase5ERevealEnvelope must be called in sign phase5E");
  }

  local_phase5e_ready_ = true;
  phase5e_revealed_s_[self_id()] = local_s_i_;

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type = MessageTypeForPhase5Stage(SignPhase5Stage::kPhase5E);
  AppendScalar(local_s_i_, &out.payload);

  MaybeAdvanceAfterPhase5E();
  return out;
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

  switch (phase_) {
    case SignPhase::kPhase1:
      if (envelope.type != MessageTypeForPhase(SignPhase::kPhase1)) {
        Abort("unexpected envelope type for sign phase1");
        return false;
      }
      return HandlePhase1CommitEnvelope(envelope);
    case SignPhase::kPhase2:
      if (envelope.type != MessageTypeForPhase(SignPhase::kPhase2)) {
        Abort("unexpected envelope type for sign phase2");
        return false;
      }
      return HandlePhase2StubEnvelope(envelope);
    case SignPhase::kPhase3:
      if (envelope.type != MessageTypeForPhase(SignPhase::kPhase3)) {
        Abort("unexpected envelope type for sign phase3");
        return false;
      }
      return HandlePhase3DeltaEnvelope(envelope);
    case SignPhase::kPhase4:
      if (envelope.type != MessageTypeForPhase(SignPhase::kPhase4)) {
        Abort("unexpected envelope type for sign phase4");
        return false;
      }
      return HandlePhase4OpenEnvelope(envelope);
    case SignPhase::kPhase5:
      switch (phase5_stage_) {
        case SignPhase5Stage::kPhase5A:
          if (envelope.type != MessageTypeForPhase5Stage(SignPhase5Stage::kPhase5A)) {
            Abort("unexpected envelope type for sign phase5A");
            return false;
          }
          return HandlePhase5ACommitEnvelope(envelope);
        case SignPhase5Stage::kPhase5B:
          if (envelope.type != MessageTypeForPhase5Stage(SignPhase5Stage::kPhase5B)) {
            Abort("unexpected envelope type for sign phase5B");
            return false;
          }
          return HandlePhase5BOpenEnvelope(envelope);
        case SignPhase5Stage::kPhase5C:
          if (envelope.type != MessageTypeForPhase5Stage(SignPhase5Stage::kPhase5C)) {
            Abort("unexpected envelope type for sign phase5C");
            return false;
          }
          return HandlePhase5CCommitEnvelope(envelope);
        case SignPhase5Stage::kPhase5D:
          if (envelope.type != MessageTypeForPhase5Stage(SignPhase5Stage::kPhase5D)) {
            Abort("unexpected envelope type for sign phase5D");
            return false;
          }
          return HandlePhase5DOpenEnvelope(envelope);
        case SignPhase5Stage::kPhase5E:
          if (envelope.type != MessageTypeForPhase5Stage(SignPhase5Stage::kPhase5E)) {
            Abort("unexpected envelope type for sign phase5E");
            return false;
          }
          return HandlePhase5ERevealEnvelope(envelope);
        case SignPhase5Stage::kCompleted:
          return false;
      }
      throw std::invalid_argument("invalid sign phase5 stage");
    case SignPhase::kCompleted:
      return false;
  }
  throw std::invalid_argument("invalid sign phase");
}

Envelope SignSession::MakePhaseBroadcastEnvelope(const Bytes& payload) const {
  if (IsTerminal()) {
    throw std::logic_error("cannot create envelope for terminal session");
  }

  Envelope out;
  out.session_id = session_id();
  out.from = self_id();
  out.to = kBroadcastPartyId;
  out.type =
      (phase_ == SignPhase::kPhase5) ? MessageTypeForPhase5Stage(phase5_stage_) : MessageTypeForPhase(phase_);
  out.payload = payload;
  return out;
}

bool SignSession::HasResult() const {
  return status() == SessionStatus::kCompleted && phase_ == SignPhase::kCompleted && has_result_;
}

const SignResult& SignSession::result() const {
  if (!HasResult()) {
    throw std::logic_error("sign result is not ready");
  }
  return result_;
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
      return static_cast<uint32_t>(SignMessageType::kPhase5A);
    case SignPhase::kCompleted:
      return static_cast<uint32_t>(SignMessageType::kAbort);
  }
  throw std::invalid_argument("invalid sign phase");
}

uint32_t SignSession::MessageTypeForPhase5Stage(SignPhase5Stage stage) {
  switch (stage) {
    case SignPhase5Stage::kPhase5A:
      return static_cast<uint32_t>(SignMessageType::kPhase5A);
    case SignPhase5Stage::kPhase5B:
      return static_cast<uint32_t>(SignMessageType::kPhase5B);
    case SignPhase5Stage::kPhase5C:
      return static_cast<uint32_t>(SignMessageType::kPhase5C);
    case SignPhase5Stage::kPhase5D:
      return static_cast<uint32_t>(SignMessageType::kPhase5D);
    case SignPhase5Stage::kPhase5E:
      return static_cast<uint32_t>(SignMessageType::kPhase5E);
    case SignPhase5Stage::kCompleted:
      return static_cast<uint32_t>(SignMessageType::kAbort);
  }
  throw std::invalid_argument("invalid sign phase5 stage");
}

bool SignSession::HandlePhase1CommitEnvelope(const Envelope& envelope) {
  if (envelope.to != kBroadcastPartyId) {
    Abort("sign phase1 commitment message must be broadcast");
    return false;
  }
  if (envelope.payload.size() != kCommitmentLen) {
    Abort("invalid sign phase1 commitment payload length");
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

bool SignSession::HandlePhase2StubEnvelope(const Envelope& envelope) {
  if (envelope.to != kBroadcastPartyId) {
    Abort("sign phase2 stub message must be broadcast");
    return false;
  }

  const bool inserted = seen_phase2_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  try {
    size_t offset = 0;
    const Scalar delta_i = ReadScalar(envelope.payload, &offset);
    const Scalar sigma_i = ReadScalar(envelope.payload, &offset);
    if (offset != envelope.payload.size()) {
      throw std::invalid_argument("sign phase2 payload has trailing bytes");
    }

    const auto expected_it = phase2_stub_shares_.find(envelope.from);
    if (expected_it == phase2_stub_shares_.end()) {
      throw std::invalid_argument("missing expected stub share for sender");
    }
    if (delta_i != expected_it->second.delta_i || sigma_i != expected_it->second.sigma_i) {
      throw std::invalid_argument("phase2 stub share mismatch for sender");
    }

    phase2_received_shares_[envelope.from] = SignPhase2StubShare{.delta_i = delta_i, .sigma_i = sigma_i};
  } catch (const std::exception& ex) {
    Abort(std::string("invalid sign phase2 payload: ") + ex.what());
    return false;
  }

  Touch();
  MaybeAdvanceAfterPhase2();
  return true;
}

bool SignSession::HandlePhase3DeltaEnvelope(const Envelope& envelope) {
  if (envelope.to != kBroadcastPartyId) {
    Abort("sign phase3 delta message must be broadcast");
    return false;
  }

  const bool inserted = seen_phase3_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  try {
    size_t offset = 0;
    const Scalar delta_i = ReadScalar(envelope.payload, &offset);
    if (offset != envelope.payload.size()) {
      throw std::invalid_argument("sign phase3 payload has trailing bytes");
    }

    const auto phase2_it = phase2_received_shares_.find(envelope.from);
    if (phase2_it == phase2_received_shares_.end()) {
      throw std::invalid_argument("sign phase3 received before phase2 share for sender");
    }
    if (delta_i != phase2_it->second.delta_i) {
      throw std::invalid_argument("sign phase3 delta mismatch with phase2 stub share");
    }

    phase3_delta_shares_[envelope.from] = delta_i;
  } catch (const std::exception& ex) {
    Abort(std::string("invalid sign phase3 payload: ") + ex.what());
    return false;
  }

  Touch();
  MaybeAdvanceAfterPhase3();
  return true;
}

bool SignSession::HandlePhase4OpenEnvelope(const Envelope& envelope) {
  if (envelope.to != kBroadcastPartyId) {
    Abort("sign phase4 open message must be broadcast");
    return false;
  }

  const bool inserted = seen_phase4_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  try {
    size_t offset = 0;
    const ECPoint gamma_i = ReadPoint(envelope.payload, &offset);
    const Bytes randomness =
        ReadSizedField(envelope.payload, &offset, kMaxOpenRandomnessLen, "sign phase4 open randomness");
    if (offset != envelope.payload.size()) {
      throw std::invalid_argument("sign phase4 payload has trailing bytes");
    }

    const auto commitment_it = phase1_commitments_.find(envelope.from);
    if (commitment_it == phase1_commitments_.end()) {
      throw std::invalid_argument("missing phase1 commitment for sender");
    }

    const Bytes gamma_bytes = gamma_i.ToCompressedBytes();
    if (!VerifyCommitment(kPhase1CommitDomain, gamma_bytes, randomness, commitment_it->second)) {
      throw std::invalid_argument("phase4 open does not match phase1 commitment");
    }

    phase4_open_data_[envelope.from] = Phase4OpenData{.gamma_i = gamma_i, .randomness = randomness};
  } catch (const std::exception& ex) {
    Abort(std::string("invalid sign phase4 payload: ") + ex.what());
    return false;
  }

  Touch();
  MaybeAdvanceAfterPhase4();
  return true;
}

bool SignSession::HandlePhase5ACommitEnvelope(const Envelope& envelope) {
  if (envelope.to != kBroadcastPartyId) {
    Abort("sign phase5A commitment message must be broadcast");
    return false;
  }
  if (envelope.payload.size() != kCommitmentLen) {
    Abort("invalid sign phase5A commitment payload length");
    return false;
  }

  const bool inserted = seen_phase5a_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  phase5a_commitments_[envelope.from] = envelope.payload;
  Touch();
  MaybeAdvanceAfterPhase5A();
  return true;
}

bool SignSession::HandlePhase5BOpenEnvelope(const Envelope& envelope) {
  if (envelope.to != kBroadcastPartyId) {
    Abort("sign phase5B open message must be broadcast");
    return false;
  }

  const bool inserted = seen_phase5b_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  try {
    size_t offset = 0;
    const ECPoint V_i = ReadPoint(envelope.payload, &offset);
    const ECPoint A_i = ReadPoint(envelope.payload, &offset);
    const Bytes randomness =
        ReadSizedField(envelope.payload, &offset, kMaxOpenRandomnessLen, "sign phase5B open randomness");
    if (offset != envelope.payload.size()) {
      throw std::invalid_argument("sign phase5B payload has trailing bytes");
    }

    const auto commitment_it = phase5a_commitments_.find(envelope.from);
    if (commitment_it == phase5a_commitments_.end()) {
      throw std::invalid_argument("missing phase5A commitment for sender");
    }

    const Bytes commit_message = SerializePointPair(V_i, A_i);
    if (!VerifyCommitment(kPhase5ACommitDomain, commit_message, randomness, commitment_it->second)) {
      throw std::invalid_argument("phase5B open does not match phase5A commitment");
    }

    phase5b_open_data_[envelope.from] = Phase5BOpenData{.V_i = V_i, .A_i = A_i, .randomness = randomness};
  } catch (const std::exception& ex) {
    Abort(std::string("invalid sign phase5B payload: ") + ex.what());
    return false;
  }

  Touch();
  MaybeAdvanceAfterPhase5B();
  return true;
}

bool SignSession::HandlePhase5CCommitEnvelope(const Envelope& envelope) {
  if (envelope.to != kBroadcastPartyId) {
    Abort("sign phase5C commitment message must be broadcast");
    return false;
  }
  if (envelope.payload.size() != kCommitmentLen) {
    Abort("invalid sign phase5C commitment payload length");
    return false;
  }

  const bool inserted = seen_phase5c_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  phase5c_commitments_[envelope.from] = envelope.payload;
  Touch();
  MaybeAdvanceAfterPhase5C();
  return true;
}

bool SignSession::HandlePhase5DOpenEnvelope(const Envelope& envelope) {
  if (envelope.to != kBroadcastPartyId) {
    Abort("sign phase5D open message must be broadcast");
    return false;
  }

  const bool inserted = seen_phase5d_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  try {
    size_t offset = 0;
    const ECPoint U_i = ReadPoint(envelope.payload, &offset);
    const ECPoint T_i = ReadPoint(envelope.payload, &offset);
    const Bytes randomness =
        ReadSizedField(envelope.payload, &offset, kMaxOpenRandomnessLen, "sign phase5D open randomness");
    if (offset != envelope.payload.size()) {
      throw std::invalid_argument("sign phase5D payload has trailing bytes");
    }

    const auto commitment_it = phase5c_commitments_.find(envelope.from);
    if (commitment_it == phase5c_commitments_.end()) {
      throw std::invalid_argument("missing phase5C commitment for sender");
    }

    const Bytes commit_message = SerializePointPair(U_i, T_i);
    if (!VerifyCommitment(kPhase5CCommitDomain, commit_message, randomness, commitment_it->second)) {
      throw std::invalid_argument("phase5D open does not match phase5C commitment");
    }

    phase5d_open_data_[envelope.from] = Phase5DOpenData{.U_i = U_i, .T_i = T_i, .randomness = randomness};
  } catch (const std::exception& ex) {
    Abort(std::string("invalid sign phase5D payload: ") + ex.what());
    return false;
  }

  Touch();
  MaybeAdvanceAfterPhase5D();
  return true;
}

bool SignSession::HandlePhase5ERevealEnvelope(const Envelope& envelope) {
  if (envelope.to != kBroadcastPartyId) {
    Abort("sign phase5E reveal message must be broadcast");
    return false;
  }

  const bool inserted = seen_phase5e_.insert(envelope.from).second;
  if (!inserted) {
    return true;
  }

  try {
    size_t offset = 0;
    const Scalar s_i = ReadScalar(envelope.payload, &offset);
    if (offset != envelope.payload.size()) {
      throw std::invalid_argument("sign phase5E payload has trailing bytes");
    }

    phase5e_revealed_s_[envelope.from] = s_i;
  } catch (const std::exception& ex) {
    Abort(std::string("invalid sign phase5E payload: ") + ex.what());
    return false;
  }

  Touch();
  MaybeAdvanceAfterPhase5E();
  return true;
}

void SignSession::PrepareResharedSigningShares() {
  lagrange_coefficients_ = ComputeLagrangeAtZero(participants_);

  const auto lambda_self_it = lagrange_coefficients_.find(self_id());
  if (lambda_self_it == lagrange_coefficients_.end()) {
    throw std::invalid_argument("missing lagrange coefficient for self");
  }

  local_w_i_ = lambda_self_it->second * local_x_i_;
  w_shares_[self_id()] = local_w_i_;

  std::vector<ECPoint> w_points;
  w_points.reserve(participants_.size());
  for (PartyIndex party : participants_) {
    const auto lambda_it = lagrange_coefficients_.find(party);
    const auto x_pub_it = all_X_i_.find(party);
    if (lambda_it == lagrange_coefficients_.end() || x_pub_it == all_X_i_.end()) {
      throw std::invalid_argument("missing lagrange coefficient or X_i for participant");
    }

    try {
      W_points_[party] = x_pub_it->second.Mul(lambda_it->second);
    } catch (const std::exception& ex) {
      throw std::invalid_argument(std::string("failed to compute W_i: ") + ex.what());
    }
    w_points.push_back(W_points_.at(party));
  }

  try {
    const ECPoint reconstructed_y = SumPointsOrThrow(w_points);
    if (reconstructed_y != public_key_y_) {
      throw std::invalid_argument("W_i aggregation does not reconstruct y");
    }
  } catch (const std::exception& ex) {
    throw std::invalid_argument(std::string("failed to validate W_i aggregation: ") + ex.what());
  }
}

void SignSession::PreparePhase1SecretsIfNeeded() {
  if (!local_phase1_commitment_.empty()) {
    return;
  }

  local_k_i_ = fixed_k_i_.value_or(RandomNonZeroScalar());
  local_gamma_i_ = fixed_gamma_i_.value_or(RandomNonZeroScalar());
  if (local_k_i_.value() == 0 || local_gamma_i_.value() == 0) {
    throw std::invalid_argument("fixed k_i and gamma_i must be non-zero");
  }

  local_Gamma_i_ = ECPoint::GeneratorMultiply(local_gamma_i_);
  const Bytes gamma_bytes = local_Gamma_i_.ToCompressedBytes();
  const CommitmentResult commitment = CommitMessage(kPhase1CommitDomain, gamma_bytes);
  local_phase1_randomness_ = commitment.randomness;
  local_phase1_commitment_ = commitment.commitment;
}

void SignSession::ComputeDeltaInverseAndAdvanceToPhase4() {
  Scalar delta;
  for (PartyIndex party : participants_) {
    const auto delta_it = phase3_delta_shares_.find(party);
    if (delta_it == phase3_delta_shares_.end()) {
      Abort("missing phase3 delta share");
      return;
    }
    delta = delta + delta_it->second;
  }

  if (delta.value() == 0) {
    Abort("aggregated delta is zero");
    return;
  }

  const std::optional<Scalar> delta_inv = InvertScalar(delta);
  if (!delta_inv.has_value()) {
    Abort("failed to invert aggregated delta");
    return;
  }

  delta_ = delta;
  delta_inv_ = *delta_inv;
  phase_ = SignPhase::kPhase4;
}

void SignSession::ComputeRAndAdvanceToPhase5() {
  std::vector<ECPoint> gammas;
  gammas.reserve(participants_.size());
  for (PartyIndex party : participants_) {
    const auto gamma_it = phase4_open_data_.find(party);
    if (gamma_it == phase4_open_data_.end()) {
      Abort("missing phase4 opened gamma point");
      return;
    }
    gammas.push_back(gamma_it->second.gamma_i);
  }

  try {
    Gamma_ = SumPointsOrThrow(gammas);
    R_ = Gamma_.Mul(delta_inv_);
  } catch (const std::exception& ex) {
    Abort(std::string("failed to compute R in phase4: ") + ex.what());
    return;
  }

  r_ = XCoordinateModQ(R_);
  if (r_.value() == 0) {
    Abort("computed r is zero");
    return;
  }

  phase_ = SignPhase::kPhase5;
  phase5_stage_ = SignPhase5Stage::kPhase5A;
}

void SignSession::ComputePhase5VAAndAdvanceToStage5C() {
  std::vector<ECPoint> v_points;
  std::vector<ECPoint> a_points;
  v_points.reserve(participants_.size());
  a_points.reserve(participants_.size());

  for (PartyIndex party : participants_) {
    const auto open_it = phase5b_open_data_.find(party);
    if (open_it == phase5b_open_data_.end()) {
      Abort("missing phase5B open data");
      return;
    }
    v_points.push_back(open_it->second.V_i);
    a_points.push_back(open_it->second.A_i);
  }

  try {
    V_ = SumPointsOrThrow(v_points);
    A_ = SumPointsOrThrow(a_points);

    if (message_scalar_.value() != 0) {
      const Scalar neg_m = Scalar() - message_scalar_;
      V_ = V_.Add(ECPoint::GeneratorMultiply(neg_m));
    }

    const Scalar neg_r = Scalar() - r_;
    V_ = V_.Add(public_key_y_.Mul(neg_r));
  } catch (const std::exception& ex) {
    Abort(std::string("failed to compute phase5 V/A aggregates: ") + ex.what());
    return;
  }

  phase5_stage_ = SignPhase5Stage::kPhase5C;
}

void SignSession::VerifyPhase5DAndAdvanceToStage5E() {
  std::vector<ECPoint> u_points;
  std::vector<ECPoint> t_points;
  u_points.reserve(participants_.size());
  t_points.reserve(participants_.size());

  for (PartyIndex party : participants_) {
    const auto open_it = phase5d_open_data_.find(party);
    if (open_it == phase5d_open_data_.end()) {
      Abort("missing phase5D open data");
      return;
    }
    u_points.push_back(open_it->second.U_i);
    t_points.push_back(open_it->second.T_i);
  }

  try {
    const ECPoint sum_u = SumPointsOrThrow(u_points);
    const ECPoint sum_t = SumPointsOrThrow(t_points);
    if (sum_u != sum_t) {
      Abort("phase5D consistency check failed");
      return;
    }
  } catch (const std::exception& ex) {
    Abort(std::string("failed to validate phase5D consistency: ") + ex.what());
    return;
  }

  phase5_stage_ = SignPhase5Stage::kPhase5E;
}

void SignSession::FinalizeSignatureAndComplete() {
  Scalar s;
  for (PartyIndex party : participants_) {
    const auto s_it = phase5e_revealed_s_.find(party);
    if (s_it == phase5e_revealed_s_.end()) {
      Abort("missing phase5E revealed share");
      return;
    }
    s = s + s_it->second;
  }

  if (s.value() == 0) {
    Abort("aggregated signature scalar s is zero");
    return;
  }

  Scalar canonical_s = s;
  if (IsHighScalar(canonical_s)) {
    canonical_s = Scalar() - canonical_s;
  }

  if (!VerifyEcdsaSignature(public_key_y_, msg32_, r_, canonical_s)) {
    Abort("final ECDSA signature verification failed");
    return;
  }

  s_ = canonical_s;
  result_.r = r_;
  result_.s = s_;
  result_.R = R_;
  result_.local_w_i = local_w_i_;
  result_.lagrange_coefficients = lagrange_coefficients_;
  result_.w_shares = w_shares_;
  result_.W_points = W_points_;
  has_result_ = true;

  phase5_stage_ = SignPhase5Stage::kCompleted;
  phase_ = SignPhase::kCompleted;
  Complete();
}

void SignSession::MaybeAdvanceAfterPhase1() {
  if (phase_ != SignPhase::kPhase1) {
    return;
  }
  if (!local_phase1_ready_) {
    return;
  }
  if (seen_phase1_.size() != peers_.size()) {
    return;
  }
  if (phase1_commitments_.size() != participants_.size()) {
    return;
  }
  phase_ = SignPhase::kPhase2;
}

void SignSession::MaybeAdvanceAfterPhase2() {
  if (phase_ != SignPhase::kPhase2) {
    return;
  }
  if (!local_phase2_ready_) {
    return;
  }
  if (seen_phase2_.size() != peers_.size()) {
    return;
  }
  if (phase2_received_shares_.size() != participants_.size()) {
    return;
  }
  phase_ = SignPhase::kPhase3;
}

void SignSession::MaybeAdvanceAfterPhase3() {
  if (phase_ != SignPhase::kPhase3) {
    return;
  }
  if (!local_phase3_ready_) {
    return;
  }
  if (seen_phase3_.size() != peers_.size()) {
    return;
  }
  if (phase3_delta_shares_.size() != participants_.size()) {
    return;
  }
  ComputeDeltaInverseAndAdvanceToPhase4();
}

void SignSession::MaybeAdvanceAfterPhase4() {
  if (phase_ != SignPhase::kPhase4) {
    return;
  }
  if (!local_phase4_ready_) {
    return;
  }
  if (seen_phase4_.size() != peers_.size()) {
    return;
  }
  if (phase4_open_data_.size() != participants_.size()) {
    return;
  }
  ComputeRAndAdvanceToPhase5();
}

void SignSession::MaybeAdvanceAfterPhase5A() {
  if (phase_ != SignPhase::kPhase5 || phase5_stage_ != SignPhase5Stage::kPhase5A) {
    return;
  }
  if (!local_phase5a_ready_) {
    return;
  }
  if (seen_phase5a_.size() != peers_.size()) {
    return;
  }
  if (phase5a_commitments_.size() != participants_.size()) {
    return;
  }
  phase5_stage_ = SignPhase5Stage::kPhase5B;
}

void SignSession::MaybeAdvanceAfterPhase5B() {
  if (phase_ != SignPhase::kPhase5 || phase5_stage_ != SignPhase5Stage::kPhase5B) {
    return;
  }
  if (!local_phase5b_ready_) {
    return;
  }
  if (seen_phase5b_.size() != peers_.size()) {
    return;
  }
  if (phase5b_open_data_.size() != participants_.size()) {
    return;
  }
  ComputePhase5VAAndAdvanceToStage5C();
}

void SignSession::MaybeAdvanceAfterPhase5C() {
  if (phase_ != SignPhase::kPhase5 || phase5_stage_ != SignPhase5Stage::kPhase5C) {
    return;
  }
  if (!local_phase5c_ready_) {
    return;
  }
  if (seen_phase5c_.size() != peers_.size()) {
    return;
  }
  if (phase5c_commitments_.size() != participants_.size()) {
    return;
  }
  phase5_stage_ = SignPhase5Stage::kPhase5D;
}

void SignSession::MaybeAdvanceAfterPhase5D() {
  if (phase_ != SignPhase::kPhase5 || phase5_stage_ != SignPhase5Stage::kPhase5D) {
    return;
  }
  if (!local_phase5d_ready_) {
    return;
  }
  if (seen_phase5d_.size() != peers_.size()) {
    return;
  }
  if (phase5d_open_data_.size() != participants_.size()) {
    return;
  }
  VerifyPhase5DAndAdvanceToStage5E();
}

void SignSession::MaybeAdvanceAfterPhase5E() {
  if (phase_ != SignPhase::kPhase5 || phase5_stage_ != SignPhase5Stage::kPhase5E) {
    return;
  }
  if (!local_phase5e_ready_) {
    return;
  }
  if (seen_phase5e_.size() != peers_.size()) {
    return;
  }
  if (phase5e_revealed_s_.size() != participants_.size()) {
    return;
  }
  FinalizeSignatureAndComplete();
}

}  // namespace tecdsa
