#pragma once

#include <chrono>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "tecdsa/crypto/ec_point.hpp"
#include "tecdsa/crypto/scalar.hpp"
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
  kPhase2Share = 1004,
  kAbort = 1099,
};

struct KeygenSessionConfig {
  Bytes session_id;
  PartyIndex self_id = 0;
  std::vector<PartyIndex> participants;
  uint32_t threshold = 1;
  std::chrono::milliseconds timeout = std::chrono::seconds(30);
};

struct SchnorrProof {
  ECPoint a;
  Scalar z;
};

struct KeygenResult {
  Scalar x_i;
  ECPoint X_i;
  ECPoint y;
  std::unordered_map<PartyIndex, ECPoint> all_X_i;
};

class KeygenSession : public Session {
 public:
  explicit KeygenSession(KeygenSessionConfig cfg);

  KeygenPhase phase() const;
  size_t received_peer_count_in_phase() const;
  uint32_t threshold() const;

  bool HandleEnvelope(const Envelope& envelope);
  Envelope MakePhaseBroadcastEnvelope(const Bytes& payload) const;
  Envelope BuildPhase1CommitEnvelope();
  std::vector<Envelope> BuildPhase2OpenAndShareEnvelopes();
  Envelope BuildPhase3XiProofEnvelope();

  bool HasResult() const;
  const KeygenResult& result() const;

  static uint32_t MessageTypeForPhase(KeygenPhase phase);
  static uint32_t Phase2ShareMessageType();

 private:
  struct Phase2OpenData {
    ECPoint y_i;
    Bytes randomness;
    std::vector<ECPoint> commitments;
  };

  struct Phase3BroadcastData {
    ECPoint X_i;
    SchnorrProof proof;
  };

  void EnsureLocalPolynomialPrepared();
  bool HandlePhase1CommitEnvelope(const Envelope& envelope);
  bool HandlePhase2OpenEnvelope(const Envelope& envelope);
  bool HandlePhase2ShareEnvelope(const Envelope& envelope);
  bool HandlePhase3XiProofEnvelope(const Envelope& envelope);

  bool VerifyDealerShareForSelf(PartyIndex dealer, const Scalar& share) const;
  void MaybeAdvanceAfterPhase1();
  void MaybeAdvanceAfterPhase2();
  void MaybeAdvanceAfterPhase3();
  void ComputePhase2Aggregates();
  SchnorrProof BuildSchnorrProof(const ECPoint& statement, const Scalar& witness) const;
  bool VerifySchnorrProof(PartyIndex prover_id,
                          const ECPoint& statement,
                          const SchnorrProof& proof) const;

  std::vector<PartyIndex> participants_;
  uint32_t threshold_ = 1;
  std::unordered_set<PartyIndex> peers_;

  std::unordered_set<PartyIndex> seen_phase1_;
  std::unordered_set<PartyIndex> seen_phase2_opens_;
  std::unordered_set<PartyIndex> seen_phase2_shares_;
  std::unordered_set<PartyIndex> seen_phase3_;

  bool local_phase2_ready_ = false;
  bool local_phase3_ready_ = false;

  std::vector<Scalar> local_poly_coefficients_;
  std::unordered_map<PartyIndex, Scalar> local_shares_;
  ECPoint local_y_i_;
  Bytes local_commitment_;
  Bytes local_open_randomness_;
  std::vector<ECPoint> local_vss_commitments_;
  std::optional<Phase3BroadcastData> local_phase3_payload_;

  std::unordered_map<PartyIndex, Bytes> phase1_commitments_;
  std::unordered_map<PartyIndex, Phase2OpenData> phase2_open_data_;
  std::unordered_map<PartyIndex, Scalar> pending_phase2_shares_;
  std::unordered_map<PartyIndex, Scalar> phase2_verified_shares_;
  std::unordered_map<PartyIndex, Phase3BroadcastData> phase3_broadcasts_;

  bool phase2_aggregates_ready_ = false;
  KeygenResult result_;
  KeygenPhase phase_ = KeygenPhase::kPhase1;
};

}  // namespace tecdsa
