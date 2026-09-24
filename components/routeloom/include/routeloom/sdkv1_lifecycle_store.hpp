#pragma once

// RLX1 removal intent: a sealed, sequenced two-slot journal. A durable
// Removing record is the authority to resume erasure after a power cut;
// neither an empty RLS1 nor an untrusted hint is such authority.
#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/sdkv1_ead.hpp"
#include "routeloom/sdkv1_store.hpp"

namespace routeloom::sdkv1 {

constexpr std::uint32_t kLifecycleMagic = 0x524C5831U;
constexpr std::uint32_t kLifecycleSeal = 0x4C583101U;
constexpr std::size_t kLifecycleSlotBytes = 2048;
// Switching carries new RLS1, signed new RRS1 and CutoverCommit in one
// durable intent; the maximum sealed record is 1609 B.
constexpr std::size_t kLifecyclePayloadMax = 1521;

enum class LifecycleMode : std::uint8_t {
  Idle = 0, Removing = 1, Holdoff = 2, UnassignedReady = 3,
  Prepared = 4, Switching = 5, Recovering = 6,
};

struct LifecycleRecord {
  LifecycleMode mode{LifecycleMode::Idle};
  NodeId self{kInvalidNodeId};
  std::uint64_t site_id{0};
  NetworkId old_network{0};
  NetworkId new_network{0};
  std::uint32_t generation{0};
  std::uint32_t rs_floor{0};
  std::uint32_t gk_floor{0};
  std::uint32_t boot_witness{0};
  std::uint64_t cutover_id{0};
  std::uint32_t revision{0};
  ByteBuffer<kLifecyclePayloadMax> payload{};
};

Status lifecycle_record_encode(const LifecycleRecord& record, std::uint32_t seal,
                               std::uint32_t seq, ByteBuffer<kLifecycleSlotBytes>& out) noexcept;
Status lifecycle_record_decode(ByteView bytes, LifecycleRecord& out) noexcept;
const SealedRecordFormat& lifecycle_record_format() noexcept;

class LifecycleStore final {
 public:
  explicit LifecycleStore(RecordSlotStorage& storage) noexcept;
  Status initialize() noexcept;
  // Only a verified Notice, bound to the current RLS1, may create intent.
  Status begin_removal(const LifecycleRecord& record) noexcept;
  // Caller has verified the CA/SAK chain and the complete binding before
  // staging. Neither call changes the active RLS1 by itself.
  Status prepare(const LifecycleRecord& record) noexcept;
  Status switch_network(const LifecycleRecord& record) noexcept;
  // Retain the nonsecret COMMIT digest and operation watermark so APPLIED can
  // be retried after a cold boot without retaining staged credentials.
  Status finish_switch(const Digest256& commit_digest) noexcept;
  // Re-twin an adopted secret-free watermark after a torn twin write.
  Status scrub_idle() noexcept;
  bool stale_sibling() const noexcept { return pair_.stale_sibling(); }
  Status resume_switch(const LifecycleRecord& verified) noexcept;
  Status holdoff() noexcept;
  Status unassigned_ready() noexcept;
  // A valid Removing/Holdoff survivor may repair a known corrupt sibling,
  // but only after the caller has reverified the signed payload and binding.
  Status resume_removal(const LifecycleRecord& verified) noexcept;
  bool has_record() const noexcept { return pair_.has_active(); }
  bool quarantined() const noexcept { return pair_.quarantined(); }
  bool uncertain() const noexcept { return pair_.uncertain(); }
  bool unknown_sibling() const noexcept {
    return pair_.slot_unsupported(0) || pair_.slot_unsupported(1) ||
           pair_.slot_unreadable(0) || pair_.slot_unreadable(1);
  }
  const LifecycleRecord& record() const noexcept { return record_; }
  std::uint32_t commit_seq() const noexcept { return pair_.active_seq(); }

 private:
  Status commit(const LifecycleRecord& record, bool twin) noexcept;
  ByteBuffer<kLifecycleSlotBytes> scratch_{};
  LifecycleRecord record_{};
  SealedSlotPair pair_;
};

}  // namespace routeloom::sdkv1
