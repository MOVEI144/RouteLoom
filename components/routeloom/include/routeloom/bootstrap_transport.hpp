#pragma once

// Routed member-session bootstrap (G-SEC P4 §7.3-§7.4, PR3): the Wire
// type-3..6 lane that carries join-relay objects AND member end-session
// (purpose 2) handshake objects between Members.
//
// Wire v2 header/type numbers are untouched: end objects ride single
// type-3 frames, longer ones ride type-5 chunks with the lane-separated
// sub 0x80|(phase<<4)|step and type-6 replies (see ObjectLane in
// sdkv1_join_transport.hpp). Type 4 stays join-relay Final/Abort only.
// Every hop protects the frame with its own established link session;
// hop authentication is NOT origin authentication — only the terminal
// EDHOC/resume verification proves the origin.
//
// This header owns the end-object envelope codec, the Node sink/port
// interfaces, the purpose-split responder rate budgets and the
// session-bank demand driver. The SecurityCoordinator (PR4) owns the
// instances and pairs link demands with discovery candidates. No heap,
// no exceptions; every entry is noexcept.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/sdkv1_handshake.hpp"
#include "routeloom/sdkv1_join_transport.hpp"
#include "routeloom/security.hpp"
#include "routeloom/session_bank.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom::sdkv1 {

// --- End object envelope (P4 §7.3) ------------------------------------------------------
// 12 B header + message:
//   0 ver=1 u8 | 1 phase=4/5 u8 | 2 step u8 | 3 flags=0 u8 |
//   4 exchange_id u32 (nonzero) | 8 purpose=2 u8 | 9 profile=1/2 u8 |
//   10 message_len u16 | 12 message[1..960]
constexpr std::uint8_t kEndObjectVersion = 1;
constexpr std::size_t kEndObjectHeaderSize = 12;
constexpr std::size_t kEndObjectMax = kEndObjectHeaderSize + kJoinMessageMax;  // 972
constexpr std::uint8_t kEndProfileMember = 1;
constexpr std::uint8_t kEndProfileDev = 2;
static_assert(kEndObjectMax <= kJoinObjectMax, "end object fits one object slot");

struct EndObject {
  JoinAuthPhase phase{JoinAuthPhase::EdhocMessage};
  std::uint8_t step{1};
  std::uint32_t exchange_id{0};
  std::uint8_t profile{kEndProfileMember};
  ByteView message{};
};

Status end_object_validate(const EndObject& object) noexcept;
std::size_t end_object_encoded_size(const EndObject& object) noexcept;
Status end_object_encode(const EndObject& object, MutableByteView out,
                         std::size_t& written) noexcept;
Status end_object_decode(ByteView encoded, EndObject& out) noexcept;

// Single-frame carriage: an end object that fits one Wire payload rides
// FrameType 3 (BootstrapAuth) like a join-relay Continue; larger objects
// ride FrameType 5 chunks (end-lane sub, id = exchange_id) with FrameType
// 6 replies. FrameType 4 is never an end object.
constexpr FrameType kEndSingleFrameType = FrameType::BootstrapAuth;
Status end_single_frame_decode(FrameType type, ByteView payload, EndObject& out) noexcept;

// --- Node sink/port (P4 §7.4) -------------------------------------------------------------
// What the terminal learns about a type-3..6 frame. `previous_hop` delivered
// a link-authenticated frame — that fact says nothing about `origin`, which
// stays an unverified claim until the handshake engine accepts it.
struct BootstrapMeta {
  NodeId origin{kInvalidNodeId};
  NodeId destination{kInvalidNodeId};
  MessageId id{};
  NodeId previous_hop{kInvalidNodeId};
  std::uint8_t hop_remaining{0};
  std::uint32_t remaining_deadline_ms{0};
};

class BootstrapSink {
 public:
  virtual ~BootstrapSink() = default;
  // One terminal type-3..6 payload. Must not call back into the Node
  // (no re-entry): the Owner queues whatever the payload requires.
  virtual Status on_frame(const BootstrapMeta& meta, FrameType type, ByteView payload,
                          MonotonicMs now_ms) noexcept = 0;
};

class BootstrapPort {
 public:
  virtual ~BootstrapPort() = default;
  // One routed bootstrap frame (types 3..6): bounded management work on the
  // Node, link-protected per hop, forwarded only by Relay/Gateway members.
  virtual Status send(NodeId destination, FrameType type, ByteView payload,
                      std::uint32_t lifetime_ms, MonotonicMs now_ms) noexcept = 0;
};

// --- Responder rate budgets (P4 §7.4) ------------------------------------------------------
// Purpose-split token buckets in front of the single handshake engine: link
// resume admits 1 start/s, end (gateway) resume 10 starts/s with a burst of
// 4. These gate the START rate; concurrency stays with the engines (the
// shared rlres1::Engine caps I/R at 4 each, EDHOC at one flight per 2 s).
// Saturating arithmetic; a backwards clock refuses without consuming.
class BootstrapBudgets {
 public:
  static constexpr std::uint32_t kLinkResumePerSecond = 1;
  static constexpr std::uint32_t kEndResumePerSecond = 10;
  static constexpr std::uint32_t kEndResumeBurst = 4;

  BootstrapBudgets() noexcept = default;
  BootstrapBudgets(const BootstrapBudgets&) = delete;
  BootstrapBudgets& operator=(const BootstrapBudgets&) = delete;

  bool admit_link_resume(MonotonicMs now_ms) noexcept;
  bool admit_end_resume(MonotonicMs now_ms) noexcept;

 private:
  void refill(std::uint32_t& tokens, std::uint32_t rate_per_s, std::uint32_t burst,
              bool& started, MonotonicMs& last_ms, MonotonicMs now_ms) noexcept;

  std::uint32_t link_tokens_{kLinkResumePerSecond};
  std::uint32_t end_tokens_{kEndResumeBurst};
  // Separate clocks: admitting one purpose must not steal elapsed refill
  // time from the other.
  MonotonicMs last_link_ms_{0};
  MonotonicMs last_end_ms_{0};
  bool link_started_{false};
  bool end_started_{false};
};

// --- Session demand driver (PR3: Session需要駆動) -------------------------------------------
// Turns SessionBank establishment demands into HandshakeEngine requests.
// End demands carry everything the engine needs and are requested inline;
// link demands need the Owner's discovery candidate (frozen DISCOVER/OFFER
// carrier), so they wait in a bounded pending list for take_link_demand().
// One driver per Owner; the bank and engine stay owned by the Coordinator.
template <std::size_t kLinkCapacity, std::size_t kEndCapacity>
class BootstrapDemandDriver {
 public:
  static constexpr std::size_t kPendingLinkDemands = 8;

  explicit BootstrapDemandDriver(SessionBank<kLinkCapacity, kEndCapacity>& bank,
                                 HandshakeEngine& engine) noexcept
      : bank_(bank), engine_(engine) {}

  BootstrapDemandDriver(const BootstrapDemandDriver&) = delete;
  BootstrapDemandDriver& operator=(const BootstrapDemandDriver&) = delete;

  // Drains every queued demand: end demands become engine requests
  // (returns the first engine refusal, if any, after draining the rest);
  // link demands move to the pending list (a full list keeps the demand
  // in the bank for the next poll — nothing is dropped silently).
  Status poll(MonotonicMs now_ms) noexcept {
    Status first_error = Status::success();
    for (;;) {
      SessionDemand demand{};
      if (!bank_.take_demand(demand)) break;
      if (demand.scope == SecurityScope::EndToEnd) {
        HandshakeRequest req{};
        req.scope = SecurityScope::EndToEnd;
        req.peer = demand.peer;
        req.reason = HandshakeReason::Initial;
        const Status requested = engine_.request(req, now_ms);
        if (!requested && first_error) first_error = requested;
      } else if (!stash_link(demand)) {
        // Pending list full: push the demand back and stop, so order is
        // preserved and nothing is dropped silently.
        bank_.note_demand(demand.scope, demand.peer);
        break;
      }
    }
    return first_error;
  }

  // Pops one pending link demand for the Owner to pair with discovery.
  // NotFound when empty.
  Status take_link_demand(SessionDemand& out) noexcept {
    for (std::size_t i = 0; i < pending_count_; ++i) {
      out = pending_[i];
      for (std::size_t j = i; j + 1 < pending_count_; ++j) pending_[j] = pending_[j + 1];
      --pending_count_;
      return Status::success();
    }
    return Status::error(StatusCode::NotFound, "no link demand");
  }

  std::size_t pending_link_count() const noexcept { return pending_count_; }

 private:
  bool stash_link(const SessionDemand& demand) noexcept {
    for (std::size_t i = 0; i < pending_count_; ++i) {
      if (pending_[i].peer == demand.peer) {
        pending_[i].deadline_ms = demand.deadline_ms;
        return true;
      }
    }
    if (pending_count_ >= kPendingLinkDemands) return false;
    pending_[pending_count_++] = demand;
    return true;
  }

  SessionBank<kLinkCapacity, kEndCapacity>& bank_;
  HandshakeEngine& engine_;
  std::array<SessionDemand, kPendingLinkDemands> pending_{};
  std::size_t pending_count_{0};
};

}  // namespace routeloom::sdkv1
