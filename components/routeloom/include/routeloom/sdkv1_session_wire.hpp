#pragma once

// Member session wire codecs (G-SEC P4 §5.1/§5.3/§5.4, link half): the
// session EAD values, the 15-element Exporter context, and the RLD1
// capability bits. Link and end sessions share these; the routed end
// envelope is PR3.
//
// Layouts are fixed-width big-endian exactly as §5.3 pins them (the C++,
// Rust and Python implementations must agree on every byte, see
// protocol/sdkv1-golden/session/): ver u8=1, purpose u8 (1 link, 2 end),
// profile u8 (=1 production member; the DevRam profile byte 2 is PR6),
// flags u8=0, then the item body. Unknown versions/flags, duplicate or
// out-of-order items are refused by the decoders and the engine's EAD
// handler — never skipped.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom::sdkv1 {

// --- RLD1 capability bits (P4 §5.1) -----------------------------------------------
// Reserved upper bits of the RLD1 capability word (a different namespace
// from the USB JoinRelay bits). Bit 24 is the EDHOC floor: a member link
// whose ends cannot both confirm it is Unsupported. Bit 25 offers resume;
// bit 26 selects the DevRam session profile (PR6) and never mixes with a
// production (profile 1) exchange.
constexpr std::uint32_t kRld1CapMemberEdhocV1 = 1U << 24;
constexpr std::uint32_t kRld1CapMemberResumeV1 = 1U << 25;
constexpr std::uint32_t kRld1CapDevRamSessionV1 = 1U << 26;
// The P4-reserved bits a disclosed word must repeat from the frozen
// DISCOVER/OFFER exchange; every other bit is a selection hint.
constexpr std::uint32_t kRld1CapP4Mask =
    kRld1CapMemberEdhocV1 | kRld1CapMemberResumeV1 | kRld1CapDevRamSessionV1;

// --- Session EAD values (member profile, P4 §5.3) ----------------------------------
// EAD labels (critical): SessionIntent -65542, SessionState -65543,
// ContextConfirm -65544. Values are fixed-width big-endian; the EDHOC
// transport wraps them as opaque EAD values (never CBOR-encoded twice).
constexpr std::int32_t kEadSessionIntent = -65542;
constexpr std::int32_t kEadSessionState = -65543;
constexpr std::int32_t kEadContextConfirm = -65544;
constexpr std::size_t kSessionIntentBytes = 44;
constexpr std::size_t kSessionStateBytes = 24;
constexpr std::size_t kContextConfirmBytes = 36;
// Session profile byte: 1 = member production protocol (P4 §5.1). The
// security_profile() certification enum is a different axis: profile 1
// still reports Development/EXPERIMENTAL until P8 certifies it.
constexpr std::uint8_t kSessionProfileMember = 1;
constexpr std::uint8_t kSessionPurposeLink = 1;
constexpr std::uint8_t kSessionPurposeEnd = 2;

// SessionIntent (m1): ver | purpose | profile | flags | caps_I u32 |
// boot_I u32 (nonzero) | binding 32B. The initiator's offer: which
// carrier it answers (binding) and the capability/boot word its m3
// State must repeat.
struct SessionIntent {
  std::uint8_t purpose{0};  // 1 link, 2 end
  std::uint8_t profile{0};  // 1 member production
  std::uint32_t caps_i{0};
  std::uint32_t boot_i{0};
  std::array<std::uint8_t, 32> binding{};
};

// SessionState (m2/m3): ver | purpose | profile | flags | site_epoch u32
// | rs_epoch u32 | gk_epoch u32 | boot u32 (nonzero) | caps u32. The
// side's disclosed epochs; site_epoch must equal the adopted full
// network's upper half and the side's credential site.
struct SessionState {
  std::uint8_t purpose{0};
  std::uint8_t profile{0};
  std::uint32_t site_epoch{0};
  std::uint32_t rs_epoch{0};
  std::uint32_t gk_epoch{0};
  std::uint32_t boot{0};
  std::uint32_t caps{0};
};

// ContextConfirm (m3/m4): ver | purpose | profile | flags |
// contexts_digest 32B. Proves both ends derived identical Exporter
// contexts (P4 §5.4); the digest already binds nodes, kids, roles and
// generations, so the item names nobody.
struct ContextConfirm {
  std::uint8_t purpose{0};
  std::uint8_t profile{0};
  std::array<std::uint8_t, 32> contexts_digest{};
};

Status session_intent_encode(const SessionIntent& intent,
                             std::array<std::uint8_t, kSessionIntentBytes>& out) noexcept;
Status session_intent_decode(ByteView bytes, SessionIntent& out) noexcept;
Status session_state_encode(const SessionState& state,
                            std::array<std::uint8_t, kSessionStateBytes>& out) noexcept;
Status session_state_decode(ByteView bytes, SessionState& out) noexcept;
Status context_confirm_encode(const ContextConfirm& confirm,
                              std::array<std::uint8_t, kContextConfirmBytes>& out) noexcept;
Status context_confirm_decode(ByteView bytes, ContextConfirm& out) noexcept;

// --- Exporter application context (P4 §5.4) -----------------------------------------
// The 15-element definite-length CBOR array, shortest-form ints:
// ["RouteLoom", 1, purpose, full_network, node_I, node_R, kid_I:bstr32,
//  kid_R:bstr32, role_I:u32, role_R:u32, [gen_I, gen_R], [2, 0],
//  context_epoch:u32, direction:u8, capability_digest:bstr32]
// context_epoch is the receiver-chosen EDHOC connection id of the
// direction (C_R for I->R, C_I for R->I); direction is 1 (I->R), 2
// (R->I), or 0 (RMS, epoch 0). Encodes under 256 B (NoCapacity past).
struct ExporterContextParams {
  std::uint8_t purpose{0};
  NetworkId network{0};
  NodeId node_i{kInvalidNodeId};
  NodeId node_r{kInvalidNodeId};
  std::array<std::uint8_t, 32> kid_i{};
  std::array<std::uint8_t, 32> kid_r{};
  std::uint32_t role_i{0};
  std::uint32_t role_r{0};
  std::uint32_t generation_i{0};
  std::uint32_t generation_r{0};
  std::uint32_t context_epoch{0};
  std::uint8_t direction{0};
  std::array<std::uint8_t, 32> capability_digest{};
};
constexpr std::size_t kExporterContextMax = 256;
Status exporter_context_encode(const ExporterContextParams& params,
                               std::array<std::uint8_t, kExporterContextMax>& out,
                               std::size_t& used) noexcept;

// EDHOC-Exporter KDF info (RFC 9528 §4.1), for the vector cross-check:
// uint(label) || bstr(context_bytes) || uint(length). The live agreement
// of libedhoc's own exporter is proven by exchange tests, not here.
constexpr std::size_t kEdhocKdfInfoMax = 320;
Status edhoc_kdf_info_encode(std::uint32_t label, ByteView context, std::uint32_t length,
                             std::array<std::uint8_t, kEdhocKdfInfoMax>& out,
                             std::size_t& used) noexcept;

// --- Member link policy ----------------------------------------------------------------
// The member profile mandates the cookie on the first step of each
// exchange (EDHOC m1, RLRES1 R1); later steps bind through the running
// transcript instead. (phase, step) share the join-transport object
// codec, validated by join_step_valid — no second framing.
constexpr bool member_cookie_required(const std::uint8_t phase, const std::uint8_t step) noexcept {
  return (phase == 4 && step == 1) || (phase == 5 && step == 1);
}

}  // namespace routeloom::sdkv1
