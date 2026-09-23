#pragma once

// Group delivery wire contract (docs/design/sdk-v1/group-delivery.md,
// docs/spec/wire-protocol.md "GROUP_DATA / GROUP_REPORT").
//
// Addressing. A group is named by a 16-bit GroupId. On the wire the GROUP_DATA
// destination field carries the group ADDRESS kGroupAddressBase | group_id;
// group 0xFFFF (kGroupAll) therefore maps to kBroadcastNodeId. Node ids at or
// above kGroupAddressBase are reserved for group addresses: a node may never
// be configured with one (MeshNode::validate_config). Group id 0 is reserved.
//
// GROUP_DATA (frame type 25) is end-protected under SecurityScope::Group
// (sender = origin, receiver = group address) and link-protected per hop. Its
// MessageId sequence carries the source's GROUP STREAM number with the top
// bit set (kGroupSequenceFlag): the stream number is visible (and end-AAD
// authenticated) in the header, so every node can deduplicate and order a
// group message before opening it, and a group MessageId can never equal a
// unicast MessageId from the same session. End-protected payload:
//   flags u8 | application payload (<= kGroupPayloadMax bytes)
// flags: bit0 ORDERED, bits1-2 Priority (0 Bulk .. 3 Urgent), bits3-7 zero.
//
// GROUP_REPORT (frame type 26) is link-only and one hop (child -> tree
// parent, hop_remaining 1, destination == next_hop), like ROUTE_UPDATE.
// Fixed 29-byte head + missing_count x u64, big-endian:
//   source u64 | session u32 | sequence u64 | round u8 | flags u8 |
//   delivered u16 | nonmember u16 | missing_total u16 | missing_count u8 |
//   missing ids (missing_count x u64, <= kGroupReportMissingMax)
// flags: bit0 NOT_CHILD (the sender already follows another tree parent for
// this message: all counts 0), bit1 TRUNCATED (missing_total >
// missing_count), bits2-7 zero.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

using GroupId = std::uint16_t;

constexpr GroupId kGroupAll = 0xFFFF;
constexpr NodeId kGroupAddressBase = 0xFFFFFFFFFFFF0000ULL;
static_assert((kGroupAddressBase | kGroupAll) == kBroadcastNodeId,
              "the ALL group address is the broadcast node id");

constexpr NodeId group_address(const GroupId group) noexcept {
  return kGroupAddressBase | group;
}
// Group 0 is reserved: its address (the base itself) is not a group address.
constexpr bool is_group_address(const NodeId node) noexcept {
  return node > kGroupAddressBase;
}
constexpr GroupId group_of_address(const NodeId address) noexcept {
  return static_cast<GroupId>(address & 0xFFFFU);
}
// Node ids a device may never carry: the invalid id and the group namespace.
constexpr bool reserved_node_id(const NodeId node) noexcept {
  return node == kInvalidNodeId || node >= kGroupAddressBase;
}

// Top bit of a group MessageId sequence: marks the group stream space.
constexpr std::uint64_t kGroupSequenceFlag = 1ULL << 63;
// Group stream numbers are u32 on the source side (per boot session).
constexpr bool is_group_sequence(const std::uint64_t sequence) noexcept {
  return (sequence & kGroupSequenceFlag) != 0 &&
         (sequence & ~kGroupSequenceFlag) != 0 &&
         (sequence & ~kGroupSequenceFlag) <= UINT32_MAX;
}
constexpr std::uint32_t group_stream_seq(const std::uint64_t sequence) noexcept {
  return static_cast<std::uint32_t>(sequence & ~kGroupSequenceFlag);
}

// GROUP_DATA delivery_round (hop-mutable header byte): bits 0-6 the round
// number (0 = first propagation, >0 = repair), bit 7 REFRESH — the source
// found its tree accounting inconsistent (nodes moved between subtrees), so
// every relay re-sends this round to ALL its children and every subtree is
// reported fresh instead of from stored per-child counts. GROUP_REPORT's
// round field carries the round number only (bit 7 clear).
constexpr std::uint8_t kGroupRoundRefresh = 0x80;
constexpr std::uint8_t kGroupRoundMask = 0x7F;

// --- GROUP_DATA payload ------------------------------------------------------
constexpr std::size_t kGroupDataHeaderBytes = 1;
constexpr std::size_t kGroupPayloadMax = kMaxApplicationPayload - kGroupDataHeaderBytes;
static_assert(kGroupPayloadMax == 127, "GROUP_DATA carries 127 application bytes");
constexpr std::uint8_t kGroupFlagOrdered = 0x01;
constexpr std::uint8_t kGroupPriorityShift = 1;
constexpr std::uint8_t kGroupPriorityMask = 0x06;
constexpr std::uint8_t kGroupDataFlagsKnown = kGroupFlagOrdered | kGroupPriorityMask;

struct GroupDataHeader {
  bool ordered{false};
  Priority priority{Priority::Normal};
};

// Writes flags || app into `out`; `written` receives the total size.
Status encode_group_data(const GroupDataHeader& header, ByteView app, MutableByteView out,
                         std::size_t& written) noexcept;
// Strict decode: at least the flags byte, no reserved flag bits. `app` views
// the application bytes inside `input`.
Status decode_group_data(ByteView input, GroupDataHeader& header, ByteView& app) noexcept;

// --- GROUP_REPORT payload ----------------------------------------------------
constexpr std::size_t kGroupReportFixedBytes = 8 + 4 + 8 + 1 + 1 + 2 + 2 + 2 + 1;
static_assert(kGroupReportFixedBytes == 29, "GROUP_REPORT head is 29 bytes");
constexpr std::size_t kGroupReportMissingMax = 12;
static_assert(kGroupReportFixedBytes + kGroupReportMissingMax * 8 <= kMaxApplicationPayload,
              "a full GROUP_REPORT fits the 128-byte payload");
constexpr std::uint8_t kGroupReportNotChild = 0x01;
constexpr std::uint8_t kGroupReportTruncated = 0x02;
constexpr std::uint8_t kGroupReportFlagsKnown = kGroupReportNotChild | kGroupReportTruncated;

struct GroupReportPayload {
  MessageKey key{};  // {source, group MessageId}
  std::uint8_t round{0};
  std::uint8_t flags{0};
  std::uint16_t delivered{0};
  std::uint16_t nonmember{0};
  std::uint16_t missing_total{0};
  std::uint8_t missing_count{0};
  std::array<NodeId, kGroupReportMissingMax> missing{};
};

// Encodes kGroupReportFixedBytes + 8 * missing_count bytes. Refuses a payload
// its own decoder would reject (flag/count consistency, reserved ids).
Status encode_group_report(const GroupReportPayload& payload, MutableByteView out,
                           std::size_t& written) noexcept;
// Strict decode: exact length for missing_count, group-stream sequence,
// non-reserved source and ids, known flags, NOT_CHILD carries zero counts,
// TRUNCATED set exactly when missing_total > missing_count.
Status decode_group_report(ByteView input, GroupReportPayload& payload) noexcept;

}  // namespace routeloom
