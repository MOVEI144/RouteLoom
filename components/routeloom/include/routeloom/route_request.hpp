#pragma once

// ROUTE_REQUEST (frame type 35) payload codec — gateway-scoped routing
// profile (docs/design/sdk-v1/routing-scale.md §4, docs/spec/wire-protocol.md).
//
// The frame is link-protected only (like ROUTE_UPDATE / SEQNO_REQUEST): one
// hop, destination == next_hop == the receiving neighbor, hop_remaining = 1.
// Multi-hop kinds are re-originated hop by hop; the TTL lives in the payload.
//
// Fixed 38-byte big-endian layout:
//   kind u8 | ttl u8 | requester u64 | target u64 | request_id u32 |
//   record: destination u64 | generation u32 | sequence u16 | metric u16
//
// The embedded record has exactly the ROUTE_UPDATE record layout and
// semantics: the receiver feeds it to RouteTable::consider() with the sending
// neighbor as next hop, and the sender runs mark_advertised() before any
// finite record leaves. ROUTE_REQUEST therefore never bypasses feasibility.

#include <cstddef>
#include <cstdint>

#include "routeloom/routing.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

enum class RouteRequestKind : std::uint8_t {
  // 1-hop pull: "send me your route to `target` now". record = the
  // requester's own self record (metric 0). ttl must be 1.
  Neighbor = 1,
  // Multi-hop on-demand discovery toward `target`. record = the sender's
  // selected route to `requester` (the reverse route being built).
  Discover = 2,
  // Multi-hop answer travelling the recorded reverse path back to
  // `requester`. record = the sender's selected route to `target`.
  Reply = 3,
};

constexpr std::size_t kRouteRequestPayloadBytes = 1 + 1 + 8 + 8 + 4 + kRouteUpdateRecordBytes;
static_assert(kRouteRequestPayloadBytes == 38, "ROUTE_REQUEST payload is 38 bytes");
// Multi-hop kinds never travel further than the wireless hop limit.
constexpr std::uint8_t kRouteRequestMaxTtl = kDefaultHopLimit;

struct RouteRequestPayload {
  RouteRequestKind kind{RouteRequestKind::Neighbor};
  std::uint8_t ttl{1};
  NodeId requester{kInvalidNodeId};
  NodeId target{kInvalidNodeId};
  std::uint32_t request_id{0};
  RouteAdvertisement record{};
};

// Encodes exactly kRouteRequestPayloadBytes; `written` receives the size.
Status encode_route_request(const RouteRequestPayload& payload, MutableByteView out,
                            std::size_t& written) noexcept;
// Strict decode: exact length, known kind, ttl in 1..kRouteRequestMaxTtl
// (Neighbor: exactly 1), non-reserved node ids, and the record destination
// bound to the kind (Neighbor/Discover: requester, Reply: target).
Status decode_route_request(ByteView input, RouteRequestPayload& payload) noexcept;

}  // namespace routeloom
