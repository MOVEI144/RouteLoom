#pragma once

// Private to the MeshNode translation units (node*.cpp): the constants and
// helpers they share. Not part of the public include tree.

#include "routeloom/node.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <limits>

#include "routeloom/autonomy_wire.hpp"
#include "routeloom/bootstrap_transport.hpp"
#include "routeloom/byte_io.hpp"
#include "routeloom/discovery_scope.hpp"
#include "routeloom/rlcw1.hpp"
#include "routeloom/sdkv1_revocation.hpp"

namespace routeloom {
namespace {

constexpr std::uint32_t kControlLifetimeMs = 1000;
constexpr std::uint32_t kMinimumEndToEndRetryMs = 250;
// ROUTE_UPDATE record: destination(8) + origin generation(4) + sequence(2) + metric(2)
constexpr std::size_t kRouteRecordBytes = 16;
// ROUTE_UPDATE payload = 1-byte count + N records; the 128-byte payload caps
// N at floor((128 - 1) / kRouteRecordBytes) = 7.
constexpr std::size_t kMaxRouteRecordsPerFrame =
    (kMaxApplicationPayload - 1) / kRouteRecordBytes;
constexpr std::uint32_t kSeqnoRequestLifetimeMs = 2000;
constexpr std::uint32_t kSeqnoRequestCooldownMs = 2000;
constexpr std::uint32_t kSeqnoRequestMaxCooldownMs = 30000;
constexpr std::size_t kSeqnoMaxInflight = 4;
constexpr std::uint32_t kSeqnoStateDwellMs = 30000;
constexpr std::uint8_t kSeqnoRequestMaxTtl = kDefaultHopLimit;
constexpr std::size_t kSeqnoRequestPayloadBytes = 8 + 8 + 2 + 4 + 1;
// Triggered updates: at most one full-neighbor burst per min-interval, each
// burst delayed by a small deterministic jitter.
constexpr std::uint32_t kTriggeredUpdateMinIntervalMs = 1000;
constexpr std::uint32_t kTriggeredJitterMs = 64;

// Saturating u64 counter bump (sdk-completion/02 §2.4): a counter that would
// exceed UINT64_MAX pins — unreachable within a boot, never wrapping.
inline void saturating_inc(std::uint64_t& counter) noexcept {
  if (counter != UINT64_MAX) ++counter;
}

// Saturating u64 add for the airtime ledger — same pin-on-overflow rule.
inline void saturating_add(std::uint64_t& counter, const std::uint64_t delta) noexcept {
  counter = UINT64_MAX - counter < delta ? UINT64_MAX : counter + delta;
}

// Map a scheduler admission verdict onto a BUSY reason (03 §5). The reason
// is derived from the verdict — a BUSY that was never transmitted is never
// reported as sent.
inline std::uint8_t busy_reason_for(const AdmitVerdict verdict) noexcept {
  switch (verdict) {
    case AdmitVerdict::ScopeLimited:
    case AdmitVerdict::OriginLimited:
      return static_cast<std::uint8_t>(autonomy::BusyReason::RateLimited);
    default:
      return static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull);
  }
}

}  // namespace
}  // namespace routeloom
