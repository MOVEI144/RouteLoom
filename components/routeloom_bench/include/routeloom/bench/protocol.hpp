#pragma once

// Bench application wire protocol (design-devflow.md §5.2): the
// application-level payload format spoken between the bench host and
// firmware/bench_node over the public SDK data path.
//
//   0   magic   4B  "RLB1"
//   4   version 1B  = 1
//   5   opcode  1B
//   6   flags   u16 (big-endian)
//   8   run_uuid 16B — one host-side run; commands for a dead/foreign run are late
//  24   sequence u32 — ordinal inside the run
//  28   body CRC32 — ISO HDLC over the body bytes only
//  32   body
//
// The three payload ceilings are distinct: an SDK unicast application
// payload is 128 B (body <= 96 B), a group application payload is 127 B
// (body <= 95 B), and a command that must also survive the normal HostOps
// lane stays <= 96 B total (body <= 64 B). Host-originated commands use the
// command bound so they work on either path; device replies only ever ride
// unicast DATA.
//
// Field order is big-endian (routeloom/byte_io.hpp). The CRC authenticates
// the body, not the header — a CRC-invalid packet's run_uuid is still
// readable for the per-run crc_invalid counter but is never trusted.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/byte_io.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom::bench {

inline constexpr std::array<std::uint8_t, 4> kMagic{'R', 'L', 'B', '1'};
inline constexpr std::uint8_t kProtocolVersion = 1;
inline constexpr std::size_t kHeaderSize = 32;
inline constexpr std::size_t kMaxBody = kMaxApplicationPayload - kHeaderSize;   // 96 (unicast)
inline constexpr std::size_t kMaxGroupBody = 127 - kHeaderSize;                 // 95 (group)
inline constexpr std::size_t kMaxCommandBody = 96 - kHeaderSize;                // 64 (HostOps lane)
inline constexpr std::size_t kMaxMessage = kHeaderSize + kMaxBody;

using RunUuid = std::array<std::uint8_t, 16>;
inline constexpr RunUuid kNullRun{};

enum class Opcode : std::uint8_t {
  Hello = 0x01,
  Capabilities = 0x02,
  EchoRequest = 0x10,
  EchoReply = 0x11,
  CountOnly = 0x20,
  CountGet = 0x21,
  CountStatus = 0x22,
  Rollcall = 0x30,
  StatusGet = 0x40,
  Status = 0x41,
  PeerSendStart = 0x50,
  PeerSendStatus = 0x51,
  PeerSendStop = 0x52,
  CounterReset = 0x60,
  FaultSet = 0x61,
  ResetRequest = 0x70,
  ResetAck = 0x71,
};

// Header flags. kFlagResponse marks a device reply: response-flagged
// messages are never dispatched as requests, which is what makes replies
// (ECHO_REPLY in particular) unechoable — one rule covers every opcode.
inline constexpr std::uint16_t kFlagResponse = 0x0001;
// A reply re-sent for a request already answered inside the run window.
inline constexpr std::uint16_t kFlagDuplicate = 0x0002;
// A reply to a request whose run is retired/unknown, or a control command
// bound to a previous boot incarnation — the run is never re-opened.
inline constexpr std::uint16_t kFlagLate = 0x0004;
// A sender-side marker: a constrained fault injection is currently active.
inline constexpr std::uint16_t kFlagFault = 0x0008;

bool opcode_known(std::uint8_t opcode) noexcept;
// Replies carry kFlagResponse; this predicate is the reply-opcode list for
// encoders and "is this opcode ever a response" checks.
bool opcode_is_reply(std::uint8_t opcode) noexcept;

// Wire-decode verdicts. An unknown opcode is NOT an error — the header is
// well formed and the application layer rejects it.
enum class DecodeError : std::uint8_t {
  Ok = 0,
  Truncated,
  BadMagic,
  UnsupportedVersion,
  CrcMismatch,
};

struct Message {
  std::uint8_t opcode{0};
  std::uint16_t flags{0};
  RunUuid run{};
  std::uint32_t sequence{0};
  ByteView body{};
};

// Decode one wire message. `out.body` borrows `wire`; callers that retain it
// must copy (the application copies into its bounded RX queue anyway).
DecodeError decode(ByteView wire, Message& out) noexcept;

// Encode one wire message into `out` (>= kHeaderSize + body.size, body <=
// kMaxBody). Returns InvalidArgument/ResourceExhausted on violation, never
// partial output.
Status encode(std::uint8_t opcode, std::uint16_t flags, const RunUuid& run,
              std::uint32_t sequence, ByteView body, MutableByteView out,
              std::size_t& written) noexcept;

// --- Bodies -------------------------------------------------------------
// Every body is a fixed prefix plus optional opaque payload; each codec is
// a pure encode/decode pair. decode_* returns false on any malformed body
// (short, trailing garbage where the layout is fixed).

// CAPABILITIES body (HELLO reply and the once-per-join announce).
struct CapabilitiesBody {
  std::uint8_t app_protocol{kProtocolVersion};
  std::uint8_t app_version{0};
  std::uint8_t max_unicast_body{kMaxBody};
  std::uint8_t max_group_body{kMaxGroupBody};
  std::uint8_t max_command_body{kMaxCommandBody};
  std::uint8_t run_slots{0};
  std::uint8_t reply_queue{0};
  std::uint8_t generator_max_inflight{0};
  std::uint64_t boot_incarnation{0};
  std::uint32_t firmware_digest{0};
  std::uint32_t config_digest{0};
  // Opcode list — sized beyond the current 17 so later tickets can add
  // opcodes without changing the body layout budget.
  std::array<std::uint8_t, 24> opcodes{};
  std::uint8_t opcode_count{0};
};
Status encode(const CapabilitiesBody& body, ByteWriter& out) noexcept;
bool decode(ByteReader& in, CapabilitiesBody& out) noexcept;
// Max wire size: 25 fixed bytes + opcode_count + the full opcode array.
inline constexpr std::size_t kCapabilitiesBodySize = 49;

// COUNT_STATUS body — the state of one tracked run (header run_uuid).
// `window` covers sequences [window_base - 63, window_base] seen uniquely.
struct CountStatusBody {
  std::uint8_t state{0};  // 0 unknown run, 1 active, 2 retired
  std::uint32_t unique_packets{0};
  std::uint32_t unique_bytes{0};
  std::uint32_t duplicates{0};
  std::uint32_t crc_invalid{0};
  std::uint32_t first_ms{0};
  std::uint32_t last_ms{0};
  std::uint32_t window_base{0};
  std::uint64_t window{0};
};
Status encode(const CountStatusBody& body, ByteWriter& out) noexcept;
bool decode(ByteReader& in, CountStatusBody& out) noexcept;
inline constexpr std::size_t kCountStatusBodySize = 37;

// ROLLCALL body: the optional per-device STATUS page request; 0xFF = none.
inline constexpr std::uint8_t kRollcallNoPage = 0xFF;
struct RollcallBody {
  std::uint8_t page{kRollcallNoPage};
};

// STATUS_GET body: which page to return.
struct StatusGetBody {
  std::uint8_t page{0};
};

// STATUS body: a bounded page of device state. sample_seq identifies one
// consistent snapshot generation — a host discards a page set whose
// sample_seq or boot_incarnation changed mid-scan (interrupted scan).
struct StatusBody {
  std::uint16_t sample_seq{0};
  std::uint64_t boot_incarnation{0};
  std::uint8_t page{0};
  std::uint8_t page_count{0};
  ByteView fields{};
};
Status encode_status_head(const StatusBody& body, ByteWriter& out) noexcept;

// PEER_SEND_START body: start a bounded device-to-device run.
struct PeerSendStartBody {
  std::uint64_t expected_boot{0};  // must equal this device's boot_incarnation
  NodeId destination{kInvalidNodeId};
  std::uint32_t sequence_begin{0};
  std::uint16_t count{0};          // planned packets, <= kGeneratorMaxCount
  std::uint8_t payload_len{0};     // bench body bytes per packet
  std::uint32_t seed{0};           // deterministic payload fill
  std::uint32_t interval_ms{0};    // spacing between sends
  std::uint32_t ttl_ms{0};         // per-packet delivery lifetime
  std::uint8_t max_inflight{1};    // clamped to the device bound; zero is invalid
};
Status encode(const PeerSendStartBody& body, ByteWriter& out) noexcept;
bool decode(ByteReader& in, PeerSendStartBody& out) noexcept;
inline constexpr std::size_t kPeerSendStartBodySize = 36;

// PEER_SEND_STATUS body — answer to START/STOP and to an empty-body query.
struct PeerSendStatusBody {
  std::uint8_t result{0};   // PeerSendResult below
  std::uint8_t state{0};    // GeneratorState below
  std::uint16_t planned{0};
  std::uint16_t submitted{0};
  std::uint16_t admitted{0};
  std::uint16_t delivered{0};
  std::uint16_t failed{0};
  std::uint16_t unknown{0};
  std::uint32_t first_ms{0};
  std::uint32_t last_ms{0};
};
Status encode(const PeerSendStatusBody& body, ByteWriter& out) noexcept;
bool decode(ByteReader& in, PeerSendStatusBody& out) noexcept;
inline constexpr std::size_t kPeerSendStatusBodySize = 22;

namespace result {
// result field values of PeerSendStatusBody.
inline constexpr std::uint8_t kQuery = 0;      // status of current/last run
inline constexpr std::uint8_t kStarted = 1;
inline constexpr std::uint8_t kDuplicate = 2;  // same (origin, run, seq) seen
inline constexpr std::uint8_t kStaleBoot = 3;  // expected_boot mismatch
inline constexpr std::uint8_t kBusy = 4;       // another generator run lives
inline constexpr std::uint8_t kInvalid = 5;
inline constexpr std::uint8_t kStopped = 6;
inline constexpr std::uint8_t kNotRunning = 7;
}  // namespace result

namespace gen_state {
// state field values of PeerSendStatusBody.
inline constexpr std::uint8_t kIdle = 0;
inline constexpr std::uint8_t kRunning = 1;
inline constexpr std::uint8_t kComplete = 2;
inline constexpr std::uint8_t kStopped = 3;
inline constexpr std::uint8_t kTimeBound = 4;  // stopped by the 60 s run bound
}  // namespace gen_state

// Control commands carry the device boot incarnation they were minted
// against: a replayed command after a reset mismatches and is refused, so a
// bounded run never silently restarts.
struct ExpectedBootBody {
  std::uint64_t expected_boot{0};
};
Status encode(const ExpectedBootBody& body, ByteWriter& out) noexcept;
bool decode(ByteReader& in, ExpectedBootBody& out) noexcept;

// FAULT_SET body: arm one constrained fault for duration_ms (0 clears).
struct FaultSetBody {
  std::uint64_t expected_boot{0};
  std::uint8_t fault{0};
  std::uint32_t duration_ms{0};
  std::uint32_t param{0};
};
Status encode(const FaultSetBody& body, ByteWriter& out) noexcept;
bool decode(ByteReader& in, FaultSetBody& out) noexcept;
inline constexpr std::size_t kFaultSetBodySize = 17;

namespace fault {
inline constexpr std::uint8_t kNone = 0;
inline constexpr std::uint8_t kEchoSuppress = 1;  // consume echoes, never reply
inline constexpr std::uint8_t kEchoDelay = 2;     // hold replies param ms
// Bounded TX load: one small COUNT_ONLY to the commander every param ms
// (floored at 50) until duration_ms elapses — a finite send-load injection,
// not an open-ended flood.
inline constexpr std::uint8_t kSendLoad = 3;
}  // namespace fault

// RESET_REQUEST body: expected_boot binds to this incarnation; delay_ms
// defers execution until after the ACK is on the wire.
struct ResetRequestBody {
  std::uint64_t expected_boot{0};
  std::uint32_t delay_ms{0};
};
Status encode(const ResetRequestBody& body, ByteWriter& out) noexcept;
bool decode(ByteReader& in, ResetRequestBody& out) noexcept;
inline constexpr std::size_t kResetRequestBodySize = 12;

struct ResetAckBody {
  std::uint8_t accepted{0};
};
Status encode(const ResetAckBody& body, ByteWriter& out) noexcept;
bool decode(ByteReader& in, ResetAckBody& out) noexcept;

// Encodes the shared scalar bodies (rollcall page, status-get page).
Status encode_page_body(std::uint8_t page, ByteWriter& out) noexcept;
bool decode_page_body(ByteReader& in, std::uint8_t& page) noexcept;

}  // namespace routeloom::bench
