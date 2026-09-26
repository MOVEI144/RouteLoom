#include "routeloom/bench/app.hpp"

#include <cstring>

#include "routeloom/byte_io.hpp"
#include "routeloom/admission.hpp"
#include "routeloom/group.hpp"

namespace routeloom::bench {

namespace {

constexpr std::uint32_t low32(MonotonicMs ms) noexcept {
  return static_cast<std::uint32_t>(ms & 0xffffffffULL);
}

// Deterministic per-packet fill for generator traffic: the destination only
// counts packets, but the content is reproducible for debugging.
std::uint8_t payload_byte(std::uint32_t seed, std::uint32_t seq,
                        std::uint32_t index) noexcept {
  std::uint32_t v = seed ^ (seq * 2654435761u) ^ (index * 2246822519u);
  v ^= v >> 15;
  v *= 2654435761u;
  return static_cast<std::uint8_t>(v >> 24);
}

}  // namespace

BenchApp::BenchApp(const BenchConfig& config) noexcept : config_(config) {}

void BenchApp::attach(MeshNode& node, MonotonicMs now_ms) noexcept {
  node_ = &node;
  attached_ms_ = now_ms;
}

std::uint64_t BenchApp::boot_incarnation() const noexcept {
  return node_ == nullptr ? 0 : node_->config().boot_incarnation;
}

bool BenchApp::authorized(NodeId origin) const noexcept {
  if (config_.controller != kInvalidNodeId) return origin == config_.controller;
  // Member sites: the first adopted route gateway is the bridge that hosts
  // the authority; nothing else may drive control commands.
  const NodeId gateway =
      node_ == nullptr ? kInvalidNodeId : node_->config().route_gateways[0];
  return gateway != kInvalidNodeId && origin == gateway;
}

void BenchApp::on_message(const MessageKey& key, NodeId /*source*/,
                          ByteView payload) noexcept {
  enqueue_rx(key.origin, payload, false, false);
}

void BenchApp::on_group_message(const GroupMessageInfo& info,
                                ByteView payload) noexcept {
  enqueue_rx(info.key.origin, payload, true, info.late);
}

void BenchApp::on_delivery(const DeliveryResult& result) noexcept {
  switch (result.state) {
    case DeliveryState::Delivered:
    case DeliveryState::Failed:
    case DeliveryState::Expired:
    case DeliveryState::CancelledBeforeTx:
    case DeliveryState::Indeterminate:
      break;
    default:
      return;
  }
  if (reset_pending_ && reset_ack_submitted_ && result.id == reset_ack_id_) {
    reset_ack_delivery_ = result.state;
    reset_ack_result_pending_ = true;
    return;
  }
  if (!generator_.inflight || result.id != generator_.inflight_id) return;
  for (DeliveryEvent& event : deliveries_) {
    if (!event.used) {
      event.id = result.id;
      event.state = result.state;
      event.used = true;
      return;
    }
  }
  ++stats_.delivery_events_dropped;
}

void BenchApp::on_diagnostic(const char* /*reason*/, NodeId /*peer*/,
                             const MessageId* /*message*/) noexcept {}

void BenchApp::enqueue_rx(NodeId origin, ByteView payload,
                          bool is_group, bool group_late) noexcept {
  if (payload.size > kMaxApplicationPayload) {
    ++stats_.rx_dropped;
    return;
  }
  for (RxEntry& entry : rx_) {
    if (!entry.used) {
      entry.origin = origin;
      entry.is_group = is_group;
      entry.group_late = group_late;
      std::memcpy(entry.buf.data(), payload.data, payload.size);
      entry.len = static_cast<std::uint8_t>(payload.size);
      entry.used = true;
      return;
    }
  }
  ++stats_.rx_dropped;
}

void BenchApp::poll(MonotonicMs now_ms) noexcept {
  if (node_ == nullptr) return;
  drain_delivery(now_ms);
  drain_rx(now_ms);
  drive_generator(now_ms);
  drive_send_load(now_ms);
  drain_replies(now_ms);
  drive_rollcall(now_ms);
  drive_reset(now_ms);
  retire_idle_runs(now_ms);
  maybe_announce(now_ms);
}

void BenchApp::drain_rx(MonotonicMs now_ms) noexcept {
  for (RxEntry& entry : rx_) {
    if (!entry.used) continue;
    entry.used = false;
    ++stats_.rx_total;
    Message msg{};
    const DecodeError err = decode(ByteView{entry.buf.data(), entry.len}, msg);
    if (err != DecodeError::Ok) {
      if (err == DecodeError::CrcMismatch) {
        ++stats_.crc_invalid;
        // The header is still readable: count the corruption against the
        // tracked run it claims, never create or mutate one from it.
        if (entry.len >= kHeaderSize) {
          ByteReader head{ByteView{entry.buf.data() + 8,
                                   static_cast<std::size_t>(entry.len) - 8}};
          RunUuid run{};
          if (head.read_bytes(MutableByteView{run.data(), run.size()})) {
            if (RunRecord* record = find_run(run)) ++record->crc_invalid;
          }
        }
      } else {
        ++stats_.malformed;
      }
      continue;
    }
    dispatch(entry, msg, now_ms);
  }
}

void BenchApp::dispatch(const RxEntry& entry, const Message& msg,
                        MonotonicMs now_ms) noexcept {
  // Replies are terminal traffic: a peer's reply never starts work here.
  // This is the "no echoing replies" rule for every reply opcode at once.
  if ((msg.flags & kFlagResponse) != 0 ||
      (opcode_is_reply(msg.opcode) &&
       msg.opcode != static_cast<std::uint8_t>(Opcode::PeerSendStatus))) {
    ++stats_.responses_seen;
    // A COUNT_STATUS can correct a verdict for the current generator run
    // after its final send has already completed.
    if (msg.opcode == static_cast<std::uint8_t>(Opcode::CountStatus) &&
        !entry.is_group && generator_.uuid == msg.run &&
        generator_.state != gen_state::kIdle) {
      handle_count_status(entry, msg, now_ms);
    }
    return;
  }
  if (!opcode_known(msg.opcode)) {
    ++stats_.unknown_opcode;
    return;
  }
  if (entry.is_group && msg.opcode != static_cast<std::uint8_t>(Opcode::Rollcall)) {
    switch (static_cast<Opcode>(msg.opcode)) {
      case Opcode::PeerSendStart:
      case Opcode::PeerSendStop:
      case Opcode::CounterReset:
      case Opcode::FaultSet:
      case Opcode::ResetRequest:
        break;  // handlers count a group-carried control as unauthorized
      default:
        ++stats_.group_ignored;
        return;
    }
  }
  switch (static_cast<Opcode>(msg.opcode)) {
    case Opcode::Hello:
      // HELLO shares the reply path: it answers with CAPABILITIES.
      handle_status_get(entry, msg, now_ms);
      break;
    case Opcode::EchoRequest:
      handle_echo(entry, msg, now_ms);
      break;
    case Opcode::CountOnly:
      handle_count(entry, msg, now_ms);
      break;
    case Opcode::CountGet:
      handle_count_get(entry, msg, now_ms);
      break;
    case Opcode::Rollcall:
      if (entry.is_group) {
        handle_rollcall(entry, msg, now_ms);
      } else {
        ++stats_.invalid_requests;  // rollcall only ever arrives via group/ALL
      }
      break;
    case Opcode::StatusGet:
      handle_status_get(entry, msg, now_ms);
      break;
    case Opcode::PeerSendStart:
      handle_peer_send_start(entry, msg, now_ms);
      break;
    case Opcode::PeerSendStop:
      handle_peer_send_stop(entry, msg, now_ms);
      break;
    case Opcode::PeerSendStatus:
      handle_peer_send_status(entry, msg, now_ms);
      break;
    case Opcode::CounterReset:
      handle_counter_reset(entry, msg, now_ms);
      break;
    case Opcode::FaultSet:
      handle_fault_set(entry, msg, now_ms);
      break;
    case Opcode::ResetRequest:
      handle_reset_request(entry, msg, now_ms);
      break;
    default:
      ++stats_.unknown_opcode;
      break;
  }
}

bool BenchApp::cmd_duplicate(NodeId origin, const RunUuid& run,
                             std::uint32_t seq) noexcept {
  const std::uint32_t boot = static_cast<std::uint32_t>(boot_incarnation());
  for (CmdSeen& seen : cmd_log_) {
    if (seen.used && seen.origin == origin && seen.run == run &&
        seen.seq == seq && seen.boot == boot) {
      return true;
    }
  }
  CmdSeen& slot = cmd_log_[cmd_cursor_];
  cmd_cursor_ = (cmd_cursor_ + 1) % kCmdLogDepth;
  slot.origin = origin;
  slot.run = run;
  slot.seq = seq;
  slot.boot = boot;
  slot.used = true;
  return false;
}

BenchApp::RunRecord* BenchApp::find_run(const RunUuid& uuid) noexcept {
  for (RunRecord& run : runs_) {
    if (run.used && run.uuid == uuid) return &run;
  }
  return nullptr;
}

const BenchApp::RunRecord* BenchApp::find_run(const RunUuid& uuid) const noexcept {
  for (const RunRecord& run : runs_) {
    if (run.used && run.uuid == uuid) return &run;
  }
  return nullptr;
}

bool BenchApp::run_retired(const RunUuid& uuid) const noexcept {
  for (std::size_t i = 0; i < retired_count_ && i < kRetiredDepth; ++i) {
    if (retired_[i] == uuid) return true;
  }
  return false;
}

void BenchApp::tombstone(const RunUuid& uuid) noexcept {
  if (run_retired(uuid)) return;
  if (retired_count_ < kRetiredDepth) {
    retired_[retired_count_++] = uuid;
  } else {
    for (std::size_t i = 1; i < kRetiredDepth; ++i) {
      retired_[i - 1] = retired_[i];
    }
    retired_[kRetiredDepth - 1] = uuid;
  }
  bump_version();
}

BenchApp::RunRecord* BenchApp::open_run(const RunUuid& uuid, std::uint32_t seq,
                                        MonotonicMs now_ms) noexcept {
  if (RunRecord* run = find_run(uuid)) return run;
  RunRecord* slot = nullptr;
  for (RunRecord& run : runs_) {
    if (!run.used) {
      slot = &run;
      break;
    }
  }
  if (slot == nullptr) {
    // Table full: evict the least recently active run into the tombstone
    // ring so its traffic counts as late instead of silently reopening.
    slot = &runs_[0];
    for (RunRecord& run : runs_) {
      if (run.last_active < slot->last_active) slot = &run;
    }
    tombstone(slot->uuid);
  }
  *slot = RunRecord{};
  slot->used = true;
  slot->uuid = uuid;
  slot->window_base = seq;
  slot->first_ms = low32(now_ms);
  slot->last_ms = low32(now_ms);
  slot->last_active = now_ms;
  bump_version();
  return slot;
}

std::uint8_t BenchApp::window_mark(RunRecord& run, std::uint32_t seq) noexcept {
  if (seq > run.window_base) {
    const std::uint32_t shift = seq - run.window_base;
    run.window = shift >= 64 ? 1 : (run.window << shift) | 1;
    run.window_base = seq;
    return 0;
  }
  const std::uint32_t diff = run.window_base - seq;
  if (diff >= 64) return 2;
  const std::uint64_t bit = 1ULL << diff;
  if ((run.window & bit) != 0) return 1;
  run.window |= bit;
  return 0;
}

bool BenchApp::fault_active(MonotonicMs now_ms) const noexcept {
  return now_ms < faults_.echo_suppress_until ||
         now_ms < faults_.echo_delay_until ||
         (faults_.send_load_to != kInvalidNodeId &&
          now_ms < faults_.send_load_until);
}

bool BenchApp::enqueue_reply(NodeId destination, std::uint8_t opcode,
                             std::uint16_t flags, const RunUuid& run,
                             std::uint32_t sequence, ByteView body,
                             MonotonicMs not_before,
                             MonotonicMs now_ms,
                             bool reset_ack) noexcept {
  for (ReplyEntry& reply : replies_) {
    if (!reply.used) {
      std::size_t written = 0;
      const Status status =
          encode(opcode, flags, run, sequence, body,
                 MutableByteView{reply.buf.data(), reply.buf.size()}, written);
      if (!status) {
        ++stats_.malformed;
        return false;
      }
      reply.destination = destination;
      reply.not_before = not_before;
      reply.expires_ms = now_ms + kReplyTtlMs;
      reply.len = static_cast<std::uint8_t>(written);
      reply.reset_ack = reset_ack;
      reply.used = true;
      return true;
    }
  }
  ++stats_.reply_dropped;
  return false;
}

void BenchApp::handle_echo(const RxEntry& entry, const Message& msg,
                           MonotonicMs now_ms) noexcept {
  if (entry.is_group) {
    ++stats_.group_ignored;
    return;
  }
  std::uint16_t flags = kFlagResponse;
  if (fault_active(now_ms)) flags |= kFlagFault;
  if (run_retired(msg.run)) {
    // Request for a run that already ended: answer once, flagged late —
    // the run is never re-opened.
    ++stats_.late_requests;
    enqueue_reply(entry.origin,
                  static_cast<std::uint8_t>(Opcode::EchoReply),
                  flags | kFlagLate, msg.run, msg.sequence, msg.body, now_ms,
                  now_ms);
    return;
  }
  RunRecord* run = open_run(msg.run, msg.sequence, now_ms);
  run->last_active = now_ms;
  const std::uint8_t mark = window_mark(*run, msg.sequence);
  if (mark == 1) {
    ++run->duplicates;
    flags |= kFlagDuplicate;
  } else if (mark == 2) {
    ++stats_.late_requests;
    flags |= kFlagLate;
  } else {
    ++run->unique_packets;
    run->unique_bytes += msg.body.size;
  }
  run->last_ms = low32(now_ms);
  if (now_ms < faults_.echo_suppress_until) {
    ++stats_.echo_suppressed;
    return;
  }
  ++stats_.echo_answered;
  const MonotonicMs not_before =
      now_ms < faults_.echo_delay_until ? now_ms + faults_.echo_delay_ms
                                        : now_ms;
  // Queue-full is already tallied inside enqueue_reply.
  (void)enqueue_reply(entry.origin,
                      static_cast<std::uint8_t>(Opcode::EchoReply), flags,
                      msg.run, msg.sequence, msg.body, not_before, now_ms);
}

void BenchApp::handle_count(const RxEntry& entry, const Message& msg,
                            MonotonicMs now_ms) noexcept {
  if (entry.is_group) {
    ++stats_.group_ignored;
    return;
  }
  // A bound COUNT packet leads its body with the destination boot
  // incarnation the run was minted against (0 = unbound). A nonzero
  // mismatch means this traffic predates a reset of this node: the run
  // must not be (re)opened or counted — report stale so the sender can
  // close its side as unknown. Unbound traffic keeps plain semantics.
  std::uint64_t bound_boot = 0;
  if (msg.body.size >= kCountBindSize) {
    ByteReader prefix{msg.body};
    (void)prefix.read_u64(bound_boot);
  }
  if (bound_boot != 0 && bound_boot != boot_incarnation()) {
    ++stats_.stale_boot;
    std::array<std::uint8_t, kCountStatusBodySize> raw{};
    ByteWriter writer{MutableByteView{raw.data(), raw.size()}};
    CountStatusBody stale{};
    stale.state = count_state::kStaleBoot;
    (void)encode(stale, writer);
    // Bounded like every reply; a queue-full drop only delays the
    // sender's stale notice until the next bound packet lands.
    (void)enqueue_reply(entry.origin,
                        static_cast<std::uint8_t>(Opcode::CountStatus),
                        kFlagResponse | kFlagLate, msg.run, msg.sequence,
                        ByteView{raw.data(), writer.size()}, now_ms, now_ms);
    return;
  }
  if (run_retired(msg.run)) {
    ++stats_.late_requests;
    return;
  }
  RunRecord* run = open_run(msg.run, msg.sequence, now_ms);
  run->last_active = now_ms;
  const std::uint8_t mark = window_mark(*run, msg.sequence);
  if (mark == 1) {
    ++run->duplicates;
  } else if (mark == 2) {
    ++stats_.late_requests;
  } else {
    ++run->unique_packets;
    run->unique_bytes += msg.body.size;
  }
  run->last_ms = low32(now_ms);
}

void BenchApp::handle_count_get(const RxEntry& entry, const Message& msg,
                                MonotonicMs now_ms) noexcept {
  CountStatusBody body{};
  const RunRecord* run = find_run(msg.run);
  if (run != nullptr) {
    body.state = count_state::kActive;
    body.unique_packets = run->unique_packets;
    body.unique_bytes = run->unique_bytes;
    body.duplicates = run->duplicates;
    body.crc_invalid = run->crc_invalid;
    body.first_ms = run->first_ms;
    body.last_ms = run->last_ms;
    body.window_base = run->window_base;
    body.window = run->window;
  } else {
    body.state =
        run_retired(msg.run) ? count_state::kRetired : count_state::kUnknown;
  }
  std::array<std::uint8_t, kCountStatusBodySize> raw{};
  ByteWriter writer{MutableByteView{raw.data(), raw.size()}};
  (void)encode(body, writer);
  enqueue_reply(entry.origin, static_cast<std::uint8_t>(Opcode::CountStatus),
                kFlagResponse, msg.run, msg.sequence,
                ByteView{raw.data(), writer.size()}, now_ms, now_ms);
}

void BenchApp::handle_count_status(const RxEntry& entry, const Message& msg,
                                   MonotonicMs /*now_ms*/) noexcept {
  Generator& gen = generator_;
  if (gen.state == gen_state::kIdle || gen.uuid != msg.run || entry.is_group ||
      entry.origin != gen.destination ||
      (msg.flags & (kFlagResponse | kFlagLate)) !=
          (kFlagResponse | kFlagLate) ||
      msg.sequence < gen.sequence_begin ||
      msg.sequence - gen.sequence_begin >= gen.sent) {
    // Only the bound destination may close the run it is bound to.
    return;
  }
  CountStatusBody status{};
  {
    ByteReader reader{msg.body};
    if (!decode(reader, status)) return;
  }
  if (status.state != count_state::kStaleBoot) return;
  // The refused packet reached only the post-reset incarnation. Correct
  // that sequence's terminal SDK verdict; a missing result is resolved by
  // drain_delivery after dest_reset latches. Clearing the bit also makes a
  // retransmitted or out-of-order notice harmless.
  const std::uint64_t bit = 1ULL << (msg.sequence - gen.sequence_begin);
  bool changed = false;
  if ((gen.delivered_mask & bit) != 0) {
    gen.delivered_mask &= ~bit;
    --gen.delivered;
    ++gen.unknown;
    changed = true;
  } else if ((gen.failed_mask & bit) != 0) {
    gen.failed_mask &= ~bit;
    --gen.failed;
    ++gen.unknown;
    changed = true;
  }
  if (!gen.dest_reset) {
    gen.dest_reset = true;
    if (!gen.active) gen.state = gen_state::kPeerReset;
    changed = true;
  }
  if (changed) bump_version();
}

void BenchApp::handle_rollcall(const RxEntry& entry, const Message& msg,
                               MonotonicMs now_ms) noexcept {
  RollcallBody body{};
  if (msg.body.size != 0) {
    ByteReader reader{msg.body};
    if (!decode_page_body(reader, body.page)) {
      ++stats_.invalid_requests;
      return;
    }
  }
  rollcall_.last_uuid = msg.run;
  rollcall_.last_seq = msg.sequence;
  rollcall_.last_ms = low32(now_ms);
  ++rollcall_.count;
  const bool first = !rollcall_.announced;
  const bool changed = rollcall_.version_at_reply != status_version_;
  const bool sliced = body.page != kRollcallNoPage;
  if (first || changed || sliced) {
    rollcall_.pending = true;
    rollcall_.reply_to = entry.origin;
    rollcall_.page = sliced ? body.page : status_page::kIdentity;
    // Bounded jitter: simultaneous joiners must not answer in lockstep.
    rollcall_.not_before =
        now_ms + (node_->node_id() ^ entry.origin ^ msg.sequence) %
                     kRollcallJitterMs;
  }
}

void BenchApp::handle_status_get(const RxEntry& entry, const Message& msg,
                                 MonotonicMs now_ms) noexcept {
  std::uint8_t page = status_page::kIdentity;
  const bool is_hello = msg.opcode == static_cast<std::uint8_t>(Opcode::Hello);
  if (is_hello) {
    // HELLO -> CAPABILITIES.
    CapabilitiesBody caps{};
    caps.app_version = config_.app_version;
    caps.run_slots = kRunSlots;
    caps.reply_queue = kReplyQueueDepth;
    caps.generator_max_inflight = kGeneratorMaxInflight;
    caps.boot_incarnation = boot_incarnation();
    caps.firmware_digest = config_.firmware_digest;
    caps.config_digest = config_.config_digest;
    std::uint8_t count = 0;
    for (std::uint8_t op = 0; op < 0x80 && count < caps.opcodes.size(); ++op) {
      if (opcode_known(op)) caps.opcodes[count++] = op;
    }
    caps.opcode_count = count;
    std::array<std::uint8_t, kMaxCommandBody> raw{};
    ByteWriter writer{MutableByteView{raw.data(), raw.size()}};
    (void)encode(caps, writer);
    enqueue_reply(entry.origin,
                  static_cast<std::uint8_t>(Opcode::Capabilities),
                  kFlagResponse, msg.run, msg.sequence,
                  ByteView{raw.data(), writer.size()}, now_ms, now_ms);
    return;
  }
  if (msg.body.size == 0) {
    ++stats_.invalid_requests;
    return;
  }
  ByteReader reader{msg.body};
  if (!decode_page_body(reader, page)) {
    ++stats_.invalid_requests;
    return;
  }
  send_status(entry.origin, msg.run, msg.sequence, page, now_ms);
}

void BenchApp::send_status(NodeId to, const RunUuid& run, std::uint32_t seq,
                           std::uint8_t page, MonotonicMs now_ms) noexcept {
  std::array<std::uint8_t, kMaxBody> body{};
  ByteWriter writer{MutableByteView{body.data(), body.size()}};
  StatusBody head{};
  head.sample_seq = status_version_;
  head.boot_incarnation = boot_incarnation();
  head.page = page;
  head.page_count = status_page::kCount;
  (void)encode_status_head(head, writer);
  if (page < status_page::kCount) {
    status_page_fields(page, writer, now_ms);
  }
  if (enqueue_reply(to, static_cast<std::uint8_t>(Opcode::Status),
                    kFlagResponse, run, seq,
                    ByteView{body.data(), writer.size()}, now_ms, now_ms)) {
    ++stats_.status_sent;
  }
}

void BenchApp::fill_generator_status(const RunUuid& run,
                                      PeerSendStatusBody& reply) const noexcept {
  if (generator_.uuid != run) return;
  reply.state = generator_.state;
  reply.planned = generator_.count;
  reply.submitted = generator_.submitted;
  reply.admitted = generator_.admitted;
  reply.delivered = generator_.delivered;
  reply.failed = generator_.failed;
  reply.unknown = generator_.unknown;
  reply.first_ms = generator_.first_ms;
  reply.last_ms = generator_.last_ms;
}

void BenchApp::handle_peer_send_status(const RxEntry& entry,
                                       const Message& msg,
                                       MonotonicMs now_ms) noexcept {
  if (entry.is_group || !authorized(entry.origin)) {
    ++stats_.unauthorized;
    return;
  }
  if (msg.body.size != 0) {
    ++stats_.invalid_requests;
    return;
  }
  PeerSendStatusBody reply{};
  reply.result = result::kQuery;
  fill_generator_status(msg.run, reply);
  std::array<std::uint8_t, kPeerSendStatusBodySize> raw{};
  ByteWriter writer{MutableByteView{raw.data(), raw.size()}};
  (void)encode(reply, writer);
  enqueue_reply(entry.origin,
                static_cast<std::uint8_t>(Opcode::PeerSendStatus),
                kFlagResponse, msg.run, msg.sequence,
                ByteView{raw.data(), writer.size()}, now_ms, now_ms);
}

void BenchApp::handle_peer_send_start(const RxEntry& entry, const Message& msg,
                                      MonotonicMs now_ms) noexcept {
  PeerSendStartBody start{};
  {
    ByteReader reader{msg.body};
    if (!decode(reader, start)) {
      ++stats_.invalid_requests;
      return;
    }
  }
  PeerSendStatusBody reply{};
  if (entry.is_group || !authorized(entry.origin)) {
    ++stats_.unauthorized;
    return;
  }
  if (cmd_duplicate(entry.origin, msg.run, msg.sequence)) {
    ++stats_.duplicate_commands;
    reply.result = result::kDuplicate;
  } else if (start.expected_boot != boot_incarnation()) {
    ++stats_.stale_boot;
    reply.result = result::kStaleBoot;
  } else if (run_retired(msg.run)) {
    ++stats_.late_requests;
    reply.result = result::kInvalid;
  } else if (generator_.active) {
    reply.result = result::kBusy;
  } else if (start.count == 0 || start.count > kGeneratorMaxCount ||
             start.payload_len < kCountBindSize ||
             static_cast<std::size_t>(start.payload_len) > kMaxBody ||
             start.ttl_ms == 0 ||
             start.ttl_ms > kMaxMessageLifetimeMs ||
             start.max_inflight == 0 ||
             static_cast<std::uint64_t>(start.sequence_begin) +
                     start.count - 1 > 0xffffffffULL ||
             start.destination == kInvalidNodeId ||
             start.destination == kBroadcastNodeId ||
             start.destination == node_->node_id() ||
             start.expected_dest_boot == 0) {
    // expected_dest_boot == 0 would mint an unbound run — and an unbound
    // run cannot honor the "no reopen across a destination reset"
    // contract, so the command is invalid rather than quietly weaker.
    reply.result = result::kInvalid;
  } else {
    generator_ = Generator{};
    generator_.active = true;
    generator_.state = gen_state::kRunning;
    generator_.uuid = msg.run;
    generator_.commander = entry.origin;
    generator_.destination = start.destination;
    generator_.dest_boot = start.expected_dest_boot;
    generator_.sequence_begin = start.sequence_begin;
    generator_.count = start.count;
    generator_.payload_len = start.payload_len;
    generator_.seed = start.seed;
    generator_.interval_ms = start.interval_ms;
    generator_.ttl_ms = start.ttl_ms;
    generator_.next_due = now_ms;
    generator_.deadline_ms = now_ms + kGeneratorMaxDurationMs;
    reply.result = result::kStarted;
    reply.state = gen_state::kRunning;
    reply.planned = start.count;
    bump_version();
  }
  fill_generator_status(msg.run, reply);
  std::array<std::uint8_t, kPeerSendStatusBodySize> raw{};
  ByteWriter writer{MutableByteView{raw.data(), raw.size()}};
  (void)encode(reply, writer);
  std::uint16_t flags = kFlagResponse;
  // One flag marks the refusal reason: a dedup hit stays "duplicate" even if
  // its run has since been retired — the tombstone only marks a *fresh*
  // command for a closed run as late.
  if (reply.result == result::kDuplicate) {
    flags |= kFlagDuplicate;
  } else if (reply.result == result::kStaleBoot || run_retired(msg.run)) {
    flags |= kFlagLate;
  }
  enqueue_reply(entry.origin,
                static_cast<std::uint8_t>(Opcode::PeerSendStatus), flags,
                msg.run, msg.sequence, ByteView{raw.data(), writer.size()},
                now_ms, now_ms);
}

void BenchApp::handle_peer_send_stop(const RxEntry& entry, const Message& msg,
                                     MonotonicMs now_ms) noexcept {
  PeerSendStatusBody reply{};
  std::uint16_t flags = kFlagResponse;
  if (entry.is_group || !authorized(entry.origin)) {
    ++stats_.unauthorized;
    return;
  }
  ExpectedBootBody body{};
  {
    ByteReader reader{msg.body};
    if (!decode(reader, body)) {
      ++stats_.invalid_requests;
      return;
    }
  }
  if (cmd_duplicate(entry.origin, msg.run, msg.sequence)) {
    ++stats_.duplicate_commands;
    reply.result = generator_.active ? result::kStopped : result::kNotRunning;
    flags |= kFlagDuplicate;
  } else if (body.expected_boot != boot_incarnation()) {
    ++stats_.stale_boot;
    reply.result = result::kStaleBoot;
    flags |= kFlagLate;
  } else if (generator_.active && generator_.uuid == msg.run) {
    if (generator_.inflight) {
      // STOP closes the run before that send's final delivery verdict.
      // Later callbacks cannot be attributed after another run starts.
      generator_.inflight = false;
      ++generator_.unknown;
    }
    generator_.active = false;
    generator_.state = gen_state::kStopped;
    reply.result = result::kStopped;
    tombstone(generator_.uuid);
    bump_version();
  } else {
    reply.result = result::kNotRunning;
  }
  fill_generator_status(msg.run, reply);
  std::array<std::uint8_t, kPeerSendStatusBodySize> raw{};
  ByteWriter writer{MutableByteView{raw.data(), raw.size()}};
  (void)encode(reply, writer);
  enqueue_reply(entry.origin,
                static_cast<std::uint8_t>(Opcode::PeerSendStatus), flags,
                msg.run, msg.sequence, ByteView{raw.data(), writer.size()},
                now_ms, now_ms);
}

void BenchApp::handle_counter_reset(const RxEntry& entry, const Message& msg,
                                    MonotonicMs /*now_ms*/) noexcept {
  ExpectedBootBody body{};
  {
    ByteReader reader{msg.body};
    if (!decode(reader, body)) {
      ++stats_.invalid_requests;
      return;
    }
  }
  if (entry.is_group || !authorized(entry.origin)) {
    ++stats_.unauthorized;
    return;
  }
  if (cmd_duplicate(entry.origin, msg.run, msg.sequence)) {
    ++stats_.duplicate_commands;
    return;
  }
  if (body.expected_boot != boot_incarnation()) {
    ++stats_.stale_boot;
    return;
  }
  if (RunRecord* run = find_run(msg.run)) {
    // Application statistics only: the dedup window is kept so a replayed
    // packet is still a duplicate — reset never weakens wire dedup.
    run->unique_packets = 0;
    run->unique_bytes = 0;
    run->duplicates = 0;
    run->crc_invalid = 0;
    run->first_ms = 0;
    run->last_ms = 0;
    bump_version();
  }
}

void BenchApp::handle_fault_set(const RxEntry& entry, const Message& msg,
                                MonotonicMs now_ms) noexcept {
  FaultSetBody fault{};
  {
    ByteReader reader{msg.body};
    if (!decode(reader, fault)) {
      ++stats_.invalid_requests;
      return;
    }
  }
  if (entry.is_group || !authorized(entry.origin)) {
    ++stats_.unauthorized;
    return;
  }
  if (cmd_duplicate(entry.origin, msg.run, msg.sequence)) {
    ++stats_.duplicate_commands;
    return;
  }
  if (fault.expected_boot != boot_incarnation()) {
    ++stats_.stale_boot;
    return;
  }
  if (fault.duration_ms > kMaxFaultDurationMs ||
      (fault.fault == fault::kNone &&
       (fault.duration_ms != 0 || fault.param != 0))) {
    ++stats_.invalid_requests;
    return;
  }
  switch (fault.fault) {
    case fault::kNone:
      faults_ = Faults{};
      break;
    case fault::kEchoSuppress:
      faults_.echo_suppress_until = now_ms + fault.duration_ms;
      break;
    case fault::kEchoDelay:
      faults_.echo_delay_until = now_ms + fault.duration_ms;
      faults_.echo_delay_ms = fault.param;
      break;
    case fault::kSendLoad:
      if (fault.duration_ms == 0) {
        faults_.send_load_to = kInvalidNodeId;
        break;
      }
      faults_.send_load_to = entry.origin;
      faults_.send_load_until = now_ms + fault.duration_ms;
      faults_.send_load_period_ms = fault.param < 50 ? 50 : fault.param;
      faults_.send_load_next = now_ms;
      faults_.send_load_seq = 0;
      break;
    default:
      ++stats_.invalid_requests;
      return;
  }
  bump_version();
}

void BenchApp::handle_reset_request(const RxEntry& entry, const Message& msg,
                                    MonotonicMs now_ms) noexcept {
  ResetRequestBody request{};
  {
    ByteReader reader{msg.body};
    if (!decode(reader, request)) {
      ++stats_.invalid_requests;
      return;
    }
  }
  if (entry.is_group || !authorized(entry.origin)) {
    ++stats_.unauthorized;
    return;
  }
  if (cmd_duplicate(entry.origin, msg.run, msg.sequence)) {
    ++stats_.duplicate_commands;
    return;
  }
  ResetAckBody ack{};
  if (request.expected_boot != boot_incarnation()) {
    ++stats_.stale_boot;
    ack.accepted = 0;
  } else if (platform_ == nullptr || reset_pending_ || reset_armed_) {
    ack.accepted = 0;
  } else {
    ack.accepted = 1;
  }
  std::array<std::uint8_t, 4> raw{};
  ByteWriter writer{MutableByteView{raw.data(), raw.size()}};
  (void)encode(ack, writer);
  std::uint16_t flags = kFlagResponse;
  if (ack.accepted == 0 &&
      request.expected_boot != boot_incarnation()) {
    flags |= kFlagLate;
  }
  // Queue the ACK before arming the reset. The delay begins only after the
  // SDK accepts the ACK for transmission.
  if (enqueue_reply(entry.origin,
                    static_cast<std::uint8_t>(Opcode::ResetAck), flags,
                    msg.run, msg.sequence,
                    ByteView{raw.data(), writer.size()}, now_ms, now_ms,
                    ack.accepted != 0) &&
        ack.accepted != 0) {
    reset_pending_ = true;
    reset_delay_ms_ = request.delay_ms < 20 ? 20 : request.delay_ms;
  }
}

void BenchApp::drain_replies(MonotonicMs now_ms) noexcept {
  for (ReplyEntry& reply : replies_) {
    if (!reply.used) continue;
    if (now_ms > reply.expires_ms) {
      if (reply.reset_ack) reset_pending_ = false;
      reply.used = false;
      ++stats_.reply_dropped;
      continue;
    }
    if (now_ms < reply.not_before) continue;
    SendOptions options{};
    options.delivery = DeliveryClass::Reliable;
    options.priority = Priority::Normal;
    const MonotonicMs left = reply.expires_ms - now_ms;
    options.lifetime_ms = left < kReplyTtlMs
                              ? static_cast<std::uint32_t>(left)
                              : kReplyTtlMs;
    if (options.lifetime_ms == 0) options.lifetime_ms = 1;
    MessageId id{};
    const Status status =
        node_->send(reply.destination,
                    ByteView{reply.buf.data(), reply.len}, options, now_ms, id);
    if (status) {
      reply.used = false;
      if (reply.reset_ack) {
        reset_ack_id_ = id;
        reset_ack_submitted_ = true;
        reset_at_ms_ = now_ms + options.lifetime_ms;
      }
    } else if (status.code == StatusCode::InvalidArgument ||
               status.code == StatusCode::InvalidState) {
      // Programmer error — retrying can never help.
      reply.used = false;
      if (reply.reset_ack) reset_pending_ = false;
      ++stats_.reply_send_failed;
    } else {
      // Transient (NoRoute during join, queue pressure, Busy): park with a
      // short backoff; the TTL bounds the total retry window.
      ++stats_.reply_send_failed;
      reply.not_before = now_ms + kReplyRetryMs;
      continue;
    }
  }
}

void BenchApp::drive_generator(MonotonicMs now_ms) noexcept {
  Generator& gen = generator_;
  if (!gen.active) return;
  if (gen.inflight && now_ms >= gen.inflight_deadline) {
    // The delivery result never came back inside the packet TTL — the
    // outcome is honestly unknown, not silently assumed lost.
    gen.inflight = false;
    ++gen.unknown;
    gen.last_ms = low32(now_ms);
  }
  if (!gen.inflight && !gen.dest_reset && gen.sent < gen.count &&
      now_ms >= gen.next_due && now_ms < gen.deadline_ms) {
    std::array<std::uint8_t, kMaxMessage> wire{};
    std::array<std::uint8_t, kMaxBody> body{};
    const std::uint32_t seq = gen.sequence_begin + gen.sent;
    // Body = bound destination boot || deterministic fill — the prefix is
    // what lets a reset destination refuse the stale run.
    ByteWriter prefix{MutableByteView{body.data(), kCountBindSize}};
    (void)prefix.write_u64(gen.dest_boot);
    for (std::size_t i = kCountBindSize; i < gen.payload_len; ++i) {
      body[i] = payload_byte(gen.seed, seq, static_cast<std::uint32_t>(i));
    }
    std::size_t written = 0;
    const Status encoded = encode(
        static_cast<std::uint8_t>(Opcode::CountOnly), 0, gen.uuid, seq,
        ByteView{body.data(), gen.payload_len},
        MutableByteView{wire.data(), wire.size()}, written);
    if (encoded) {
      ++gen.submitted;
      SendOptions options{};
      options.delivery = DeliveryClass::Reliable;
      options.priority = Priority::Normal;
      options.lifetime_ms = gen.ttl_ms;
      MessageId id{};
      const Status sent = node_->send(gen.destination,
                                      ByteView{wire.data(), written},
                                      options, now_ms, id);
      if (sent) {
        ++gen.admitted;
        ++gen.sent;
        gen.inflight = true;
        gen.inflight_id = id;
        // The delivery result has the packet TTL plus a slack round to land;
        // past that the outcome is unknown.
        gen.inflight_deadline = now_ms + gen.ttl_ms + 1000;
        gen.next_due = now_ms + gen.interval_ms;
        if (gen.first_ms == 0) gen.first_ms = low32(now_ms);
        gen.last_ms = low32(now_ms);
      } else {
        ++gen.failed;
        ++gen.sent;
        gen.next_due = now_ms + gen.interval_ms;
        gen.last_ms = low32(now_ms);
      }
    }
  }
  const bool exhausted = gen.sent >= gen.count;
  const bool timed_out = now_ms >= gen.deadline_ms;
  if ((exhausted || timed_out || gen.dest_reset) && !gen.inflight) {
    gen.active = false;
    gen.state = gen.dest_reset ? gen_state::kPeerReset
                : timed_out && !exhausted ? gen_state::kTimeBound
                                         : gen_state::kComplete;
    tombstone(gen.uuid);
    bump_version();
  }
}

void BenchApp::drain_delivery(MonotonicMs now_ms) noexcept {
  if (reset_ack_result_pending_) {
    reset_ack_result_pending_ = false;
    reset_pending_ = false;
    reset_ack_submitted_ = false;
    if (reset_ack_delivery_ == DeliveryState::Delivered) {
      reset_armed_ = true;
      reset_at_ms_ = now_ms + reset_delay_ms_;
    }
  } else if (reset_pending_ && reset_ack_submitted_ &&
             now_ms >= reset_at_ms_) {
    reset_pending_ = false;
    reset_ack_submitted_ = false;
  }
  for (DeliveryEvent& event : deliveries_) {
    if (!event.used) continue;
    event.used = false;
    Generator& gen = generator_;
    if (!gen.inflight || event.id != gen.inflight_id) continue;
    gen.inflight = false;
    if (gen.dest_reset) {
      // The run's destination rebooted: a MAC-level verdict cannot prove
      // the bound incarnation counted the packet — the outcome is unknown.
      ++gen.unknown;
      continue;
    }
    switch (event.state) {
      case DeliveryState::Delivered:
        ++gen.delivered;
        gen.delivered_mask |= 1ULL << (gen.sent - 1);
        break;
      case DeliveryState::Indeterminate:
        ++gen.unknown;
        break;
      default:
        ++gen.failed;
        gen.failed_mask |= 1ULL << (gen.sent - 1);
        break;
    }
  }
}

void BenchApp::drive_rollcall(MonotonicMs now_ms) noexcept {
  if (!rollcall_.pending || now_ms < rollcall_.not_before) return;
  rollcall_.pending = false;
  if (rollcall_.reply_to == kInvalidNodeId) return;
  send_status(rollcall_.reply_to, rollcall_.last_uuid, rollcall_.last_seq,
              rollcall_.page, now_ms);
  // The sample generation carried by this scheduled reply is what the next
  // rollcall compares against for "state changed since last report".
  rollcall_.version_at_reply = status_version_;
  rollcall_.announced = true;
}

void BenchApp::drive_send_load(MonotonicMs now_ms) noexcept {
  if (faults_.send_load_to == kInvalidNodeId ||
      now_ms >= faults_.send_load_until || now_ms < faults_.send_load_next) {
    return;
  }
  const std::uint32_t seq = 0x80000000u + faults_.send_load_seq;
  std::array<std::uint8_t, 16> body{};
  // Bind prefix 0: fault traffic is deliberately unbound — it makes no run
  // claim, so it counts on whichever incarnation receives it.
  ByteWriter prefix{MutableByteView{body.data(), kCountBindSize}};
  (void)prefix.write_u64(0);
  for (std::size_t i = kCountBindSize; i < body.size(); ++i) {
    body[i] = payload_byte(0x5A5A5A5Au, seq, static_cast<std::uint32_t>(i));
  }
  std::array<std::uint8_t, kMaxMessage> wire{};
  std::size_t written = 0;
  const Status encoded = encode(
      static_cast<std::uint8_t>(Opcode::CountOnly), 0, kNullRun, seq,
      ByteView{body.data(), body.size()},
      MutableByteView{wire.data(), wire.size()}, written);
  if (!encoded) return;
  SendOptions options{};
  options.delivery = DeliveryClass::Reliable;
  options.lifetime_ms = faults_.send_load_period_ms;
  MessageId id{};
  if (node_->send(faults_.send_load_to, ByteView{wire.data(), written},
                  options, now_ms, id)) {
    ++stats_.send_load_sent;
    ++faults_.send_load_seq;
  }
  faults_.send_load_next = now_ms + faults_.send_load_period_ms;
}

void BenchApp::drive_reset(MonotonicMs now_ms) noexcept {
  if (!reset_armed_ || now_ms < reset_at_ms_) return;
  reset_armed_ = false;
  ++stats_.resets_executed;
  if (platform_ != nullptr) platform_->restart();
}

void BenchApp::retire_idle_runs(MonotonicMs now_ms) noexcept {
  for (RunRecord& run : runs_) {
    if (run.used && now_ms - run.last_active > kRunIdleMs) {
      const RunUuid uuid = run.uuid;
      run = RunRecord{};
      tombstone(uuid);
    }
  }
}

void BenchApp::maybe_announce(MonotonicMs now_ms) noexcept {
  if (node_ == nullptr || !node_->started()) return;
  if (probe_ != nullptr) {
    BenchProbeSample sample{};
    probe_->sample(sample);
    if (sample.participation_valid &&
        sample.membership != static_cast<std::uint8_t>(MembershipState::Member)) {
      announced_ = false;
      return;
    }
  }
  if (announced_) return;
  NodeId controller = config_.controller;
  if (controller == kInvalidNodeId) {
    controller = node_->config().route_gateways[0];
  }
  if (controller == kInvalidNodeId) return;
  // Once per participation: announce capabilities to the controller so a
  // freshly joined bench node is discoverable without a host round-trip.
  CapabilitiesBody caps{};
  caps.app_version = config_.app_version;
  caps.run_slots = kRunSlots;
  caps.reply_queue = kReplyQueueDepth;
  caps.generator_max_inflight = kGeneratorMaxInflight;
  caps.boot_incarnation = boot_incarnation();
  caps.firmware_digest = config_.firmware_digest;
  caps.config_digest = config_.config_digest;
  std::uint8_t count = 0;
  for (std::uint8_t op = 0; op < 0x80 && count < caps.opcodes.size(); ++op) {
    if (opcode_known(op)) caps.opcodes[count++] = op;
  }
  caps.opcode_count = count;
  std::array<std::uint8_t, kMaxCommandBody> raw{};
  ByteWriter writer{MutableByteView{raw.data(), raw.size()}};
  (void)encode(caps, writer);
  const RunUuid announce_run{};
  announced_ = enqueue_reply(controller,
                             static_cast<std::uint8_t>(Opcode::Capabilities),
                             kFlagResponse, announce_run, 0,
                             ByteView{raw.data(), writer.size()}, now_ms, now_ms);
}

void BenchApp::status_page_fields(std::uint8_t page, ByteWriter& writer,
                                  MonotonicMs now_ms) noexcept {
  switch (page) {
    case status_page::kIdentity: {
      BenchProbeSample sample{};
      if (probe_ != nullptr) probe_->sample(sample);
      const NodeId self = node_ != nullptr ? node_->node_id() : kInvalidNodeId;
      (void)writer.write_u64(self);
      (void)writer.write_u8(kProtocolVersion);
      (void)writer.write_u8(config_.app_version);
      (void)writer.write_u32(low32(now_ms - attached_ms_));
      (void)writer.write_u8(platform_ != nullptr ? platform_->reset_cause() : 0);
      (void)writer.write_u32(config_.firmware_digest);
      (void)writer.write_u32(config_.config_digest);
      (void)writer.write_u64(sample.site_id);
      (void)writer.write_u32(0);  // kid fingerprint: D02/D05 pending
      break;
    }
    case status_page::kParticipation: {
      BenchProbeSample sample{};
      if (probe_ != nullptr) probe_->sample(sample);
      (void)writer.write_u8((sample.participation_valid ? 1 : 0) |
                            (sample.site_valid ? 2 : 0));
      (void)writer.write_u8(sample.mode);
      (void)writer.write_u8(sample.membership);
      (void)writer.write_u8(sample.joiner);
      (void)writer.write_u8(sample.joiner_error);
      (void)writer.write_u32(sample.joiner_observations);
      (void)writer.write_u32(sample.radio_generation);
      (void)writer.write_u8(sample.authority_flags);
      (void)writer.write_u8(sample.refresh_strikes);
      (void)writer.write_u16(sample.link_sessions);
      (void)writer.write_u16(sample.end_sessions);
      (void)writer.write_u32(sample.gk_epoch_current);
      (void)writer.write_u32(sample.gk_epoch_next);
      (void)writer.write_u32(sample.assignment_generation);
      (void)writer.write_u8(sample.role);
      // Route profile/gateway: the effective routing profile is a NodeConfig
      // adoption, so the probe reads it from the node's own config.
      (void)writer.write_u8(sample.route_profile);
      (void)writer.write_u64(sample.gateway);
      break;
    }
    case status_page::kCounters: {
      const std::uint32_t* words = &stats_.rx_total;
      const std::size_t count = sizeof(BenchStats) / sizeof(std::uint32_t);
      for (std::size_t i = 0; i < count; ++i) {
        (void)writer.write_u32(words[i]);
      }
      break;
    }
    case status_page::kRun0:
    case status_page::kRun1: {
      const RunRecord& run = runs_[page - status_page::kRun0];
      (void)writer.write_bytes(ByteView{run.uuid.data(), run.uuid.size()});
      (void)writer.write_u8(run.used ? 1 : 0);
      (void)writer.write_u32(run.unique_packets);
      (void)writer.write_u32(run.unique_bytes);
      (void)writer.write_u32(run.duplicates);
      (void)writer.write_u32(run.crc_invalid);
      (void)writer.write_u32(run.first_ms);
      (void)writer.write_u32(run.last_ms);
      (void)writer.write_u32(run.window_base);
      (void)writer.write_u64(run.window);
      break;
    }
    case status_page::kGenerator: {
      const Generator& gen = generator_;
      (void)writer.write_u8(gen.state);
      (void)writer.write_u64(gen.commander);
      (void)writer.write_bytes(
          ByteView{gen.uuid.data(), gen.uuid.size()});
      (void)writer.write_u64(gen.destination);
      (void)writer.write_u32(gen.sequence_begin);
      (void)writer.write_u16(gen.count);
      (void)writer.write_u16(gen.submitted);
      (void)writer.write_u16(gen.admitted);
      (void)writer.write_u16(gen.delivered);
      (void)writer.write_u16(gen.failed);
      (void)writer.write_u16(gen.unknown);
      (void)writer.write_u16(gen.sent);
      (void)writer.write_u32(gen.first_ms);
      (void)writer.write_u32(gen.last_ms);
      (void)writer.write_u32(gen.interval_ms);
      (void)writer.write_u8(gen.inflight ? 1 : 0);
      break;
    }
    case status_page::kResources: {
      (void)writer.write_u32(platform_ != nullptr ? platform_->heap_free_bytes() : 0);
      (void)writer.write_u32(platform_ != nullptr ? platform_->heap_min_free_bytes() : 0);
      (void)writer.write_u32(platform_ != nullptr ? platform_->heap_largest_free_bytes() : 0);
      (void)writer.write_u32(platform_ != nullptr ? platform_->stack_high_water_bytes() : 0);
      (void)writer.write_u8(platform_ != nullptr ? platform_->reset_cause() : 0);
      const std::uint16_t fault_mask =
          (now_ms < faults_.echo_suppress_until ? 1 : 0) |
          (now_ms < faults_.echo_delay_until ? 2 : 0) |
          (faults_.send_load_to != kInvalidNodeId &&
                   now_ms < faults_.send_load_until
               ? 4
               : 0);
      (void)writer.write_u16(fault_mask);
      (void)writer.write_u32(rollcall_.count);
      (void)writer.write_u32(rollcall_.last_seq);
      (void)writer.write_u32(rollcall_.last_ms);
      (void)writer.write_bytes(ByteView{rollcall_.last_uuid.data(),
                                        rollcall_.last_uuid.size()});
      break;
    }
    default:
      break;
  }
}

}  // namespace routeloom::bench
