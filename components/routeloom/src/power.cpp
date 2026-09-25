#include "routeloom/power.hpp"

#include <cstring>

#include "routeloom/byte_io.hpp"
#include "routeloom/crc32.hpp"

namespace routeloom {
namespace {

constexpr std::uint32_t kImageMagic = 0x524c5057;  // "RLPW"
constexpr std::size_t kImageHeaderSize = 32;
constexpr std::size_t kImagePeerSize = 20;
constexpr std::size_t kImagePendingSize = 157;
constexpr std::size_t kImageCrcOffset = kPowerImageRecordSize - 4;

static_assert(kImageHeaderSize +
                      kPowerPeerCacheCapacity * kImagePeerSize +
                      kPowerPendingCapacity * kImagePendingSize + 4 ==
                  kPowerImageRecordSize,
              "sleep image record layout must stay fixed-size");

Status encode_image(const PowerImage& image,
                    std::array<std::uint8_t, kPowerImageRecordSize>& out) noexcept {
  out.fill(0);
  ByteWriter writer(MutableByteView{out.data(), out.size()});
  Status status;
#define RL_WRITE(expr)            \
  do {                            \
    status = (expr);              \
    if (!status) return status;   \
  } while (false)
  RL_WRITE(writer.write_u32(kImageMagic));
  RL_WRITE(writer.write_u16(static_cast<std::uint16_t>(kPowerImageSchemaVersion)));
  RL_WRITE(writer.write_u32(image.sequence));
  RL_WRITE(writer.write_u64(image.network));
  RL_WRITE(writer.write_u64(image.node));
  RL_WRITE(writer.write_u32(image.config_revision));
  RL_WRITE(writer.write_u8(image.channel));
  RL_WRITE(writer.write_u8(0));
  for (const auto& peer : image.peers) {
    RL_WRITE(writer.write_u64(peer.node));
    RL_WRITE(writer.write_bytes(ByteView{peer.address.data(), peer.address.size()}));
    RL_WRITE(writer.write_u8(peer.address_size));
    RL_WRITE(writer.write_u16(peer.metric));
    RL_WRITE(writer.write_u8(peer.used ? 1 : 0));
  }
  for (const auto& pending : image.pending) {
    RL_WRITE(writer.write_u32(pending.original_id.session));
    RL_WRITE(writer.write_u64(pending.original_id.sequence));
    RL_WRITE(writer.write_u64(pending.destination));
    RL_WRITE(writer.write_u8(static_cast<std::uint8_t>(pending.delivery)));
    RL_WRITE(writer.write_u8(static_cast<std::uint8_t>(pending.priority)));
    RL_WRITE(writer.write_u8(pending.hop_limit));
    RL_WRITE(writer.write_u8(pending.payload_size));
    RL_WRITE(writer.write_u32(pending.stored_remaining_ms));
    RL_WRITE(writer.write_u8(pending.used ? 1 : 0));
    RL_WRITE(writer.write_bytes(ByteView{pending.payload.data(), pending.payload.size()}));
  }
#undef RL_WRITE
  if (writer.size() != kImageCrcOffset) {
    return Status::error(StatusCode::InternalError, "sleep image encode size");
  }
  const std::uint32_t crc =
      crc32_iso_hdlc(ByteView{out.data(), kImageCrcOffset});
  status = writer.write_u32(crc);
  if (!status) return status;
  return writer.size() == kPowerImageRecordSize
             ? Status::success()
             : Status::error(StatusCode::InternalError, "sleep image encode size");
}

Status decode_image(const ByteView record, PowerImage& image) noexcept {
  if (record.data == nullptr || record.size != kPowerImageRecordSize) {
    return Status::error(StatusCode::IntegrityError, "sleep image size");
  }
  const std::uint32_t expected =
      crc32_iso_hdlc(ByteView{record.data, kImageCrcOffset});
  ByteReader reader(record);
  std::uint32_t magic = 0;
  std::uint16_t schema = 0;
  Status status;
#define RL_READ(expr)             \
  do {                            \
    status = (expr);              \
    if (!status) return status;   \
  } while (false)
  RL_READ(reader.read_u32(magic));
  RL_READ(reader.read_u16(schema));
  if (magic != kImageMagic || schema != kPowerImageSchemaVersion) {
    return Status::error(StatusCode::IntegrityError, "sleep image magic/schema");
  }
  RL_READ(reader.read_u32(image.sequence));
  RL_READ(reader.read_u64(image.network));
  RL_READ(reader.read_u64(image.node));
  RL_READ(reader.read_u32(image.config_revision));
  RL_READ(reader.read_u8(image.channel));
  std::uint8_t scratch = 0;
  RL_READ(reader.read_u8(scratch));
  for (auto& peer : image.peers) {
    std::uint8_t used = 0;
    RL_READ(reader.read_u64(peer.node));
    RL_READ(reader.read_bytes(
        MutableByteView{peer.address.data(), peer.address.size()}));
    RL_READ(reader.read_u8(peer.address_size));
    RL_READ(reader.read_u16(peer.metric));
    RL_READ(reader.read_u8(used));
    peer.used = used != 0;
  }
  for (auto& pending : image.pending) {
    std::uint8_t delivery = 0;
    std::uint8_t priority = 0;
    std::uint8_t used = 0;
    RL_READ(reader.read_u32(pending.original_id.session));
    RL_READ(reader.read_u64(pending.original_id.sequence));
    RL_READ(reader.read_u64(pending.destination));
    RL_READ(reader.read_u8(delivery));
    RL_READ(reader.read_u8(priority));
    RL_READ(reader.read_u8(pending.hop_limit));
    RL_READ(reader.read_u8(pending.payload_size));
    RL_READ(reader.read_u32(pending.stored_remaining_ms));
    RL_READ(reader.read_u8(used));
    RL_READ(reader.read_bytes(
        MutableByteView{pending.payload.data(), pending.payload.size()}));
    if (delivery > static_cast<std::uint8_t>(DeliveryClass::Applied) ||
        priority > static_cast<std::uint8_t>(Priority::Urgent)) {
      return Status::error(StatusCode::IntegrityError, "sleep image enum range");
    }
    pending.delivery = static_cast<DeliveryClass>(delivery);
    pending.priority = static_cast<Priority>(priority);
    pending.used = used != 0;
    if (pending.payload_size > kMaxApplicationPayload) {
      return Status::error(StatusCode::IntegrityError, "sleep image payload size");
    }
  }
  std::uint32_t crc = 0;
  RL_READ(reader.read_u32(crc));
#undef RL_READ
  if (reader.remaining() != 0 || crc != expected) {
    return Status::error(StatusCode::IntegrityError, "sleep image crc");
  }
  return Status::success();
}

std::size_t peer_count(const PowerImage& image) noexcept {
  std::size_t count = 0;
  for (const auto& peer : image.peers) count += peer.used ? 1U : 0U;
  return count;
}

bool has_pending(const PowerImage& image) noexcept {
  for (const auto& pending : image.pending) {
    if (pending.used) return true;
  }
  return false;
}

}  // namespace

const char* power_state_name(const PowerState state) noexcept {
  switch (state) {
    case PowerState::Running: return "RUNNING";
    case PowerState::Draining: return "DRAINING";
    case PowerState::Persisting: return "PERSISTING";
    case PowerState::ReadyToSleep: return "READY_TO_SLEEP";
    case PowerState::Sleeping: return "SLEEPING";
    case PowerState::Resuming: return "RESUMING";
  }
  return "UNKNOWN";
}

const char* resume_outcome_name(const ResumeOutcome outcome) noexcept {
  switch (outcome) {
    case ResumeOutcome::None: return "NONE";
    case ResumeOutcome::ColdStart: return "COLD_START";
    case ResumeOutcome::FastResume: return "FAST_RESUME";
    case ResumeOutcome::DiscoveryRequired: return "DISCOVERY_REQUIRED";
    case ResumeOutcome::CacheLost: return "CACHE_LOST";
  }
  return "UNKNOWN";
}

ElapsedInterval classify_sleep_elapsed(const bool deep_sleep_wake, const bool timer_wake,
                                       const bool marker_ok,
                                       const std::uint32_t programmed_ms) noexcept {
  ElapsedInterval out{};
  if (!deep_sleep_wake || !timer_wake || !marker_ok || programmed_ms == 0) return out;
  out.lower_ms = programmed_ms;
  // u64 arithmetic: a u32 program plus the margin cannot wrap below lower.
  out.upper_ms = static_cast<std::uint64_t>(programmed_ms) + kSleepWakeBootMarginMs;
  out.known = true;
  return out;
}

PowerCoordinator::PowerCoordinator(const PowerConfig& config, MeshNode& node,
                                   PowerPort& port, PowerStorage& storage,
                                   PowerEvents& events) noexcept
    : config_(config), node_(node), port_(port), storage_(storage),
      events_(events) {
  save_target_.fill(0xFF);
}

void PowerCoordinator::notify_transition(const PowerState from,
                                         const PowerState to,
                                         const char* reason) noexcept {
  CallbackScope callback(in_callback_);
  events_.on_transition(from, to, reason);
}

void PowerCoordinator::notify_pending_result(
    const PendingDeliveryRecord& record, const StatusCode result) noexcept {
  CallbackScope callback(in_callback_);
  events_.on_pending_result(record, result);
}

void PowerCoordinator::notify_diagnostic(const char* reason) noexcept {
  CallbackScope callback(in_callback_);
  events_.on_diagnostic(reason);
}

void PowerCoordinator::transition(const PowerState next,
                                  const char* reason) noexcept {
  if (state_ == next) return;
  const PowerState from = state_;
  // Post-state notification: the new state is fully in effect (mask and
  // ticket updates included) before the application runs, so a callback
  // observes `to` from state(). Mutating calls from the callback are Busy —
  // nothing overwrites this assignment behind the notification.
  state_ = next;
  notify_transition(from, next, reason);
}

std::uint32_t PowerCoordinator::pending_generation() const noexcept {
  return node_.work_generation() + app_events_;
}

bool PowerCoordinator::ticket_valid(const SleepTicket& ticket) const noexcept {
  return ticket.issued && ticket_.issued && ticket.id == ticket_.id &&
         ticket.radio_generation == radio_generation_ &&
         ticket.config_revision == node_.config_revision() &&
         ticket.pending_generation == pending_generation();
}

void PowerCoordinator::issue_ticket() noexcept {
  ticket_ = SleepTicket{next_ticket_id_++, radio_generation_,
                        node_.config_revision(), pending_generation(), true};
}

Status PowerCoordinator::begin(const ResetCause cause,
                               const ElapsedInterval elapsed,
                               const MonotonicMs now_ms) noexcept {
  if (in_callback()) {
    return Status::error(StatusCode::Busy, "POWER_IN_CALLBACK");
  }
  if (begun_) {
    return Status::error(StatusCode::AlreadyExists, "coordinator already begun");
  }
  begun_ = true;
  cause_ = cause;
  transition(PowerState::Resuming,
             cause == ResetCause::DeepSleepWake ? "WAKE_DEEP_SLEEP" : "BOOT");
  resume_flow(cause, elapsed, now_ms);
  return Status::success();
}

Status PowerCoordinator::sleep_prepare(const SleepRequest& request,
                                       const MonotonicMs now_ms) noexcept {
  if (in_callback()) {
    return Status::error(StatusCode::Busy, "POWER_IN_CALLBACK");
  }
  if (!begun_ || !node_.started()) {
    return Status::error(StatusCode::InvalidState, "not running");
  }
  if (state_ != PowerState::Running) {
    return Status::error(StatusCode::InvalidState, "not running");
  }
  if (image_sequence_ == UINT32_MAX) {
    return Status::error(StatusCode::CounterExhausted,
                         "SLEEP_SEQUENCE_EXHAUSTED");
  }
  start_prepare(request, now_ms);
  return Status::success();
}

Status PowerCoordinator::sleep_abort(const char* reason) noexcept {
  if (in_callback()) {
    return Status::error(StatusCode::Busy, "POWER_IN_CALLBACK");
  }
  if (!sleep_attempt_active()) {
    return Status::error(StatusCode::InvalidState, "no sleep in progress");
  }
  if (reason == nullptr) reason = "SLEEP_ABORT_REQUEST";
  // Immediate: the reason is consumed synchronously by the notification
  // below, never retained, so no copy is needed.
  abort_to_running(reason);
  return Status::success();
}

Status PowerCoordinator::sleep_enter(const SleepTicket& ticket,
                                     const MonotonicMs now_ms) noexcept {
  if (in_callback()) {
    return Status::error(StatusCode::Busy, "POWER_IN_CALLBACK");
  }
  // Value-copy the ticket at receipt: callers may alias ticket() itself,
  // which later calls invalidate — the copy below stays intact.
  const SleepTicket submitted = ticket;
  // Receipt gate: READY, armed image, current ticket.
  // A rejection here changes nothing — a bogus ticket alone never consumes
  // or destroys the outstanding one.
  if (!validate_enter(submitted, false)) {
    if (state_ != PowerState::ReadyToSleep) {
      return Status::error(StatusCode::InvalidState, "not ready to sleep");
    }
    if (!image_valid_ || !sleep_image_armed_) {
      return Status::error(StatusCode::InvalidState, "SLEEP_IMAGE_MISSING");
    }
    return Status::error(StatusCode::InvalidState, "SLEEP_TICKET_INVALID");
  }
  return run_enter(submitted, now_ms);
}

bool PowerCoordinator::validate_enter(const SleepTicket& ticket,
                                      const bool handoff) const noexcept {
  if (handoff) {
    if (state_ != PowerState::Sleeping || !entering_) return false;
  } else if (state_ != PowerState::ReadyToSleep) {
    return false;
  }
  if (!ticket.issued || !ticket_.issued || ticket.id != ticket_.id) return false;
  if (ticket.radio_generation != radio_generation_) return false;
  if (ticket.config_revision != node_.config_revision()) return false;
  if (ticket.pending_generation != pending_generation()) return false;
  if (!image_valid_ || !sleep_image_armed_) return false;
  for (const auto plan : carry_plan_) {
    if (plan == CarryPlanKind::Expired) {
      return false;  // un-notified carry plan: settlement did not finish
    }
  }
  if (!node_.draining() || !radio_quiesced_) return false;
  return true;
}

Status PowerCoordinator::run_enter(const SleepTicket& ticket,
                                   const MonotonicMs now_ms) noexcept {
  // Execution-start gate: the ticket was valid at receipt; re-check before
  // touching anything.
  if (!validate_enter(ticket, false)) {
    abort_to_running("SLEEP_TICKET_INVALID");
    return Status::error(StatusCode::InvalidState, "SLEEP_TICKET_INVALID");
  }
  // Time spent waiting in READY_TO_SLEEP is real elapsed lifetime: plan the
  // refresh from the carry set's absolute deadlines first, commit it, and
  // only then terminate what expired while waiting — never the reverse.
  std::array<bool, kPowerPendingCapacity> expired_mask{};
  std::array<std::uint32_t, kPowerPendingCapacity> refreshed{};
  bool changed = false;
  for (std::size_t i = 0; i < carry_.size(); ++i) {
    if (!carry_[i].used) continue;
    if (carry_[i].expires_at_ms <= now_ms) {
      expired_mask[i] = true;
      changed = true;
      continue;
    }
    refreshed[i] =
        static_cast<std::uint32_t>(carry_[i].expires_at_ms - now_ms);
    if (refreshed[i] != carry_[i].stored_remaining_ms) changed = true;
  }
  if (changed) {
    PowerImage refresh = image_;
    for (auto& record : refresh.pending) record.used = false;
    for (std::size_t i = 0; i < carry_.size(); ++i) {
      if (!carry_[i].used) continue;
      refresh.pending[i] = carry_[i];
      refresh.pending[i].stored_remaining_ms = refreshed[i];
    }
    // The first slot retains every carried record, including those whose
    // lifetime reached zero. If the final image does not land, reboot still
    // reports their expiry.
    for (std::uint8_t copy = 0; copy < kPowerImageSlots; ++copy) {
      if (copy != 0) {
        for (std::size_t i = 0; i < carry_.size(); ++i) {
          if (expired_mask[i]) refresh.pending[i].used = false;
        }
      }
      if (!next_image_sequence(refresh.sequence)) {
        ticket_ = SleepTicket{};
        sleep_image_armed_ = false;
        disk_pending_possible_ = true;
        abort_to_running("SLEEP_SEQUENCE_EXHAUSTED");
        return Status::error(StatusCode::CounterExhausted,
                             "SLEEP_SEQUENCE_EXHAUSTED");
      }
      const auto commit = commit_image(refresh);
      if (!commit) {
        // Abort instead of sleeping on a stale image, with no new Expired
        // notification: the refresh never landed, so nothing terminated.
        ticket_ = SleepTicket{};
        sleep_image_armed_ = false;
        abort_to_running(commit.detail);
        return commit;
      }
    }
    disk_pending_possible_ = has_pending(refresh);
    for (std::size_t i = 0; i < carry_.size(); ++i) {
      if (carry_[i].used && !expired_mask[i]) {
        carry_[i].stored_remaining_ms = refreshed[i];
      }
    }
  }
  // Terminate what the refresh dropped. The notifications below are app
  // callbacks: a refused send from one still retires the ticket's
  // generation, so the entry revalidates before the handoff.
  for (std::size_t i = 0; i < carry_.size(); ++i) {
    if (!carry_[i].used || !expired_mask[i]) continue;
    const PendingDeliveryRecord record = carry_[i];
    carry_[i].used = false;
    carry_plan_[i] = CarryPlanKind::Unused;
    notify_pending_result(record, StatusCode::Expired);
  }
  if (!validate_enter(ticket, false)) {
    abort_to_running("SLEEP_TICKET_INVALID");
    return Status::error(StatusCode::InvalidState, "SLEEP_TICKET_INVALID");
  }
  // Handoff begins. SLEEP_ENTER reports "platform handoff in progress", not
  // proof of physical sleep: a failed wake setup still aborts from here.
  entering_ = true;
  transition(PowerState::Sleeping, "SLEEP_ENTER");
  if (!validate_enter(ticket, true)) {
    entering_ = false;
    abort_to_running("SLEEP_TICKET_INVALID");
    return Status::error(StatusCode::InvalidState, "SLEEP_TICKET_INVALID");
  }
  auto status = port_.configure_wake(request_.wake);
  if (!status) {
    entering_ = false;
    abort_to_running("SLEEP_ENTER_FAILED");
    return status;
  }
  // Final gate and the single port call with no application callback
  // between them: nothing can invalidate the ticket in this gap.
  if (!validate_enter(ticket, true)) {
    entering_ = false;
    abort_to_running("SLEEP_TICKET_INVALID");
    return Status::error(StatusCode::InvalidState, "SLEEP_TICKET_INVALID");
  }
  ticket_ = SleepTicket{};  // consume: at most one platform enter per ticket
  sleep_image_armed_ = false;
  status = port_.enter_sleep();
  entering_ = false;
  if (!status) {
    abort_to_running("SLEEP_ENTER_FAILED");
    return status;
  }
  return Status::success();
}

Status PowerCoordinator::wake(const ResetCause cause,
                              const ElapsedInterval elapsed,
                              const MonotonicMs now_ms) noexcept {
  if (in_callback()) {
    return Status::error(StatusCode::Busy, "POWER_IN_CALLBACK");
  }
  if (state_ != PowerState::Sleeping) {
    return Status::error(StatusCode::InvalidState, "not sleeping");
  }
  cause_ = cause;
  transition(PowerState::Resuming, "WAKE");
  resume_flow(cause, elapsed, now_ms);
  return Status::success();
}

Status PowerCoordinator::notify_app_event() noexcept {
  if (in_callback()) {
    return Status::error(StatusCode::Busy, "POWER_IN_CALLBACK");
  }
  ++app_events_;
  if (sleep_attempt_active()) {
    abort_to_running("SLEEP_TICKET_INVALID");
  }
  return Status::success();
}

Status PowerCoordinator::notify_radio_reset() noexcept {
  if (in_callback()) {
    return Status::error(StatusCode::Busy, "POWER_IN_CALLBACK");
  }
  ++radio_generation_;
  if (sleep_attempt_active()) {
    abort_to_running("SLEEP_TICKET_INVALID");
  }
  return Status::success();
}

void PowerCoordinator::poll(const MonotonicMs now_ms) noexcept {
  // Re-entrant drive from a callback is a silent no-op: no side effects, no
  // diagnostic.
  if (in_callback()) return;
  switch (state_) {
    case PowerState::Running:
      node_.poll(now_ms);
      break;
    case PowerState::Draining: {
      node_.poll(now_ms);
      if (node_.quiesced() || now_ms >= drain_deadline_ms_) {
        settle_current_attempt(now_ms);
      }
      break;
    }
    case PowerState::ReadyToSleep:
      // Radio is quiesced; a ticket invalidated by late activity aborts the
      // sleep attempt instead of entering on a stale snapshot.
      if (!ticket_valid(ticket_)) {
        abort_to_running("SLEEP_TICKET_INVALID");
      }
      break;
    case PowerState::Resuming:
      node_.poll(now_ms);
      // Only inbound peer traffic confirms a fast resume: a failed TX
      // callback or an app send must not count as peers answering.
      if (node_.rx_generation() != confirm_baseline_) {
        outcome_ = ResumeOutcome::FastResume;
        transition(PowerState::Running, "RESUME_CONFIRMED");
      } else if (now_ms >= resume_deadline_ms_) {
        if (!discovery_started_) {
          discovery_started_ = true;
          const auto discovery = port_.start_discovery(image_);
          notify_diagnostic(discovery ? "RESUME_DISCOVERY_STARTED"
                                      : discovery.detail);
        }
        outcome_ = ResumeOutcome::DiscoveryRequired;
        transition(PowerState::Running, "RESUME_UNCONFIRMED");
      }
      break;
    case PowerState::Persisting:
    case PowerState::Sleeping:
      break;
  }
}

void PowerCoordinator::start_prepare(const SleepRequest& request,
                                     const MonotonicMs start_at) noexcept {
  request_ = request;
  node_.set_draining(true);
  drain_deadline_ms_ = start_at + config_.drain_timeout_ms;
  sleep_image_armed_ = false;
  transition(PowerState::Draining, "SLEEP_PREPARE");
}

void PowerCoordinator::settle_current_attempt(const MonotonicMs now_ms) noexcept {
  transition(PowerState::Persisting,
             node_.quiesced() ? "DRAIN_SETTLED" : "DRAIN_DEADLINE");
  // Phase 1: plan and commit WITHOUT changing delivery state or notifying.
  // A failure here aborts with live work, carry set and holds untouched.
  plan_sleep_image(now_ms);
  const auto status = persist_image(now_ms);
  if (!status) {
    abort_to_running(status.detail);
    return;
  }
  // Phase 2: the image is durable — only now settle. Every callback below
  // still sees PERSISTING with the node draining: send()/send_group() are
  // refused by the drain pause, and coordinator calls are Busy, so the
  // settlement always runs to completion — no abort can land mid-way.
  for (std::size_t i = 0; i < carry_.size(); ++i) {
    if (carry_plan_[i] != CarryPlanKind::Expired) {
      continue;
    }
    const PendingDeliveryRecord record = carry_[i];
    carry_[i].used = false;
    carry_plan_[i] = CarryPlanKind::Unused;
    notify_pending_result(record, StatusCode::Expired);
  }
  while (node_.settle_one_sleep_delivery(
      request_.pending_policy,
      [&](const MessageId& id) { return claim_saved(id); })) {
  }
  while (node_.settle_one_sleep_group_origin(request_.pending_policy)) {
  }
  while (true) {
    const SleepHoldRelease released = node_.release_one_group_hold_for_sleep();
    if (released == SleepHoldRelease::NonePending) break;
    if (released == SleepHoldRelease::StreamInvariant) {
      // Holds are kept; the attempt cannot honestly proceed to a ticket.
      abort_to_running("GROUP_HOLD_STREAM_MISSING");
      return;
    }
  }
  node_.quiesce_for_sleep();
  const auto radio = port_.quiesce_radio();
  if (!radio) {
    abort_to_running(radio.detail);
    return;
  }
  radio_quiesced_ = true;
  ++radio_generation_;
  // Pre-ticket gate: leftover plans or unclaimed records mean the commit
  // and the settlement disagree — abort instead of issuing a ticket on
  // half-settled books. Refused sends need no gate here: their
  // work_generation bump is baked into the freshly issued ticket, and the
  // caller already saw the deterministic NODE_DRAINING error.
  if (!sleep_books_consistent()) {
    abort_to_running("SLEEP_BOOKS_INCONSISTENT");
    return;
  }
  issue_ticket();
  sleep_image_armed_ = true;
  transition(PowerState::ReadyToSleep, "SLEEP_READY");
}

void PowerCoordinator::plan_sleep_image(const MonotonicMs now_ms) noexcept {
  for (auto& record : image_.pending) record = PendingDeliveryRecord{};
  fresh_live_mask_ = 0;
  for (auto& plan : carry_plan_) plan = CarryPlanKind::Unused;
  save_target_.fill(0xFF);
  saved_live_mask_ = 0;
  image_.network = node_.config().network;
  image_.node = node_.config().node;
  // Carry first: an un-notified durable carry is NEVER evicted from the
  // candidate by fresh work. Settlement always runs to completion, so a
  // carry left out of the candidate would be dropped, never retried —
  // fresh overflow instead fails its live delivery loudly
  // (SLEEP_PERSIST_FULL) in phase 2. A carry that outlived its deadline
  // while awake terminates loudly in phase 2. The carry set fits the
  // candidate by construction (same capacity).
  std::array<std::uint8_t, kPowerPendingCapacity> carry_slot{};
  carry_slot.fill(0xFF);
  for (std::size_t j = 0; j < carry_.size(); ++j) {
    if (!carry_[j].used) continue;
    if (carry_[j].expires_at_ms <= now_ms) {
      carry_plan_[j] = CarryPlanKind::Expired;
      continue;
    }
    for (std::size_t i = 0; i < image_.pending.size(); ++i) {
      if (image_.pending[i].used) continue;
      image_.pending[i] = carry_[j];
      image_.pending[i].stored_remaining_ms =
          static_cast<std::uint32_t>(carry_[j].expires_at_ms - now_ms);
      carry_slot[i] = static_cast<std::uint8_t>(j);
      break;
    }
    carry_plan_[j] = CarryPlanKind::Keep;
  }
  const auto fill_slot = [&](const std::size_t i,
                               const DeliverySnapshot& snapshot) noexcept {
    PendingDeliveryRecord& record = image_.pending[i];
    record.used = true;
    record.original_id = snapshot.id;
    record.destination = snapshot.destination;
    record.delivery = snapshot.options.delivery;
    record.priority = snapshot.options.priority;
    record.hop_limit = snapshot.options.hop_limit;
    record.expires_at_ms = snapshot.expires_at_ms;
    record.stored_remaining_ms =
        static_cast<std::uint32_t>(snapshot.expires_at_ms - now_ms);
    record.payload_size = static_cast<std::uint8_t>(snapshot.payload.size);
    if (snapshot.payload.size != 0) {
      std::memcpy(record.payload.data(), snapshot.payload.data,
                  snapshot.payload.size);
    }
    fresh_live_mask_ = static_cast<std::uint8_t>(
        fresh_live_mask_ | static_cast<std::uint8_t>(1U << i));
  };
  // Fresh snapshot into the remaining room: durable work, or every live
  // delivery under Save. Expired live work is never persisted. A fresh
  // record that re-persists a carried id supersedes its namesake in place
  // (no extra slot); one that finds the candidate full is simply not
  // placed — phase 2 fails it as SLEEP_PERSIST_FULL, never silently.
  node_.snapshot_for_sleep(request_.pending_policy,
                           [&](const DeliverySnapshot& snapshot) {
                             if (snapshot.expires_at_ms <= now_ms) return false;
                             for (std::size_t i = 0; i < image_.pending.size();
                                  ++i) {
                               if (!image_.pending[i].used) continue;
                               if ((fresh_live_mask_ &
                                    static_cast<std::uint8_t>(1U << i)) != 0) {
                                 continue;
                               }
                               if (!(image_.pending[i].original_id ==
                                     snapshot.id)) {
                                 continue;
                               }
                               fill_slot(i, snapshot);
                               const std::uint8_t target = carry_slot[i];
                               if (target < carry_.size()) {
                                 carry_plan_[target] =
                                     CarryPlanKind::CoveredByFresh;
                                 save_target_[i] = target;
                               }
                               return true;
                             }
                             for (std::size_t i = 0; i < image_.pending.size();
                                  ++i) {
                               if (image_.pending[i].used) continue;
                               fill_slot(i, snapshot);
                               return true;
                             }
                             return false;
                           });
  // Claim targets: every other fresh record takes a free carry slot.
  // Fresh-placed + Keep <= capacity by construction above. Expired slots
  // count as free here: phase 2 consumes them before the first claim runs,
  // so they are available when the claims land. A missing slot (impossible
  // by the counting above) defensively settles as unsaved.
  for (std::size_t i = 0; i < image_.pending.size(); ++i) {
    if ((fresh_live_mask_ & static_cast<std::uint8_t>(1U << i)) == 0 ||
        save_target_[i] != 0xFF) {
      continue;
    }
    for (std::size_t j = 0; j < carry_.size(); ++j) {
      const bool reusable =
          !carry_[j].used || carry_plan_[j] == CarryPlanKind::Expired;
      if (!reusable) continue;
      bool taken = false;
      for (const auto target : save_target_) taken = taken || target == j;
      if (!taken) {
        save_target_[i] = static_cast<std::uint8_t>(j);
        break;
      }
    }
  }
}

bool PowerCoordinator::claim_saved(const MessageId& id) noexcept {
  for (std::size_t i = 0; i < image_.pending.size(); ++i) {
    if (!image_.pending[i].used ||
        (fresh_live_mask_ & static_cast<std::uint8_t>(1U << i)) == 0 ||
        !(image_.pending[i].original_id == id)) {
      continue;
    }
    const std::uint8_t target = save_target_[i];
    if (target >= carry_.size()) return false;  // defensive: unsettled
    carry_[target] = image_.pending[i];
    carry_[target].used = true;
    // The target was a CoveredByFresh slot (replaced in place), a free
    // slot, or an Expired slot phase 2 already consumed: in all cases it
    // now holds a live carried record.
    carry_plan_[target] = CarryPlanKind::Keep;
    saved_live_mask_ = static_cast<std::uint8_t>(
        saved_live_mask_ | static_cast<std::uint8_t>(1U << i));
    return true;
  }
  return false;
}

bool PowerCoordinator::sleep_books_consistent() const noexcept {
  for (const auto plan : carry_plan_) {
    if (plan == CarryPlanKind::Expired) {
      return false;
    }
  }
  for (const auto& carried : carry_) {
    if (!carried.used) continue;
    bool in_candidate = false;
    for (const auto& record : image_.pending) {
      if (record.used && record.original_id == carried.original_id) {
        in_candidate = true;
        break;
      }
    }
    if (!in_candidate) return false;
  }
  for (std::size_t i = 0; i < image_.pending.size(); ++i) {
    if ((fresh_live_mask_ & static_cast<std::uint8_t>(1U << i)) != 0 &&
        (saved_live_mask_ & static_cast<std::uint8_t>(1U << i)) == 0) {
      return false;
    }
  }
  return true;
}

Status PowerCoordinator::persist_image(const MonotonicMs now_ms) noexcept {
  // Durable commit only: capture the platform cache and write the image.
  // Radio quiesce, the ticket and the READY_TO_SLEEP transition belong to
  // the settlement chain AFTER the dispositions — issuing them here would
  // let a callback observe READY_TO_SLEEP while its own work is still
  // being torn down. Callback-free: live work, carry set and holds stay
  // untouched, so any failure aborts with nothing half-settled.
  if (!next_image_sequence(image_.sequence)) {
    disk_pending_possible_ = true;
    return Status::error(StatusCode::CounterExhausted,
                         "SLEEP_SEQUENCE_EXHAUSTED");
  }
  image_.config_revision = node_.config_revision();
  auto status = port_.capture_cache(image_);
  if (!status) return status;
  // An older slot may still hold pending records. When two writes are needed,
  // the first keeps every carried record (with its current remaining life):
  // if the final image does not land, reboot must not lose a carry whose
  // expiry or same-id replacement phase 2 never reported. The final
  // candidate lands only in the second slot, after the retained set is
  // safely staged.
  const bool dual_write = disk_pending_possible_;
  if (dual_write) {
    PowerImage staged = image_;
    for (auto& record : staged.pending) record = PendingDeliveryRecord{};
    for (std::size_t i = 0; i < carry_.size(); ++i) {
      if (!carry_[i].used) continue;
      staged.pending[i] = carry_[i];
      staged.pending[i].stored_remaining_ms =
          carry_[i].expires_at_ms > now_ms
              ? static_cast<std::uint32_t>(carry_[i].expires_at_ms - now_ms)
              : 0;
    }
    // Keep fresh candidate records in the room left by carry. A record
    // successfully re-injected on wake is live rather than carried, but its
    // durable copy must not disappear if the final write fails.
    for (const auto& candidate : image_.pending) {
      if (!candidate.used) continue;
      bool present = false;
      for (const auto& record : staged.pending) {
        present = present ||
                  (record.used && record.original_id == candidate.original_id);
      }
      if (present) continue;
      for (auto& record : staged.pending) {
        if (record.used) continue;
        record = candidate;
        break;
      }
    }
    status = commit_image(staged);
    if (!status) return status;
    if (!next_image_sequence(image_.sequence)) {
      disk_pending_possible_ = true;
      return Status::error(StatusCode::CounterExhausted,
                           "SLEEP_SEQUENCE_EXHAUSTED");
    }
  }
  status = commit_image(image_);
  if (!status) return status;
  disk_pending_possible_ = has_pending(image_);
  return Status::success();
}

bool PowerCoordinator::next_image_sequence(std::uint32_t& out) noexcept {
  if (image_sequence_ == UINT32_MAX) return false;
  out = image_sequence_ + 1;
  return true;
}

Status PowerCoordinator::commit_image(const PowerImage& image) noexcept {
  std::array<std::uint8_t, kPowerImageRecordSize> record{};
  auto status = encode_image(image, record);
  if (!status) {
    image_sequence_ = image.sequence;  // numbering is consumed regardless
    disk_pending_possible_ = true;
    return status;
  }
  status = storage_.write(static_cast<std::uint8_t>(image.sequence & 1U),
                          ByteView{record.data(), record.size()});
  if (!status) {
    // A failed write may still have torn the slot: numbering is consumed so
    // the sequence is never reused, and the slot counts as suspect.
    image_sequence_ = image.sequence;
    disk_pending_possible_ = true;
    return status;
  }
  image_sequence_ = image.sequence;
  image_valid_ = true;
  return Status::success();
}

Status PowerCoordinator::load_image(PowerImage& image, bool& found) noexcept {
  found = false;
  std::array<std::uint8_t, kPowerImageRecordSize> record{};
  bool any = false;
  bool any_pending = false;
  std::uint32_t best_sequence = 0;
  for (std::uint8_t slot = 0; slot < kPowerImageSlots; ++slot) {
    const auto status =
        storage_.read(slot, MutableByteView{record.data(), record.size()});
    if (!status) {
      notify_diagnostic(status.detail);
      continue;
    }
    PowerImage candidate{};
    if (!decode_image(ByteView{record.data(), record.size()}, candidate)) {
      continue;  // torn/corrupt slot: discard, never erase
    }
    any_pending = any_pending || has_pending(candidate);
    if (!any || candidate.sequence > best_sequence) {
      image = candidate;
      best_sequence = candidate.sequence;
      any = true;
    }
  }
  if (any) {
    found = true;
    image_sequence_ = best_sequence;
  }
  disk_pending_possible_ = any_pending;
  return Status::success();
}

bool PowerCoordinator::image_usable(const PowerImage& image) const noexcept {
  // Identity binding only. config_revision is persisted in the image for
  // diagnostics but deliberately not compared here: MeshNode::config_revision
  // also bumps on runtime peer add/remove, so a freshly-booted node would
  // never match a stored image and every resume would degrade to cold start.
  return image.network == node_.config().network &&
         image.node == node_.config().node;
}

void PowerCoordinator::resume_flow(const ResetCause cause,
                                   const ElapsedInterval elapsed,
                                   const MonotonicMs now_ms) noexcept {
  outcome_ = ResumeOutcome::None;
  discovery_started_ = false;
  radio_quiesced_ = false;
  image_valid_ = false;
  sleep_image_armed_ = false;
  for (auto& record : carry_) record = PendingDeliveryRecord{};
  for (auto& plan : carry_plan_) plan = CarryPlanKind::Unused;

  PowerImage stored{};
  bool found = false;
  (void)load_image(stored, found);
  const bool usable = found && image_usable(stored);
  if (found && !usable) {
    notify_diagnostic("SLEEP_IMAGE_CONTEXT_MISMATCH");
  }

  // Saved peers first, then the platform's current peer table (static config
  // covers the cold path). Duplicates keep the platform record — it is the
  // authoritative current configuration.
  PowerImage platform{};
  (void)port_.capture_cache(platform);
  PowerImage merged = usable ? stored : PowerImage{};
  for (const auto& peer : platform.peers) {
    if (!peer.used) continue;
    bool placed = false;
    for (auto& slot : merged.peers) {
      if (slot.used && slot.node == peer.node) {
        slot = peer;
        placed = true;
      }
    }
    if (placed) continue;
    for (auto& slot : merged.peers) {
      if (!slot.used) {
        slot = peer;
        break;
      }
    }
  }
  merged.channel = usable && stored.channel != 0 ? stored.channel
                                                 : platform.channel;

  ++radio_generation_;
  const auto radio = port_.start_radio(&merged);
  if (!radio) notify_diagnostic(radio.detail);

  if (!node_.started()) {
    (void)node_.start(now_ms);
  }
  node_.set_draining(false);
  for (const auto& peer : merged.peers) {
    if (peer.used) {
      (void)node_.add_neighbor(peer.node, peer.metric, now_ms);
    }
  }

  if (usable) {
    restore_pending(stored, elapsed, now_ms, merged);
    if (has_pending(stored)) {
      // Consume only the pendings that were re-injected; records whose send
      // failed stay in `merged.pending` so the next sleep image retains them
      // instead of silently dropping durable work. A single slot: the other
      // still holds the pre-consume image, which is exactly what
      // disk_pending_possible_ remembers for the next phase 1.
      if (next_image_sequence(merged.sequence)) {
        (void)commit_image(merged);
      }
    }
    // The retained records become this incarnation's carry set; the next
    // prepare plans them into its candidate explicitly.
    for (std::size_t i = 0; i < carry_.size(); ++i) {
      carry_[i] = merged.pending[i];
    }
  }
  image_ = merged;

  if (peer_count(merged) == 0) {
    const bool expected = cause == ResetCause::DeepSleepWake;
    outcome_ = usable ? ResumeOutcome::ColdStart
                      : (expected || found) ? ResumeOutcome::CacheLost
                                            : ResumeOutcome::ColdStart;
    transition(PowerState::Running, "COLD_START");
    return;
  }
  confirm_baseline_ = node_.rx_generation();
  resume_deadline_ms_ = now_ms + config_.resume_confirm_ms;
  // Stay RESUMING: poll() confirms saved peers inside the window or starts
  // bounded discovery on expiry.
}

void PowerCoordinator::restore_pending(const PowerImage& image,
                                       const ElapsedInterval elapsed,
                                       const MonotonicMs now_ms,
                                       PowerImage& retained) noexcept {
  for (std::size_t i = 0; i < image.pending.size(); ++i) {
    const PendingDeliveryRecord& record = image.pending[i];
    if (!record.used) continue;
    // Same-index slot in `retained` tracks what survives this resume. The
    // default below is "consumed": mark the retained copy unused unless the
    // re-inject fails and the record must outlive this boot.
    PendingDeliveryRecord* keep =
        i < retained.pending.size() ? &retained.pending[i] : nullptr;
    if (keep != nullptr) keep->used = false;
    std::uint32_t remaining = 0;
    const auto resumed = resume_remaining_lifetime(
        config_.deadline_policy, record.stored_remaining_ms, elapsed, remaining);
    if (!resumed) {
      // TIME_UNCERTAIN/EXPIRED: never auto-resend on a fabricated clock.
      notify_pending_result(record, resumed.code);
      continue;
    }
    const SendOptions options{record.delivery, record.priority, remaining,
                              record.hop_limit, true};
    // Resume under the ORIGINAL logical id, not a fresh send() allocation:
    // the destination may already have delivered the payload and lost only
    // the end receipt — terminal dedup keyed on this id must still suppress
    // the retransmission so the application never sees it twice. Fresh link
    // counters are fine; logical identity is what dedup tracks.
    const auto sent = node_.resume_delivery(
        record.original_id, record.destination,
        ByteView{record.payload.data(), record.payload_size}, options, now_ms);
    if (!sent.ok() && keep != nullptr) {
      // Re-injection failed (queue full, draining, ...): keep the durable
      // record — with the decayed lifetime — so a later sleep image retries
      // it instead of dropping it at the storage layer. expires_at_ms is
      // RAM-only bookkeeping, so it is re-anchored on this boot's clock and
      // awake time still counts against the deadline. Settled BEFORE the
      // notification below, so a callback observes final bookkeeping.
      *keep = record;
      keep->used = true;
      keep->stored_remaining_ms = remaining;
      keep->expires_at_ms = now_ms + remaining;
    }
    notify_pending_result(record, sent.ok() ? StatusCode::Ok : sent.code);
  }
}

void PowerCoordinator::abort_to_running(const char* reason) noexcept {
  // All teardown first, notifications last: a mutating call inside the
  // notifications below is Busy — it can never re-run this worker.
  ticket_ = SleepTicket{};
  sleep_image_armed_ = false;
  Status radio_status = Status::success();
  if (radio_quiesced_) {
    ++radio_generation_;
    radio_status = port_.start_radio(&image_);
    radio_quiesced_ = false;
  }
  node_.set_draining(false);
  const PowerState from = state_;
  state_ = PowerState::Running;
  notify_diagnostic(reason);
  // A failed radio restart is surfaced, never hidden: RUNNING means control
  // is back with the owner, not that the radio is healthy. The ticket stays
  // invalid and later radio errors take the normal recovery path.
  if (!radio_status) notify_diagnostic(radio_status.detail);
  if (from != PowerState::Running) {
    notify_transition(from, PowerState::Running, "SLEEP_ABORTED");
  }
}

}  // namespace routeloom
