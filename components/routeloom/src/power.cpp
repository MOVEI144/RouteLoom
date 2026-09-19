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

PowerCoordinator::PowerCoordinator(const PowerConfig& config, MeshNode& node,
                                   PowerPort& port, PowerStorage& storage,
                                   PowerEvents& events) noexcept
    : config_(config), node_(node), port_(port), storage_(storage),
      events_(events) {}

void PowerCoordinator::transition(const PowerState next,
                                  const char* reason) noexcept {
  if (state_ == next) return;
  events_.on_transition(state_, next, reason);
  state_ = next;
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
  if (!begun_ || state_ != PowerState::Running || !node_.started()) {
    return Status::error(StatusCode::InvalidState, "not running");
  }
  request_ = request;
  node_.set_draining(true);
  drain_deadline_ms_ = now_ms + config_.drain_timeout_ms;
  transition(PowerState::Draining, "SLEEP_PREPARE");
  return Status::success();
}

Status PowerCoordinator::sleep_abort(const char* reason) noexcept {
  if (state_ != PowerState::Draining && state_ != PowerState::ReadyToSleep) {
    return Status::error(StatusCode::InvalidState, "no sleep in progress");
  }
  abort_to_running(reason == nullptr ? "SLEEP_ABORT_REQUEST" : reason);
  return Status::success();
}

Status PowerCoordinator::sleep_enter(const SleepTicket& ticket,
                                     const MonotonicMs now_ms) noexcept {
  (void)now_ms;
  if (state_ != PowerState::ReadyToSleep) {
    return Status::error(StatusCode::InvalidState, "not ready to sleep");
  }
  if (!image_valid_) {
    // READY_TO_SLEEP is only reachable after commit_image() succeeded, but
    // re-check the durable flag: entering deep sleep without a committed
    // image would silently lose the resume context.
    return Status::error(StatusCode::InvalidState, "SLEEP_IMAGE_MISSING");
  }
  if (!ticket_valid(ticket)) {
    return Status::error(StatusCode::InvalidState, "SLEEP_TICKET_INVALID");
  }
  ticket_ = SleepTicket{};  // consume: no other ticket can re-enter
  transition(PowerState::Sleeping, "SLEEP_ENTER");
  auto status = port_.configure_wake(request_.wake);
  if (status) status = port_.enter_sleep();
  if (!status) {
    abort_to_running("SLEEP_ENTER_FAILED");
    return status;
  }
  return Status::success();
}

Status PowerCoordinator::wake(const ResetCause cause,
                              const ElapsedInterval elapsed,
                              const MonotonicMs now_ms) noexcept {
  if (state_ != PowerState::Sleeping) {
    return Status::error(StatusCode::InvalidState, "not sleeping");
  }
  cause_ = cause;
  transition(PowerState::Resuming, "WAKE");
  resume_flow(cause, elapsed, now_ms);
  return Status::success();
}

void PowerCoordinator::poll(const MonotonicMs now_ms) noexcept {
  switch (state_) {
    case PowerState::Running:
      node_.poll(now_ms);
      break;
    case PowerState::Draining:
      node_.poll(now_ms);
      if (node_.quiesced() || now_ms >= drain_deadline_ms_) {
        finish_drain(now_ms);
      }
      break;
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
          events_.on_diagnostic(discovery ? "RESUME_DISCOVERY_STARTED"
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

void PowerCoordinator::finish_drain(const MonotonicMs now_ms) noexcept {
  transition(PowerState::Persisting,
             node_.quiesced() ? "DRAIN_SETTLED" : "DRAIN_DEADLINE");
  image_ = PowerImage{};
  image_.network = node_.config().network;
  image_.node = node_.config().node;
  node_.settle_for_sleep(request_.pending_policy,
                         [&](const DeliverySnapshot& snapshot) {
                           if (snapshot.expires_at_ms <= now_ms) return false;
                           for (auto& record : image_.pending) {
                             if (record.used) continue;
                             record.used = true;
                             record.original_id = snapshot.id;
                             record.destination = snapshot.destination;
                             record.delivery = snapshot.options.delivery;
                             record.priority = snapshot.options.priority;
                             record.hop_limit = snapshot.options.hop_limit;
                             record.stored_remaining_ms = static_cast<std::uint32_t>(
                                 snapshot.expires_at_ms - now_ms);
                             record.payload_size = static_cast<std::uint8_t>(
                                 snapshot.payload.size);
                             if (snapshot.payload.size != 0) {
                               std::memcpy(record.payload.data(), snapshot.payload.data,
                                           snapshot.payload.size);
                             }
                             return true;
                           }
                           return false;
                         });
  node_.quiesce_for_sleep();
  const auto status = persist_image();
  if (!status) abort_to_running(status.detail);
}

Status PowerCoordinator::persist_image() noexcept {
  image_.sequence = image_sequence_ + 1;
  image_.config_revision = node_.config_revision();
  auto status = port_.capture_cache(image_);
  if (!status) return status;
  status = commit_image(image_);
  if (!status) return status;
  status = port_.quiesce_radio();
  if (!status) return status;
  radio_quiesced_ = true;
  ++radio_generation_;
  issue_ticket();
  transition(PowerState::ReadyToSleep, "SLEEP_READY");
  return Status::success();
}

Status PowerCoordinator::commit_image(const PowerImage& image) noexcept {
  std::array<std::uint8_t, kPowerImageRecordSize> record{};
  auto status = encode_image(image, record);
  if (!status) return status;
  status = storage_.write(static_cast<std::uint8_t>(image.sequence & 1U),
                          ByteView{record.data(), record.size()});
  if (!status) return status;
  image_sequence_ = image.sequence;
  image_valid_ = true;
  return Status::success();
}

Status PowerCoordinator::load_image(PowerImage& image, bool& found) noexcept {
  found = false;
  std::array<std::uint8_t, kPowerImageRecordSize> record{};
  bool any = false;
  std::uint32_t best_sequence = 0;
  for (std::uint8_t slot = 0; slot < kPowerImageSlots; ++slot) {
    const auto status =
        storage_.read(slot, MutableByteView{record.data(), record.size()});
    if (!status) {
      events_.on_diagnostic(status.detail);
      continue;
    }
    PowerImage candidate{};
    if (!decode_image(ByteView{record.data(), record.size()}, candidate)) {
      continue;  // torn/corrupt slot: discard, never erase
    }
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

  PowerImage stored{};
  bool found = false;
  (void)load_image(stored, found);
  const bool usable = found && image_usable(stored);
  if (found && !usable) {
    events_.on_diagnostic("SLEEP_IMAGE_CONTEXT_MISMATCH");
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
  if (!radio) events_.on_diagnostic(radio.detail);

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
      // instead of silently dropping durable work.
      merged.sequence = image_sequence_ + 1;
      (void)commit_image(merged);
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
      events_.on_pending_result(record, resumed.code);
      continue;
    }
    const SendOptions options{record.delivery, record.priority, remaining,
                              record.hop_limit, true};
    MessageId new_id{};
    const auto sent = node_.send(
        record.destination, ByteView{record.payload.data(), record.payload_size},
        options, now_ms, new_id);
    events_.on_pending_result(record, sent.ok() ? StatusCode::Ok : sent.code);
    if (!sent.ok() && keep != nullptr) {
      // Re-injection failed (queue full, draining, ...): keep the durable
      // record — with the decayed lifetime — so a later sleep image retries
      // it instead of dropping it at the storage layer.
      *keep = record;
      keep->used = true;
      keep->stored_remaining_ms = remaining;
    }
  }
}

void PowerCoordinator::abort_to_running(const char* reason) noexcept {
  events_.on_diagnostic(reason);
  ticket_ = SleepTicket{};
  if (radio_quiesced_) {
    ++radio_generation_;
    (void)port_.start_radio(&image_);
    radio_quiesced_ = false;
  }
  node_.set_draining(false);
  transition(PowerState::Running, "SLEEP_ABORTED");
}

}  // namespace routeloom
