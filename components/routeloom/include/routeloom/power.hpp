#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/deadline.hpp"
#include "routeloom/node.hpp"
#include "routeloom/routing.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

// Power coordinator states. Every transition is explicit and bounded; the
// coordinator never skips DRAINING or PERSISTING on the way to SLEEPING.
enum class PowerState : std::uint8_t {
  Running = 0,
  Draining,       // background work stopped, in-flight TX settling
  Persisting,     // sleep image being committed to durable storage
  ReadyToSleep,   // image committed, radio quiesced, ticket issued
  Sleeping,       // enter_sleep accepted (real deep sleep does not return)
  Resuming,       // restore path after boot/wake, waiting for peer confirm
};

// Boot classification input. Cold boot and deep-sleep resume are distinct
// inputs; anything that lost RAM but kept NVS still counts as a reset, not a
// sleep resume.
enum class ResetCause : std::uint8_t {
  ColdBoot = 0,      // power-on / brownout: no trusted elapsed time, no RTC cache
  DeepSleepWake = 1, // woke from a sleep_enter()-driven deep sleep
  OtherReset = 2,    // watchdog/panic/etc: RAM lost, NVS intact
};

enum class ResumeOutcome : std::uint8_t {
  None = 0,
  ColdStart,          // no peers to resume with; normal bootstrap path
  FastResume,         // saved peers confirmed inside the confirm window
  DiscoveryRequired,  // saved peers silent; bounded discovery was started
  CacheLost,          // image corrupt/unreadable: peers must be rediscovered
};

// Handle issued when the coordinator reaches READY_TO_SLEEP. Bound to the
// radio generation, config revision and pending-work generation at issue
// time; any later TX enqueue/RX frame/app event invalidates it.
struct SleepTicket {
  std::uint32_t id{0};
  std::uint32_t radio_generation{0};
  std::uint32_t config_revision{0};
  std::uint32_t pending_generation{0};
  bool issued{false};
};

constexpr std::size_t kPowerPeerCacheCapacity = 8;
constexpr std::size_t kPowerPendingCapacity = 4;
constexpr std::size_t kPowerPeerAddressSize = 8;

struct PowerPeerRecord {
  NodeId node{kInvalidNodeId};
  std::array<std::uint8_t, kPowerPeerAddressSize> address{};
  std::uint8_t address_size{0};
  RouteMetric metric{1};
  bool used{false};
};

// A delivery persisted across sleep. `stored_remaining_ms` is the lifetime
// left when the durable record was (last) committed; on resume it goes
// through resume_remaining_lifetime so unknown elapsed time marks
// TIME_UNCERTAIN instead of a fabricated zero.
struct PendingDeliveryRecord {
  MessageId original_id{};
  NodeId destination{kInvalidNodeId};
  DeliveryClass delivery{DeliveryClass::Reliable};
  Priority priority{Priority::Normal};
  std::uint8_t hop_limit{kDefaultHopLimit};
  std::uint32_t stored_remaining_ms{0};
  // Absolute deadline on this boot's monotonic clock — RAM only, never
  // serialized. Lets sleep_enter() re-derive stored_remaining_ms so time
  // spent waiting in READY_TO_SLEEP is still deducted from the lifetime.
  MonotonicMs expires_at_ms{0};
  std::array<std::uint8_t, kMaxApplicationPayload> payload{};
  std::uint8_t payload_size{0};
  bool used{false};
};

struct PowerImage {
  std::uint32_t sequence{0};
  std::uint32_t config_revision{0};
  NetworkId network{0};
  NodeId node{kInvalidNodeId};
  std::uint8_t channel{0};
  std::array<PowerPeerRecord, kPowerPeerCacheCapacity> peers{};
  std::array<PendingDeliveryRecord, kPowerPendingCapacity> pending{};
};

// Raw two-slot persistence for the sleep image. Each slot holds exactly
// kPowerImageRecordSize bytes. Implementations must tolerate power loss at
// any byte boundary and must never erase or reformat storage on error;
// a torn write simply invalidates that slot through the CRC.
class PowerStorage {
 public:
  virtual ~PowerStorage() = default;
  virtual Status read(std::uint8_t slot, MutableByteView target) noexcept = 0;
  virtual Status write(std::uint8_t slot, ByteView data) noexcept = 0;
};

constexpr std::uint8_t kPowerImageSlots = 2;
constexpr std::uint32_t kPowerImageSchemaVersion = 1;
constexpr std::size_t kPowerImageRecordSize = 824;

struct WakePlan {
  std::uint64_t wake_after_ms{0};
  std::uint32_t gpio_mask{0};  // platform-defined wake pins; 0 = none
};

// Platform hooks the coordinator drives. Every call must be bounded; the
// coordinator applies its own deadlines on top.
class PowerPort {
 public:
  virtual ~PowerPort() = default;
  // Fill peers[] and channel with the platform's current peer cache.
  virtual Status capture_cache(PowerImage& image) noexcept = 0;
  // Stop the radio driver so no new TX/RX can start. MeshNode work has
  // already settled; this must not fabricate unknown TX results.
  virtual Status quiesce_radio() noexcept = 0;
  // (Re-)initialise the radio. With `image` != nullptr, rebuild driver peers
  // from the saved cache and re-apply the radio profile (LR250) and channel.
  virtual Status start_radio(const PowerImage* image) noexcept = 0;
  // Arm wake sources. Bounded; must not enter sleep itself.
  virtual Status configure_wake(const WakePlan& plan) noexcept = 0;
  // Enter deep sleep. On hardware this does not return; test doubles return
  // success so the model can exercise SLEEPING -> RESUMING in-process.
  virtual Status enter_sleep() noexcept = 0;
  // Bounded rediscovery when saved peers do not confirm inside the resume
  // window: same channel -> saved candidates -> limited scan. May return
  // Unsupported when the platform has no bounded discovery yet.
  virtual Status start_discovery(const PowerImage& image) noexcept = 0;
};

class PowerEvents {
 public:
  virtual ~PowerEvents() = default;
  virtual void on_transition(PowerState from, PowerState to,
                             const char* reason) noexcept = 0;
  virtual void on_pending_result(const PendingDeliveryRecord& record,
                                 StatusCode result) noexcept = 0;
  virtual void on_diagnostic(const char* reason) noexcept = 0;
};

class NullPowerEvents final : public PowerEvents {
 public:
  void on_transition(PowerState, PowerState, const char*) noexcept override {}
  void on_pending_result(const PendingDeliveryRecord&, StatusCode) noexcept override {}
  void on_diagnostic(const char*) noexcept override {}
};

struct PowerConfig {
  // Bound for settling in-flight TX inside DRAINING. On expiry the remaining
  // work is forced through its sleep disposition — the node must never be
  // kept awake forever by a stuck queue.
  std::uint32_t drain_timeout_ms{500};
  // Bound for saved peers to confirm (any RX/TX callback) after resume before
  // bounded discovery starts.
  std::uint32_t resume_confirm_ms{1000};
  DeadlinePolicy deadline_policy{DeadlinePolicy::WallElapsedValidity};
};

struct SleepRequest {
  // Disposition for non-durable unfinished deliveries at settle time.
  SleepWorkPolicy pending_policy{SleepWorkPolicy::Fail};
  WakePlan wake{};
};

const char* power_state_name(PowerState state) noexcept;
const char* resume_outcome_name(ResumeOutcome outcome) noexcept;

class PowerCoordinator {
 public:
  PowerCoordinator(const PowerConfig& config, MeshNode& node, PowerPort& port,
                   PowerStorage& storage, PowerEvents& events) noexcept;

  // Boot classification; call exactly once before polling. `elapsed` is the
  // trusted slept-time interval from the platform clock; known=false parks
  // durable pendings as TIME_UNCERTAIN instead of resending on zero.
  Status begin(ResetCause cause, ElapsedInterval elapsed,
               MonotonicMs now_ms) noexcept;

  // Two-phase sleep: prepare stops new work and starts the bounded drain;
  // when the image is persisted and the radio quiesced a ticket is issued.
  Status sleep_prepare(const SleepRequest& request, MonotonicMs now_ms) noexcept;
  Status sleep_abort(const char* reason) noexcept;
  // Only from READY_TO_SLEEP with a still-valid ticket.
  Status sleep_enter(const SleepTicket& ticket, MonotonicMs now_ms) noexcept;
  // In-process model of a wake from deep sleep (real hardware re-enters via
  // begin() on a fresh coordinator). Valid only from SLEEPING.
  Status wake(ResetCause cause, ElapsedInterval elapsed,
              MonotonicMs now_ms) noexcept;

  void poll(MonotonicMs now_ms) noexcept;

  // Application events (GPIO, sensor work, host request) invalidate tickets.
  void notify_app_event() noexcept { ++app_events_; }
  // External radio resets (driver recovery) invalidate tickets.
  void notify_radio_reset() noexcept { ++radio_generation_; }

  PowerState state() const noexcept { return state_; }
  ResetCause reset_cause() const noexcept { return cause_; }
  ResumeOutcome resume_outcome() const noexcept { return outcome_; }
  const SleepTicket& ticket() const noexcept { return ticket_; }
  bool ticket_valid(const SleepTicket& ticket) const noexcept;

 private:
  void transition(PowerState next, const char* reason) noexcept;
  std::uint32_t pending_generation() const noexcept;
  void issue_ticket() noexcept;
  void finish_drain(std::uint32_t attempt, MonotonicMs now_ms) noexcept;
  Status persist_image() noexcept;
  void resume_flow(ResetCause cause, ElapsedInterval elapsed,
                   MonotonicMs now_ms) noexcept;
  void restore_pending(const PowerImage& image, ElapsedInterval elapsed,
                       MonotonicMs now_ms, PowerImage& retained) noexcept;
  Status load_image(PowerImage& image, bool& found) noexcept;
  Status commit_image(const PowerImage& image) noexcept;
  void abort_to_running(const char* reason) noexcept;
  bool image_usable(const PowerImage& image) const noexcept;

  PowerConfig config_{};
  MeshNode& node_;
  PowerPort& port_;
  PowerStorage& storage_;
  PowerEvents& events_;
  PowerState state_{PowerState::Running};
  ResetCause cause_{ResetCause::ColdBoot};
  ResumeOutcome outcome_{ResumeOutcome::None};
  SleepRequest request_{};
  SleepTicket ticket_{};
  PowerImage image_{};       // scratch + last persisted/restored image
  bool image_valid_{false};  // image_ holds a validated durable image
  std::uint32_t image_sequence_{0};  // newest committed image sequence
  std::uint32_t next_ticket_id_{1};
  std::uint32_t radio_generation_{0};
  std::uint32_t app_events_{0};
  // Sleep-attempt generation: bumped by sleep_prepare() and by every
  // abort_to_running(). App callbacks can re-enter (sleep_abort, a fresh
  // sleep_prepare); every site that runs application code pins the attempt
  // it serves and stops if the generation moved on underneath it.
  std::uint32_t attempt_{0};
  MonotonicMs drain_deadline_ms_{0};
  MonotonicMs resume_deadline_ms_{0};
  std::uint32_t confirm_baseline_{0};
  bool discovery_started_{false};
  bool radio_quiesced_{false};
  bool begun_{false};
};

}  // namespace routeloom
