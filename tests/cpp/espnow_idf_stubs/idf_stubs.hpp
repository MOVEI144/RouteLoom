// Test driver surface for the ESP-IDF stand-ins (issue #117 host regression
// test): fake-clock control plus counters for the driver calls the tests
// assert on. Single-threaded; plain globals are enough.
//
// The multi-node mesh harness (D04) runs one node per process and switches
// radio frames between processes: each peer sets its own station MAC,
// captures every esp_now_send payload with take_tx, and the harness
// re-injects the delivered ones with inject_rx.
#pragma once

#include <cstdint>
#include <cstddef>

namespace idf_stub {

void reset() noexcept;
void set_now_us(std::int64_t now_us) noexcept;
void advance_ms(std::uint32_t ms) noexcept;
std::int64_t now_us() noexcept;
// esp_now_send / esp_now_del_peer call counts since reset.
unsigned send_count() noexcept;
bool last_send_to(const std::uint8_t mac[6]) noexcept;
unsigned del_peer_count() noexcept;
void fail_del_peer(bool fail) noexcept;
void fail_add_peer(bool fail) noexcept;
// Opt-in physical ESP-NOW table for the Owner mesh harness. Other stub
// tests keep the historical permissive driver unless they set a limit.
void set_peer_limit(std::size_t limit) noexcept;
std::size_t peer_count() noexcept;
// Per-process station MAC (esp_wifi_get_mac); reset() restores the default.
void set_mac(const std::uint8_t mac[6]) noexcept;
// Injects one RX frame with its observed destination (broadcast for
// broadcast frames): the member-scope destination rule drops frames
// whose destination is neither this node nor broadcast, so a zeroed
// destination would silently discard real RLD1 traffic.
bool inject_rx(const std::uint8_t source[6], const std::uint8_t dest[6],
               const std::uint8_t* frame, std::size_t length) noexcept;
bool inject_rx(const std::uint8_t source[6], const std::uint8_t* frame,
               std::size_t length) noexcept;
// Complete the oldest uncompleted esp_now_send through the registered
// send callback, as the driver would. Destinations attribute in send
// order even after take_tx drained the capture queue. No-op when nothing
// is outstanding or no callback is registered. Returns true when a
// completion was delivered.
bool complete_send(bool success) noexcept;
// One captured esp_now_send payload (ESP_NOW_MAX_DATA_LEN body max).
struct TxFrame {
  static constexpr std::size_t kMaxBytes = 280;
  std::uint8_t dest[6]{};
  std::uint8_t bytes[kMaxBytes]{};
  std::size_t length{0};
};
// Pops the oldest captured TX frame; false when the capture queue is
// empty. Frames overwritten by queue overflow are counted in
// tx_overruns() instead of being silently reordered.
bool take_tx(TxFrame& out) noexcept;
std::size_t tx_pending() noexcept;
unsigned tx_overruns() noexcept;

// Called after every successful xQueueReceive (nullptr clears): lets a
// test refill a queue while the Owner drains it, as the radio does.
void set_receive_hook(void (*hook)(void* context), void* context) noexcept;
// Ticks passed to the most recent xQueuePeek.
unsigned last_peek_ticks() noexcept;
bool log_contains(const char* text) noexcept;

// Pop the oldest captured TX frame; false when the capture ring is empty.
bool pop_tx(TxFrame& out) noexcept;
// TX frames dropped because the capture ring was full or oversized.
unsigned tx_drops() noexcept;

}  // namespace idf_stub
