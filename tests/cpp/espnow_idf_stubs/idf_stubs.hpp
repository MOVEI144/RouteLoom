// Test driver surface for the ESP-IDF stand-ins (issue #117 host regression
// test): fake-clock control plus counters for the driver calls the tests
// assert on. Single-threaded; plain globals are enough.
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
bool inject_rx(const std::uint8_t source[6], const std::uint8_t* frame,
               std::size_t length) noexcept;
// Complete the most recent uncompleted esp_now_send through the
// registered send callback, as the driver would. No-op when nothing is
// outstanding or no callback is registered. Returns true when a
// completion was delivered.
bool complete_send(bool success) noexcept;

}  // namespace idf_stub
