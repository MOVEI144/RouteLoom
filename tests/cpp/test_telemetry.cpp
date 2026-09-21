#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "routeloom/byte_io.hpp"
#include "routeloom/telemetry.hpp"

namespace {

int failures = 0;
#define CHECK(expr)                                                          \
  do {                                                                       \
    if (!(expr)) {                                                           \
      std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__,   \
                   #expr);                                                   \
      ++failures;                                                            \
    }                                                                        \
  } while (false)
#define CHECK_OK(expr)                                                       \
  do {                                                                       \
    const auto _status = (expr);                                             \
    if (!_status.ok()) {                                                     \
      std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__,       \
                   __LINE__, #expr, _status.detail);                         \
      ++failures;                                                            \
    }                                                                        \
  } while (false)

using namespace routeloom;

RadioRxMetadataV2 meta(const std::int8_t rssi, const std::uint32_t binding = 7,
                       const std::uint32_t radio = 3,
                       const std::uint32_t channel_epoch = 1) {
  RadioRxMetadataV2 m{};
  m.received_us = 5000;
  m.binding_generation = BindingGeneration{binding};
  m.radio_generation = RadioGeneration{radio};
  m.channel_epoch = ChannelEpoch{channel_epoch};
  m.rssi_dbm = rssi;
  m.rssi_valid = true;
  return m;
}

// Signed Q8.8 EWMA: negative samples must pull the average down, never wrap.
void test_rssi_ewma() {
  std::int16_t ewma = 0;
  rssi_ewma_add(ewma, -80, 1);
  CHECK(ewma == -80 * 256);
  rssi_ewma_add(ewma, -40, 2);
  CHECK(ewma == -75 * 256);  // -80 + (-40 - -80)/8 = -75
  // A run of lower samples descends monotonically — no unsigned wrap.
  std::int16_t prev = ewma;
  for (std::uint64_t n = 3; n < 40; ++n) {
    rssi_ewma_add(ewma, -90, n);
    CHECK(ewma <= prev);
    CHECK(ewma >= -90 * 256 && ewma <= -40 * 256);
    prev = ewma;
  }
  // Converges toward -90.
  for (std::uint64_t n = 40; n < 200; ++n) rssi_ewma_add(ewma, -90, n);
  CHECK(ewma <= -89 * 256 && ewma >= -90 * 256);
}

void test_peer_summary_table() {
  PeerTelemetryTable table{};
  CHECK(table.find(5) == nullptr);

  auto* e = table.note_rx(5, meta(-70), ObservationProvenance::LocalDriver, 9,
                          1000);
  CHECK(e != nullptr && e->peer == 5 && e->occupied);
  CHECK(e->rssi_present && e->rssi_samples == 1);
  CHECK(e->rssi_last == -70 && e->rssi_min == -70 && e->rssi_max == -70);
  CHECK(e->rssi_ewma_q8_8 == -70 * 256);

  e = table.note_rx(5, meta(-60), ObservationProvenance::LocalDriver, 9, 1100);
  CHECK(e != nullptr && e->rssi_samples == 2);
  CHECK(e->rssi_max == -60 && e->rssi_min == -70);
  CHECK(e->rssi_ewma_q8_8 == static_cast<std::int16_t>(-70 * 256 + (-60 * 256 + 70 * 256) / 8));

  // Missing RSSI updates freshness but not the RSSI fields.
  RadioRxMetadataV2 no_rssi = meta(0);
  no_rssi.rssi_valid = false;
  e = table.note_rx(5, no_rssi, ObservationProvenance::LocalDriver, 9, 1200);
  CHECK(e != nullptr && e->rssi_samples == 2 && e->rssi_last == -60);
  CHECK(e->last_sample_ms == 1200);

  // Generation change: stale, then a new observation restarts fresh.
  table.note_rx(5, meta(-50, /*binding=*/8), ObservationProvenance::LocalDriver,
                9, 1300);
  const PeerTelemetrySummary* s = table.find(5);
  CHECK(s != nullptr && s->binding.value == 8);
  CHECK(s->rssi_samples == 1 && s->rssi_last == -50 && !s->stale);

  // Capacity bound: peer 5 plus 18 more fill the table; the 20th is a loss,
  // not an eviction or a fake entry.
  for (std::uint64_t p = 100; p < 118; ++p) {
    CHECK(table.note_rx(p, meta(-65), ObservationProvenance::LocalDriver, 9,
                        2000) != nullptr);
  }
  CHECK(table.size() == kPeerSummaryCapacity);
  CHECK(table.note_rx(999, meta(-65), ObservationProvenance::LocalDriver, 9,
                      2100) == nullptr);
  CHECK(table.find(999) == nullptr);
}

void test_query_codec() {
  TelemetryQuery q{};
  q.request_id = 0xA1B2C3D4;
  q.peer = 0x1122334455;
  q.direction = ObservationDirection::Ingress;
  q.length_class = 2;
  q.max_age_ms = 1500;

  std::array<std::uint8_t, kTelemetryQueryBodySize> buf{};
  MutableByteView out{buf.data(), buf.size()};
  CHECK_OK(telemetry_query_encode(q, out));

  // Exact layout: prefix(4) then fields, big-endian.
  CHECK(buf[0] == 1 && buf[1] == 3 && buf[2] == 0 && buf[3] == 0);
  CHECK(buf[4] == 0xA1 && buf[5] == 0xB2 && buf[6] == 0xC3 && buf[7] == 0xD4);
  CHECK(buf[11] == 0x11 && buf[12] == 0x22 && buf[13] == 0x33 &&
        buf[14] == 0x44 && buf[15] == 0x55);  // peer u64 BE tail
  CHECK(buf[16] == 1 && buf[17] == 2);
  CHECK(buf[18] == 0 && buf[19] == 0);
  CHECK(buf[20] == 0 && buf[21] == 0 && buf[22] == 0x05 && buf[23] == 0xDC);

  TelemetryQuery back{};
  CHECK_OK(telemetry_query_decode(ByteView{buf.data(), buf.size()}, back));
  CHECK(back.request_id == q.request_id && back.peer == q.peer);
  CHECK(back.direction == q.direction && back.length_class == 2);
  CHECK(back.max_age_ms == 1500);

  // Rejections: zero id, broadcast peer, bad direction/class/age, trailing.
  TelemetryQuery bad = q;
  bad.request_id = 0;
  CHECK(!telemetry_query_encode(bad, out).ok());
  bad = q;
  bad.max_age_ms = 3001;
  CHECK(!telemetry_query_encode(bad, out).ok());

  std::array<std::uint8_t, kTelemetryQueryBodySize> tampered = buf;
  tampered[4] = 0;  tampered[5] = 0; tampered[6] = 0; tampered[7] = 0;
  CHECK(!telemetry_query_decode(ByteView{tampered.data(), tampered.size()}, back).ok());
  tampered = buf;
  tampered[16] = 2;  // direction
  CHECK(!telemetry_query_decode(ByteView{tampered.data(), tampered.size()}, back).ok());
  tampered = buf;
  tampered[17] = 3;  // class
  CHECK(!telemetry_query_decode(ByteView{tampered.data(), tampered.size()}, back).ok());
  tampered = buf;
  tampered[19] = 1;  // reserved
  CHECK(!telemetry_query_decode(ByteView{tampered.data(), tampered.size()}, back).ok());
  tampered = buf;
  tampered[1] = 7;   // wrong subtype
  CHECK(!telemetry_query_decode(ByteView{tampered.data(), tampered.size()}, back).ok());
  tampered = buf;
  tampered[0] = 9;   // wrong version
  CHECK(!telemetry_query_decode(ByteView{tampered.data(), tampered.size()}, back).ok());
  // Trailing byte rejected; short body rejected.
  std::array<std::uint8_t, kTelemetryQueryBodySize + 1> longer{};
  std::memcpy(longer.data(), buf.data(), buf.size());
  CHECK(!telemetry_query_decode(ByteView{longer.data(), longer.size()}, back).ok());
  CHECK(!telemetry_query_decode(ByteView{buf.data(), buf.size() - 1}, back).ok());

  // Class 255 (summary only) is legal.
  bad = q;
  bad.length_class = kTelemetryPeerSummaryClass;
  CHECK_OK(telemetry_query_encode(bad, out));
}

void test_snapshot_codec() {
  TelemetrySnapshot s{};
  s.request_id = 77;
  s.observer = 0xC3;
  s.observer_boot = 0xDEADBEEF;
  s.peer = 0x5;
  s.binding = BindingGeneration{7};
  s.radio = RadioGeneration{3};
  s.channel_epoch = ChannelEpoch{1};
  s.channel = 11;
  s.direction = ObservationDirection::Egress;
  s.length_class = 1;
  s.validity = static_cast<std::uint8_t>(kTelemetryValidRssi |
                                         kTelemetryValidBucket |
                                         kTelemetrySourceLocalDriver);
  s.sampled_at_ms = 123456789;
  s.window_ms = 2000;
  s.sample_age_ms = 40;
  s.rssi_last = -55;
  s.rssi_min = -80;
  s.rssi_max = -50;
  s.rssi_ewma_q8_8 = static_cast<std::int16_t>(-60 * 256);
  s.rssi_samples = 12;
  s.tx_submitted = 100;
  s.tx_mac_success = 96;
  s.tx_mac_fail = 3;
  s.tx_unknown = 1;
  s.sdk_retries = 4;
  s.hop_accepts = 95;
  s.hop_timeouts = 2;
  s.busy = 1;
  s.queue_us_ewma = 1234;
  s.driver_us_ewma = 5678;
  s.hop_rtt_us_ewma = 9012;
  s.event_drops = 2;
  s.saturation_mask = kSatEventDrops;

  std::array<std::uint8_t, kTelemetrySnapshotBodySize> buf{};
  MutableByteView out{buf.data(), buf.size()};
  CHECK_OK(telemetry_snapshot_encode(s, out));

  // Spot-check the §4.2 offset table byte-exactly.
  CHECK(buf[0] == 1 && buf[1] == 4 && buf[2] == 0 && buf[3] == 0);
  CHECK(buf[4] == 0 && buf[7] == 77);              // request_id BE
  CHECK(buf[8 + 7] == 0xC3);                      // observer BE tail
  CHECK(buf[44] == 11);                           // channel
  CHECK(buf[45] == 0 && buf[46] == 1);            // direction/class
  CHECK(buf[47] == 0x13);                         // validity bits 0|1|4
  CHECK(buf[64] == static_cast<std::uint8_t>(-55));
  CHECK(buf[65] == static_cast<std::uint8_t>(-80));
  CHECK(buf[66] == static_cast<std::uint8_t>(-50));
  CHECK(buf[67] == 0);                            // reserved
  // -60*256 = -15360 = 0xC400 -> BE bytes C4 00 at offsets 68,69.
  CHECK(buf[68] == 0xC4 && buf[69] == 0x00 && buf[70] == 0 && buf[71] == 0);

  TelemetrySnapshot back{};
  CHECK_OK(telemetry_snapshot_decode(ByteView{buf.data(), buf.size()}, back));
  CHECK(back.request_id == 77 && back.observer == 0xC3);
  CHECK(back.observer_boot == 0xDEADBEEF && back.peer == 5);
  CHECK(back.binding.value == 7 && back.radio.value == 3 &&
        back.channel_epoch.value == 1 && back.channel == 11);
  CHECK(back.validity == s.validity);
  CHECK(back.sampled_at_ms == 123456789 && back.window_ms == 2000);
  CHECK(back.sample_age_ms == 40);
  CHECK(back.rssi_last == -55 && back.rssi_min == -80 && back.rssi_max == -50);
  CHECK(back.rssi_ewma_q8_8 == -60 * 256);
  CHECK(back.rssi_samples == 12 && back.tx_submitted == 100);
  CHECK(back.tx_mac_success == 96 && back.tx_mac_fail == 3 &&
        back.tx_unknown == 1);
  CHECK(back.sdk_retries == 4 && back.hop_accepts == 95 &&
        back.hop_timeouts == 2 && back.busy == 1);
  CHECK(back.queue_us_ewma == 1234 && back.driver_us_ewma == 5678 &&
        back.hop_rtt_us_ewma == 9012);
  CHECK(back.event_drops == 2 &&
        back.saturation_mask == kSatEventDrops);

  // Mutually exclusive provenance bits are a decode rejection.
  std::array<std::uint8_t, kTelemetrySnapshotBodySize> tampered = buf;
  tampered[47] = static_cast<std::uint8_t>(kTelemetrySourceLocalDriver |
                                           kTelemetrySourceInjectedTest);
  CHECK(!telemetry_snapshot_decode(ByteView{tampered.data(), tampered.size()}, back).ok());
  // Wrong size / subtype rejected.
  CHECK(!telemetry_snapshot_decode(ByteView{buf.data(), buf.size() - 1}, back).ok());
  tampered = buf;
  tampered[1] = 3;
  CHECK(!telemetry_snapshot_decode(ByteView{tampered.data(), tampered.size()}, back).ok());
}

void test_reject_codec() {
  DiagnosticReject r{};
  r.request_id = 42;
  r.reason = DiagnosticRejectReason::NoBucket;
  r.observer = 0x99;
  r.detail = 0;

  std::array<std::uint8_t, kDiagnosticRejectBodySize> buf{};
  MutableByteView out{buf.data(), buf.size()};
  CHECK_OK(diagnostic_reject_encode(r, out));
  CHECK(buf[0] == 1 && buf[1] == 6 && buf[2] == 0 && buf[3] == 0);
  CHECK(buf[8] == 0 && buf[9] == 5);  // reason BE

  DiagnosticReject back{};
  CHECK_OK(diagnostic_reject_decode(ByteView{buf.data(), buf.size()}, back));
  CHECK(back.request_id == 42 && back.observer == 0x99);
  CHECK(back.reason == DiagnosticRejectReason::NoBucket);

  std::array<std::uint8_t, kDiagnosticRejectBodySize> tampered = buf;
  tampered[9] = 8;  // reason out of range
  CHECK(!diagnostic_reject_decode(ByteView{tampered.data(), tampered.size()}, back).ok());
  tampered = buf;
  tampered[9] = 0;
  CHECK(!diagnostic_reject_decode(ByteView{tampered.data(), tampered.size()}, back).ok());
}

void test_positive_metric_input() {
  ObservationBucket bucket{};
  // Nothing recorded: no positive input.
  CHECK(!bucket.positive_metric_input(1000));

  bucket.current.present = true;
  bucket.current.sources =
      static_cast<std::uint8_t>(1u << static_cast<unsigned>(
          ObservationProvenance::LocalDriver));
  bucket.current.last_sample_ms = 900;
  bucket.current.incomplete = false;
  CHECK(bucket.positive_metric_input(1000));
  // Stale beyond the 3 s feedback TTL.
  CHECK(!bucket.positive_metric_input(900 + kFeedbackTtlMs + 1));
  // Injected/mixed sources never improve a metric.
  bucket.current.sources =
      static_cast<std::uint8_t>(1u << static_cast<unsigned>(
          ObservationProvenance::InjectedTest));
  CHECK(!bucket.positive_metric_input(1000));
  bucket.current.sources = static_cast<std::uint8_t>(
      (1u << static_cast<unsigned>(ObservationProvenance::LocalDriver)) |
      (1u << static_cast<unsigned>(ObservationProvenance::InjectedTest)));
  CHECK(!bucket.positive_metric_input(1000));
  bucket.current.sources =
      static_cast<std::uint8_t>(1u << static_cast<unsigned>(
          ObservationProvenance::LocalDriver));
  bucket.current.incomplete = true;
  CHECK(!bucket.positive_metric_input(1000));
  bucket.current.incomplete = false;
  bucket.stale = true;
  CHECK(!bucket.positive_metric_input(1000));
  // A future timestamp is clock-uncertain, not fresh.
  bucket.stale = false;
  bucket.current.last_sample_ms = 2000;
  CHECK(!bucket.positive_metric_input(1000));
}

}  // namespace

int main() {
  test_rssi_ewma();
  test_peer_summary_table();
  test_query_codec();
  test_snapshot_codec();
  test_reject_codec();
  test_positive_metric_input();

  if (failures != 0) {
    std::fprintf(stderr, "%d telemetry checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom telemetry tests passed");
  return 0;
}
