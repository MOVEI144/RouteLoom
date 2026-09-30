// Board provisioning console (benchcfg/benchsecret), the RLK1 secrets
// store and the generic field-image boot gate (resolve_field_identity):
// durable per-device config/secrets behind one signed image, mismatch
// refusal before RF, power-cut readback and app-update persistence.
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

#include "routeloom/board_config.hpp"
#include "routeloom/board_secrets.hpp"
#include "routeloom/crc32.hpp"
#include "routeloom/sdkv1_board_setup.hpp"
#include "routeloom/sdkv1_maintenance.hpp"

#include "test_sdkv1.hpp"

using namespace routeloom;
using namespace routeloom::sdkv1;
using sdkv1_test::FaultyRecordStorage;

namespace {

int failures = 0;
#define CHECK(expr)                                                            \
  do {                                                                         \
    if (!(expr)) {                                                             \
      std::fprintf(stderr, "CHECK failed %s:%d [%s]\n", __FILE__, __LINE__,    \
                   #expr);                                                     \
      ++failures;                                                              \
    }                                                                          \
  } while (false)

constexpr NodeId kBoardNode = 0x00A1000000001000ULL;
constexpr std::array<std::uint8_t, 6> kBoardMac{0x02, 0x11, 0x22, 0x33, 0x44, 0x55};

// RLC1 setup document (42 B, the layout benchcfg stage accepts).
std::array<std::uint8_t, kBoardDocV1Bytes> build_doc(const NodeId node,
    const std::array<std::uint8_t, 6>& mac, const std::uint8_t chip,
    const BoardRole role, const BoardSecurity security,
    const std::uint8_t channel, const std::uint32_t network) {
  std::array<std::uint8_t, kBoardDocV1Bytes> doc{};
  const auto put32 = [&](const std::size_t at, const std::uint32_t v) {
    doc[at] = static_cast<std::uint8_t>(v >> 24U);
    doc[at + 1] = static_cast<std::uint8_t>(v >> 16U);
    doc[at + 2] = static_cast<std::uint8_t>(v >> 8U);
    doc[at + 3] = static_cast<std::uint8_t>(v);
  };
  put32(0, kBoardDocMagic);
  doc[4] = 1;
  doc[6] = 0;
  doc[7] = kBoardDocV1Bytes;
  for (int i = 0; i < 8; ++i) doc[8 + i] = static_cast<std::uint8_t>(node >> (56 - 8 * i));
  for (std::size_t i = 0; i < 6; ++i) doc[16 + i] = mac[i];
  doc[22] = chip;
  doc[23] = static_cast<std::uint8_t>(role);
  doc[24] = static_cast<std::uint8_t>(security);
  doc[25] = channel;
  put32(26, network);
  put32(38, crc32_iso_hdlc(ByteView{doc.data(), 38}));
  return doc;
}

std::string hex_encode(const std::uint8_t* data, const std::size_t size) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(size * 2);
  for (std::size_t i = 0; i < size; ++i) {
    out.push_back(kDigits[data[i] >> 4]);
    out.push_back(kDigits[data[i] & 0xF]);
  }
  return out;
}

std::string hex_encode(const std::vector<std::uint8_t>& bytes) {
  return hex_encode(bytes.data(), bytes.size());
}

template <std::size_t N>
std::string hex_encode(const std::array<std::uint8_t, N>& bytes) {
  return hex_encode(bytes.data(), N);
}

// The three durable stores one board owns; one FaultyRecordStorage pair
// each so faults can be injected per store. `expected` is the setup
// image's field profile the console binds commits to — the tests always
// bind it, so every commit exercises the §4.2 profile check.
struct BoardBench {
  BoardBootIdentity expected{};
  FaultyRecordStorage config_slots{kBoardConfigSlotBytes};
  FaultyRecordStorage secrets_slots{kBoardSecretsSlotBytes};
  FaultyRecordStorage identity_slots{kIdentitySlotBytes};
  BoardConfigStore config{config_slots};
  BoardSecretsStore secrets{secrets_slots};
  IdentityStore identity{identity_slots};
  BoardSetupConsole console{config, secrets, identity, expected};

  void expect(const BoardRole role, const BoardSecurity security) {
    expected.chip = kBoardChipEsp32C6;
    expected.sta_mac = kBoardMac;
    expected.role = role;
    expected.security = security;
  }
};

std::string run(BoardSetupConsole& console, const std::string& line) {
  char response[kMaintenanceResponseMax]{};
  std::size_t size = 0;
  const Status status = console.process_line(
      ByteView{reinterpret_cast<const std::uint8_t*>(line.data()), line.size()}, response,
      sizeof(response), size);
  CHECK(status.ok());
  if (!status) return "";
  return std::string(response, size);
}

BoardBootIdentity boot_identity(const NodeId rli_node = kBoardNode) {
  BoardBootIdentity id{};
  id.chip = kBoardChipEsp32C6;
  id.sta_mac = kBoardMac;
  id.role = BoardRole::Reference;
  id.security = BoardSecurity::Member;
  id.rli_node = rli_node;
  return id;
}

void test_secrets_store() {
  FaultyRecordStorage slots(kBoardSecretsSlotBytes);
  BoardSecretsStore store(slots);
  CHECK(store.initialize().ok());
  CHECK(!store.has_secrets());

  BoardSecrets secrets{};
  secrets.generation = 7;
  secrets.has_psk = true;
  for (std::size_t i = 0; i < secrets.psk.size(); ++i) {
    secrets.psk[i] = static_cast<std::uint8_t>(0x40 + i);
  }
  secrets.usb_len = 5;
  const char usb[] = "s3crt";
  std::memcpy(secrets.usb_secret.data(), usb, sizeof(usb) - 1);
  CHECK(store.commit(secrets).ok());

  // Readback proves the durable record; a re-opened store sees the same.
  BoardSecretsStore reopened(slots);
  CHECK(reopened.initialize().ok());
  CHECK(reopened.has_secrets());
  CHECK(board_secrets_equal(reopened.secrets(), secrets));

  Digest256 fingerprint{};
  CHECK(board_secrets_fingerprint(secrets, fingerprint).ok());
  Digest256 fingerprint2{};
  CHECK(board_secrets_fingerprint(reopened.secrets(), fingerprint2).ok());
  CHECK(fingerprint == fingerprint2);
  CHECK(fingerprint != Digest256{});

  // The public config binds generation + fingerprint; a DevRam board
  // needs the PSK kind.
  BoardConfig config{};
  config.secrets_generation = 7;
  config.secrets_fingerprint = fingerprint;
  config.security = BoardSecurity::DevRam;
  config.role = BoardRole::Reference;
  CHECK(reopened.authorize(config).ok());

  // Generation or fingerprint drift is refused.
  config.secrets_generation = 8;
  CHECK(!reopened.authorize(config).ok());
  config.secrets_generation = 7;
  config.secrets_fingerprint[0] ^= 0x01;
  CHECK(!reopened.authorize(config).ok());
  config.secrets_fingerprint[0] ^= 0x01;

  // A bound record missing the needed kind is refused.
  BoardSecrets psk_less = secrets;
  psk_less.has_psk = false;
  for (auto& byte : psk_less.psk) byte = 0;
  psk_less.generation = 9;
  CHECK(reopened.commit(psk_less).ok());
  BoardConfig need_psk = config;
  need_psk.secrets_generation = 9;
  CHECK(board_secrets_fingerprint(psk_less, need_psk.secrets_fingerprint).ok());
  CHECK(!reopened.authorize(need_psk).ok());
  // ... while a Member bridge (usb only) accepts the same record.
  BoardConfig bridge = need_psk;
  bridge.security = BoardSecurity::Member;
  bridge.role = BoardRole::Bridge;
  CHECK(reopened.authorize(bridge).ok());

  // Generations never regress.
  CHECK(!reopened.commit(secrets).ok());   // generation 7 < 9
  CHECK(!reopened.commit(psk_less).ok());  // equal generation replays

  // A Member non-bridge board binds no secrets record at all.
  BoardConfig member{};
  member.security = BoardSecurity::Member;
  member.role = BoardRole::Reference;
  CHECK(reopened.authorize(member).ok());
}

void test_secrets_power_cut() {
  // A lost write acknowledgement leaves the store unready for commits and
  // authorization; reboot readback then adopts whichever side landed.
  for (const bool lands : {false, true}) {
    FaultyRecordStorage slots(kBoardSecretsSlotBytes);
    BoardSecretsStore writer(slots);
    CHECK(writer.initialize().ok());
    BoardSecrets first{};
    first.generation = 1;
    first.has_psk = true;
    first.psk.fill(0x11);
    CHECK(writer.commit(first).ok());
    BoardSecrets second = first;
    second.generation = 2;
    second.psk.fill(0x22);
    slots.cut_call = slots.write_calls + 1;
    slots.cut_bytes = lands ? kBoardSecretsRecordBytes : 4;
    CHECK(!writer.commit(second).ok());
    BoardConfig bound{};
    bound.secrets_generation = 1;
    bound.security = BoardSecurity::DevRam;
    bound.role = BoardRole::Reference;
    CHECK(board_secrets_fingerprint(first, bound.secrets_fingerprint).ok());
    // The unproven commit refuses authorization until readback.
    CHECK(!writer.authorize(bound).ok());
    slots.disarm();
    BoardSecretsStore reboot(slots);
    CHECK(reboot.initialize().ok());
    CHECK(reboot.has_secrets());
    CHECK(reboot.secrets().generation == (lands ? 2 : 1));
    BoardConfig adopted{};
    adopted.secrets_generation = reboot.secrets().generation;
    adopted.security = BoardSecurity::DevRam;
    adopted.role = BoardRole::Reference;
    CHECK(board_secrets_fingerprint(reboot.secrets(), adopted.secrets_fingerprint).ok());
    CHECK(reboot.authorize(adopted).ok());
  }
}

void test_console_flow() {
  BoardBench bench;
  bench.expect(BoardRole::Bridge, BoardSecurity::DevRam);
  // Field stores start empty; the board refuses RF before provisioning.
  const BoardSecrets* out = reinterpret_cast<const BoardSecrets*>(0x1);
  CHECK(!resolve_field_identity(bench.config, bench.secrets, boot_identity(), out).ok());
  CHECK(out == nullptr);

  CHECK(run(bench.console, "benchcfg status") == "OK board=none");
  CHECK(run(bench.console, "benchsecret status") == "OK secrets=none");

  const auto doc = build_doc(kBoardNode, kBoardMac, kBoardChipEsp32C6,
                             BoardRole::Bridge, BoardSecurity::DevRam, 6, 42);
  CHECK(run(bench.console, "benchcfg stage " + hex_encode(doc)) ==
        "OK staged bytes=42");
  CHECK(run(bench.console, "benchcfg validate") ==
        "OK valid node=00a1000000001000 role=bridge security=devram");
  // Replaying the document stages cleanly again (idempotent stage).
  CHECK(run(bench.console, "benchcfg stage " + hex_encode(doc)) ==
        "OK staged bytes=42");

  keys::Secret psk{};
  psk.fill(0x5A);
  const std::string usb = "usb-session-1";
  CHECK(run(bench.console, "benchsecret stage psk 3 " + hex_encode(psk)) ==
        "OK staged kind=psk generation=3");
  CHECK(run(bench.console, "benchsecret stage usb 3 " + hex_encode(
                std::vector<std::uint8_t>(usb.begin(), usb.end()))) ==
        "OK staged kind=usb generation=3");
  const std::string committed =
      run(bench.console, "benchcfg commit 3");
  CHECK(committed == "OK committed generation=3 node=00a1000000001000");

  const std::string board_status = run(bench.console, "benchcfg status");
  CHECK(board_status.find("OK board=committed generation=3 "
                          "node=00a1000000001000 role=bridge "
                          "security=devram secrets_generation=3 "
                          "fingerprint=") == 0);
  const std::string secrets_status =
      run(bench.console, "benchsecret status");
  CHECK(secrets_status.find("OK secrets=committed generation=3 psk=1 usb=1 "
                            "fingerprint=") == 0);
  // Secret bytes never appear in a response.
  CHECK(secrets_status.find(hex_encode(psk)) == std::string::npos);
  CHECK(secrets_status.find(hex_encode(
            std::vector<std::uint8_t>(usb.begin(), usb.end()))) ==
        std::string::npos);

  // The committed pair authorizes exactly this board.
  BoardBootIdentity id = boot_identity();
  id.role = BoardRole::Bridge;
  id.security = BoardSecurity::DevRam;
  id.rli_node = 0;  // DevRam does not bind an RLI1 node
  CHECK(resolve_field_identity(bench.config, bench.secrets, id, out).ok());
  CHECK(out != nullptr);
  CHECK(out->has_psk && out->psk == psk);
  CHECK(out->usb_len == usb.size());
  CHECK(std::memcmp(out->usb_secret.data(), usb.data(), usb.size()) == 0);

  // Idempotent replay: the same commit succeeds without a write.
  CHECK(run(bench.console, "benchcfg stage " + hex_encode(doc)) ==
        "OK staged bytes=42");
  CHECK(run(bench.console, "benchsecret stage psk 3 " + hex_encode(psk)) ==
        "OK staged kind=psk generation=3");
  CHECK(run(bench.console, "benchsecret stage usb 3 " + hex_encode(
                std::vector<std::uint8_t>(usb.begin(), usb.end()))) ==
        "OK staged kind=usb generation=3");
  CHECK(run(bench.console, "benchcfg commit 3") ==
        "OK committed generation=3 node=00a1000000001000");
  // A commit generation other than the staged secrets' refuses the pair.
  CHECK(run(bench.console, "benchsecret stage psk 9 " + hex_encode(psk)) ==
        "OK staged kind=psk generation=9");
  CHECK(run(bench.console, "benchcfg commit 2") == "ERR generation_mismatch");
}

void test_console_guards() {
  // Locked identity seal: status stays readable, every mutating verb is refused.
  {
    BoardBench bench;
    CHECK(bench.identity.initialize().ok());
    CHECK(bench.identity.commit(sdkv1_test::identity_record(/*strict=*/true)).ok());
    bench.expect(BoardRole::Reference, BoardSecurity::Member);
    const auto doc = build_doc(kBoardNode, kBoardMac, kBoardChipEsp32C6,
                               BoardRole::Reference, BoardSecurity::Member, 6, 42);
    CHECK(run(bench.console, "benchcfg status") == "OK board=none");
    CHECK(run(bench.console, "benchcfg stage " + hex_encode(doc)) == "ERR locked");
    CHECK(run(bench.console, "benchsecret stage psk 1 " + hex_encode(keys::Secret{})) ==
          "ERR locked");
    CHECK(run(bench.console, "benchcfg commit 1") == "ERR locked");
  }
  // Secret generation must equal the commit generation.
  {
    BoardBench bench;
    bench.expect(BoardRole::Reference, BoardSecurity::DevRam);
    const auto doc = build_doc(kBoardNode, kBoardMac, kBoardChipEsp32C6,
                               BoardRole::Reference, BoardSecurity::DevRam, 6, 42);
    CHECK(run(bench.console, "benchcfg stage " + hex_encode(doc)) ==
          "OK staged bytes=42");
    keys::Secret psk{};
    psk.fill(0x77);
    CHECK(run(bench.console, "benchsecret stage psk 5 " + hex_encode(psk)) ==
          "OK staged kind=psk generation=5");
    CHECK(run(bench.console, "benchcfg commit 6") == "ERR generation_mismatch");
  }
  // DevRam without a staged (or durable) PSK cannot commit its binding.
  {
    BoardBench bench;
    bench.expect(BoardRole::Reference, BoardSecurity::DevRam);
    const auto doc = build_doc(kBoardNode, kBoardMac, kBoardChipEsp32C6,
                               BoardRole::Reference, BoardSecurity::DevRam, 6, 42);
    CHECK(run(bench.console, "benchcfg stage " + hex_encode(doc)) ==
          "OK staged bytes=42");
    CHECK(run(bench.console, "benchcfg commit 1") == "ERR secrets_required");
  }
  // Member bridge without a USB secret cannot commit.
  {
    BoardBench bench;
    bench.expect(BoardRole::Bridge, BoardSecurity::Member);
    const auto doc = build_doc(kBoardNode, kBoardMac, kBoardChipEsp32C6,
                               BoardRole::Bridge, BoardSecurity::Member, 6, 42);
    CHECK(run(bench.console, "benchcfg stage " + hex_encode(doc)) ==
          "OK staged bytes=42");
    CHECK(run(bench.console, "benchcfg commit 1") == "ERR secrets_required");
  }
  // Member reference needs no secrets at all.
  {
    BoardBench bench;
    bench.expect(BoardRole::Reference, BoardSecurity::Member);
    const auto doc = build_doc(kBoardNode, kBoardMac, kBoardChipEsp32C6,
                               BoardRole::Reference, BoardSecurity::Member, 6, 42);
    CHECK(run(bench.console, "benchcfg stage " + hex_encode(doc)) ==
          "OK staged bytes=42");
    CHECK(run(bench.console, "benchcfg commit 1") ==
          "OK committed generation=1 node=00a1000000001000");
    const std::string status = run(bench.console, "benchcfg status");
    CHECK(status.find("secrets_generation=0 fingerprint=-") !=
          std::string::npos);
  }
  // An impaired store refuses mutation, never silently recovers: a
  // read-faulted pair cannot prove its durable state, so the verb fails
  // closed before any write is attempted.
  {
    BoardBench bench;
    bench.expect(BoardRole::Reference, BoardSecurity::Member);
    const auto doc = build_doc(kBoardNode, kBoardMac, kBoardChipEsp32C6,
                               BoardRole::Reference, BoardSecurity::Member, 6, 42);
    CHECK(run(bench.console, "benchcfg stage " + hex_encode(doc)) ==
          "OK staged bytes=42");
    bench.config_slots.read_error = true;
    CHECK(run(bench.console, "benchcfg commit 1") == "ERR store_unavailable");
    // A write that fails mid-commit also fails the verb — and the store
    // stays unready (readback required) for the next attempt.
    bench.config_slots.read_error = false;
    // A power cut mid-write leaves a torn record; the verb reports the
    // failed commit, and the next line's fresh readback observes the
    // impairment — still refused, never implicitly repaired.
    bench.config_slots.cut_call = bench.config_slots.write_calls;
    bench.config_slots.cut_bytes = 12;
    CHECK(run(bench.console, "benchcfg commit 1") == "ERR commit_failed");
    CHECK(run(bench.console, "benchcfg commit 1") == "ERR store_unavailable");
  }
  // Malformed documents and arguments are rejected.
  {
    BoardBench bench;
    auto doc = build_doc(kBoardNode, kBoardMac, kBoardChipEsp32C6,
                         BoardRole::Reference, BoardSecurity::Member, 6, 42);
    doc[25] = 0;  // channel out of range -> validate/commit refuse
    CHECK(run(bench.console, "benchcfg stage " + hex_encode(doc)) ==
          "OK staged bytes=42");
    CHECK(run(bench.console, "benchcfg validate") == "ERR invalid_argument");
    CHECK(run(bench.console, "benchcfg commit 1") == "ERR invalid_argument");
    CHECK(run(bench.console, "benchcfg") == "ERR invalid_argument");
    CHECK(run(bench.console, "wrenchcfg status") == "ERR invalid_argument");
  }
  // The declared 2 KiB staging limit must fit on one setup-console line.
  {
    BoardBench bench;
    const std::vector<std::uint8_t> max_doc(sdkv1::kBoardSetupDocMax, 0);
    CHECK(run(bench.console, "benchcfg stage " + hex_encode(max_doc)) ==
          "OK staged bytes=2048");
    CHECK(run(bench.console, "benchcfg validate") == "ERR invalid_argument");
  }
  // A syntactically valid document cannot name an unsupported chip.
  {
    BoardBench bench;
    const auto doc = build_doc(kBoardNode, kBoardMac, 0x7f,
                               BoardRole::Reference, BoardSecurity::Member, 6, 42);
    CHECK(run(bench.console, "benchcfg stage " + hex_encode(doc)) ==
          "OK staged bytes=42");
    CHECK(run(bench.console, "benchcfg validate") == "ERR invalid_argument");
  }
  // A document naming a different profile/MAC than this image's cannot
  // commit (§4.2): the setup image catches what the field gate would.
  {
    BoardBench bench;
    bench.expect(BoardRole::Reference, BoardSecurity::Member);
    const auto doc = build_doc(kBoardNode, kBoardMac, kBoardChipEsp32C6,
                               BoardRole::Bridge, BoardSecurity::Member, 6, 42);
    CHECK(run(bench.console, "benchcfg stage " + hex_encode(doc)) ==
          "OK staged bytes=42");
    CHECK(run(bench.console, "benchcfg validate").find("OK valid") == 0);
    CHECK(run(bench.console, "benchcfg commit 1") == "ERR profile_mismatch");
    std::array<std::uint8_t, 6> other_mac = kBoardMac;
    other_mac[5] ^= 0x01;
    const auto doc2 = build_doc(kBoardNode, other_mac, kBoardChipEsp32C6,
                                BoardRole::Reference, BoardSecurity::Member, 6, 42);
    CHECK(run(bench.console, "benchcfg stage " + hex_encode(doc2)) ==
          "OK staged bytes=42");
    CHECK(run(bench.console, "benchcfg commit 1") == "ERR profile_mismatch");
  }
}

void test_field_gate() {
  // One Member reference config per board; the same resolve_field_identity
  // is the "image" — the durable record alone distinguishes boards.
  BoardBench bench;
  bench.expect(BoardRole::Reference, BoardSecurity::Member);
  const auto doc = build_doc(kBoardNode, kBoardMac, kBoardChipEsp32C6,
                             BoardRole::Reference, BoardSecurity::Member, 6, 42);
  CHECK(run(bench.console, "benchcfg stage " + hex_encode(doc)) ==
        "OK staged bytes=42");
  CHECK(run(bench.console, "benchcfg commit 1").find("OK committed") == 0);

  const BoardSecrets* out = reinterpret_cast<const BoardSecrets*>(0x1);
  CHECK(resolve_field_identity(bench.config, bench.secrets, boot_identity(), out).ok());
  CHECK(out == nullptr);  // Member reference binds no secrets record

  // Wrong chip/MAC/role/security/RLI1 node are all refused before RF.
  BoardBootIdentity id = boot_identity();
  id.chip = kBoardChipEsp32C3;
  CHECK(!resolve_field_identity(bench.config, bench.secrets, id, out).ok());
  id = boot_identity();
  id.sta_mac[5] ^= 0x01;
  CHECK(!resolve_field_identity(bench.config, bench.secrets, id, out).ok());
  id = boot_identity();
  id.role = BoardRole::Bridge;
  CHECK(!resolve_field_identity(bench.config, bench.secrets, id, out).ok());
  id = boot_identity();
  id.security = BoardSecurity::DevRam;
  CHECK(!resolve_field_identity(bench.config, bench.secrets, id, out).ok());
  id = boot_identity();
  id.rli_node = kBoardNode + 1;
  CHECK(!resolve_field_identity(bench.config, bench.secrets, id, out).ok());
}

void test_three_boards_one_image() {
  // Acceptance (D02): the same image digest serves three boards whose only
  // difference is the durable record — each resolves its own NodeId.
  BoardBench benches[3];
  for (std::uint8_t i = 0; i < 3; ++i) {
    std::array<std::uint8_t, 6> mac = kBoardMac;
    mac[5] += i;
    benches[i].expect(BoardRole::Reference, BoardSecurity::Member);
    benches[i].expected.sta_mac = mac;
    const auto doc = build_doc(kBoardNode + i, mac, kBoardChipEsp32C6,
                               BoardRole::Reference, BoardSecurity::Member, 6, 42);
    CHECK(run(benches[i].console, "benchcfg stage " + hex_encode(doc)) ==
          "OK staged bytes=42");
    CHECK(run(benches[i].console, "benchcfg commit 1").find("OK committed") == 0);
  }
  for (std::uint8_t i = 0; i < 3; ++i) {
    // Field boot re-initializes the stores (the app update path below).
    CHECK(benches[i].config.initialize().ok());
    CHECK(benches[i].secrets.initialize().ok());
    BoardBootIdentity id = boot_identity();
    id.sta_mac[5] += i;
    id.rli_node = kBoardNode + i;
    const BoardSecrets* out = nullptr;
    CHECK(resolve_field_identity(benches[i].config, benches[i].secrets, id, out).ok());
    CHECK(benches[i].config.config().node == kBoardNode + i);
    // Board j's identity must never boot board i's record.
    BoardBootIdentity wrong = boot_identity();
    wrong.sta_mac[5] += static_cast<std::uint8_t>((i + 1) % 3);
    wrong.rli_node = kBoardNode + (i + 1) % 3;
    CHECK(!resolve_field_identity(benches[i].config, benches[i].secrets, wrong, out).ok());
  }
}

void test_app_update_preserves_stores() {
  // An app-only update is a fresh set of store objects over the same
  // durable slots: nothing is rewritten, the committed identity survives.
  FaultyRecordStorage config_slots(kBoardConfigSlotBytes);
  FaultyRecordStorage secrets_slots(kBoardSecretsSlotBytes);
  FaultyRecordStorage identity_slots(kIdentitySlotBytes);
  {
    BoardConfigStore config(config_slots);
    BoardSecretsStore secrets(secrets_slots);
    IdentityStore identity(identity_slots);
    CHECK(config.initialize().ok());
    CHECK(secrets.initialize().ok());
    CHECK(identity.initialize().ok());
    CHECK(identity.commit(sdkv1_test::identity_record()).ok());
    BoardSecrets secret{};
    secret.generation = 4;
    secret.usb_len = 2;
    secret.usb_secret = {'o', 'k'};
    CHECK(secrets.commit(secret).ok());
    BoardConfig cfg{};
    cfg.generation = 4;
    cfg.node = kBoardNode;
    cfg.sta_mac = kBoardMac;
    cfg.chip = kBoardChipEsp32C6;
    cfg.role = BoardRole::Bridge;
    cfg.security = BoardSecurity::Member;
    cfg.network = 42;
    cfg.channel = 6;
    cfg.secrets_generation = 4;
    CHECK(board_secrets_fingerprint(secret, cfg.secrets_fingerprint).ok());
    CHECK(config.commit(cfg).ok());
  }
  const auto config_image = config_slots.slot(0);
  const auto secrets_image = secrets_slots.slot(0);
  const auto identity_image = identity_slots.slot(0);
  const std::size_t writes_before = config_slots.write_calls +
                                  secrets_slots.write_calls +
                                  identity_slots.write_calls;
  // The "new app" only ever reads: the field path performs zero durable
  // writes, so rlcfg/rlkeys/rlsec all survive untouched.
  BoardConfigStore config(config_slots);
  BoardSecretsStore secrets(secrets_slots);
  IdentityStore identity(identity_slots);
  CHECK(config.initialize().ok());
  CHECK(secrets.initialize().ok());
  CHECK(identity.initialize().ok());
  CHECK(config.has_config() && config.config().node == kBoardNode);
  CHECK(secrets.has_secrets() && secrets.secrets().generation == 4);
  CHECK(identity.has_identity() && identity.identity().node_id == sdkv1_test::kNode);
  const BoardSecrets* out = nullptr;
  BoardBootIdentity id = boot_identity();
  id.role = BoardRole::Bridge;
  CHECK(resolve_field_identity(config, secrets, id, out).ok());
  CHECK(out != nullptr && out->usb_len == 2);
  CHECK(config_slots.write_calls + secrets_slots.write_calls +
            identity_slots.write_calls ==
        writes_before);
  CHECK(config_slots.slot(0) == config_image);
  CHECK(secrets_slots.slot(0) == secrets_image);
  CHECK(identity_slots.slot(0) == identity_image);
}

}  // namespace

int main() {
  test_secrets_store();
  test_secrets_power_cut();
  test_console_flow();
  test_console_guards();
  test_field_gate();
  test_three_boards_one_image();
  test_app_update_preserves_stores();
  if (failures == 0) std::printf("board setup tests passed\n");
  return failures ? 1 : 0;
}
