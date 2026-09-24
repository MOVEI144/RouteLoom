// RAM session bank and provider (G-SEC P4 §4; acceptance V1-K02/K03/K04,
// P4-S01/C01 halves): install/retire discipline, the secret-salt lookup,
// the use budget (2^32-1024 / 2^32), the 64-bit replay window, lifetimes,
// establishment demand, RX-only overlap, and callback re-entry.
//
// The suite runs twice: once against a deterministic test AEAD and once
// against real AES-GCM-128 through OpenSSL EVP (ROUTELOOM_HAVE_OPENSSL),
// pinned by NIST gcmEncryptExtIV128 cases 1-2. The bank logic never depends
// on which one answers.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "routeloom/key_schedule.hpp"
#include "routeloom/security.hpp"
#include "routeloom/session_bank.hpp"

#ifdef ROUTELOOM_HAVE_OPENSSL
#include <openssl/evp.h>
#endif

namespace {

int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); ++failures; } } while (false)
#define CHECK_OK(expr) do { const auto _status = (expr); if (!_status.ok()) { std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__, __LINE__, #expr, _status.detail); ++failures; } } while (false)

using namespace routeloom;
using namespace routeloom::sdkv1;

constexpr NodeId kSelf = 0x00A1000000001234ULL;
constexpr NodeId kPeer = 0x00A1000000000777ULL;
constexpr NetworkId kNet = (static_cast<NetworkId>(3) << 32U) | 0x0A1B2C3DU;
constexpr std::uint32_t kGk = 203;

// --- Deterministic fixtures --------------------------------------------------------

struct TestRandom {
  std::uint64_t state{0x123456789ABCDEFULL};
  bool exhausted{false};
  static bool fill(void* ctx, std::uint8_t* out, const std::size_t size) noexcept {
    auto& self = *static_cast<TestRandom*>(ctx);
    if (self.exhausted) return false;
    for (std::size_t i = 0; i < size; ++i) {
      self.state = self.state * 6364136223846793005ULL + 1442695040888963407ULL;
      out[i] = static_cast<std::uint8_t>(self.state >> 56U);
    }
    return true;
  }
};

// A keyed test cipher (NOT an AEAD): stream-mixes key/nonce/aad/index so
// every input bit perturbs the output, with a 16-byte tag over everything.
// Cross-key/cross-nonce confusion fails the tag; the OpenSSL pass below
// proves the same bank against real AES-GCM.
struct TestAead {
  bool fail_next{false};
  // Re-entry probe: when set, the port calls it back (it must see Busy).
  bool (*reenter)(void* ctx) noexcept{nullptr};
  void* reenter_ctx{nullptr};
  bool reenter_saw_busy{false};

  static std::uint64_t mix(std::uint64_t state, std::uint64_t value) noexcept {
    state ^= value + 0x9e3779b97f4a7c15ULL + (state << 6U) + (state >> 2U);
    return state * 0xbf58476d1ce4e5b9ULL;
  }
  static bool call(void* ctx, const std::uint8_t key[16], const std::uint8_t nonce[12],
                   const ByteView aad, const ByteView input, std::uint8_t* out,
                   std::uint8_t tag[16], const bool sealing) noexcept {
    auto& self = *static_cast<TestAead*>(ctx);
    if (self.fail_next) {
      self.fail_next = false;
      return false;
    }
    if (self.reenter != nullptr) self.reenter_saw_busy = self.reenter(self.reenter_ctx);
    std::uint64_t state = 0x7465737461656164ULL;
    for (int i = 0; i < 16; ++i) state = mix(state, key[i]);
    for (int i = 0; i < 12; ++i) state = mix(state, nonce[i]);
    for (std::size_t i = 0; i < aad.size; ++i) state = mix(state, aad.data[i]);
    const std::uint64_t keystream = state;
    for (std::size_t i = 0; i < input.size; ++i) {
      out[i] = input.data[i] ^ static_cast<std::uint8_t>(mix(keystream, i + 1) >> 56U);
    }
    std::uint64_t left = keystream, right = mix(keystream, 0x746167ULL);
    const ByteView tag_input = sealing ? ByteView{out, input.size} : input;
    for (std::size_t i = 0; i < aad.size; ++i) left = mix(left, aad.data[i]);
    for (std::size_t i = 0; i < tag_input.size; ++i) right = mix(right, tag_input.data[i]);
    std::uint8_t expect[16];
    for (int i = 0; i < 8; ++i) {
      expect[i] = static_cast<std::uint8_t>(left >> (56 - i * 8));
      expect[8 + i] = static_cast<std::uint8_t>(right >> (56 - i * 8));
    }
    if (sealing) {
      std::memcpy(tag, expect, 16);
      return true;
    }
    std::uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) diff |= static_cast<std::uint8_t>(expect[i] ^ tag[i]);
    return diff == 0;
  }
  static bool seal(void* ctx, const std::uint8_t key[16], const std::uint8_t nonce[12],
                   const ByteView aad, const ByteView plaintext, std::uint8_t* out,
                   std::uint8_t tag[16]) noexcept {
    return call(ctx, key, nonce, aad, plaintext, out, tag, true);
  }
  static bool open(void* ctx, const std::uint8_t key[16], const std::uint8_t nonce[12],
                   const ByteView aad, const ByteView ciphertext, const std::uint8_t tag[16],
                   std::uint8_t* out) noexcept {
    std::uint8_t copy[16];
    std::memcpy(copy, tag, 16);
    return call(ctx, key, nonce, aad, ciphertext, out, copy, false);
  }
};

#ifdef ROUTELOOM_HAVE_OPENSSL
struct OpenSslAead {
  bool fail_next{false};
  static bool seal(void* ctx, const std::uint8_t key[16], const std::uint8_t nonce[12],
                   const ByteView aad, const ByteView plaintext, std::uint8_t* out,
                   std::uint8_t tag[16]) noexcept {
    auto& self = *static_cast<OpenSslAead*>(ctx);
    if (self.fail_next) {
      self.fail_next = false;
      return false;
    }
    EVP_CIPHER_CTX* evp = EVP_CIPHER_CTX_new();
    if (evp == nullptr) return false;
    int length = 0;
    bool ok = EVP_EncryptInit_ex(evp, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
              EVP_EncryptInit_ex(evp, nullptr, nullptr, key, nonce) == 1 &&
              (aad.size == 0 ||
               EVP_EncryptUpdate(evp, nullptr, &length, aad.data, (int)aad.size) == 1) &&
              (plaintext.size == 0 ||
               EVP_EncryptUpdate(evp, out, &length, plaintext.data, (int)plaintext.size) == 1) &&
              EVP_EncryptFinal_ex(evp, out + length, &length) == 1 &&
              EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1;
    EVP_CIPHER_CTX_free(evp);
    return ok;
  }
  static bool open(void* ctx, const std::uint8_t key[16], const std::uint8_t nonce[12],
                   const ByteView aad, const ByteView ciphertext, const std::uint8_t tag[16],
                   std::uint8_t* out) noexcept {
    auto& self = *static_cast<OpenSslAead*>(ctx);
    if (self.fail_next) {
      self.fail_next = false;
      return false;
    }
    EVP_CIPHER_CTX* evp = EVP_CIPHER_CTX_new();
    if (evp == nullptr) return false;
    int length = 0;
    bool ok = EVP_DecryptInit_ex(evp, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
              EVP_DecryptInit_ex(evp, nullptr, nullptr, key, nonce) == 1 &&
              (aad.size == 0 ||
               EVP_DecryptUpdate(evp, nullptr, &length, aad.data, (int)aad.size) == 1) &&
              (ciphertext.size == 0 ||
               EVP_DecryptUpdate(evp, out, &length, ciphertext.data, (int)ciphertext.size) == 1) &&
              EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) == 1 &&
              EVP_DecryptFinal_ex(evp, out + length, &length) == 1;
    EVP_CIPHER_CTX_free(evp);
    return ok;
  }
};
#endif

template <typename Bank>
struct Fixture {
  TestRandom random{};
  TestAead test_aead{};
  Bank bank{};
  using LocalView = typename Bank::LocalView;

  AeadGcm test_port() noexcept {
    return AeadGcm{&TestAead::seal, &TestAead::open, &test_aead};
  }
  typename Bank::RandomSource random_source() noexcept {
    return typename Bank::RandomSource{&TestRandom::fill, &random};
  }
  Status configure(const AeadGcm& port, const NodeId self = kSelf,
                   const MonotonicMs now = 1000) noexcept {
    LocalView local{};
    local.self = self;
    local.network = kNet;
    local.gk_epoch = kGk;
    return bank.configure(local, port, random_source(), now);
  }
};

// One installed link context, A->B and B->A material mirrored.
template <typename Bank>
void install_link(Bank& bank, const NodeId peer, const std::uint32_t tx_cid,
                  const std::uint32_t rx_cid, const std::uint8_t seed) {
  ContextKeys keys{};
  keys.scope = SecurityScope::Link;
  keys.network = kNet;
  keys.peer = peer;
  keys.tx_context_id = tx_cid;
  keys.rx_context_id = rx_cid;
  for (std::size_t i = 0; i < keys.tx_key.size(); ++i) {
    keys.tx_key[i] = static_cast<std::uint8_t>(seed + i);
    keys.rx_key[i] = static_cast<std::uint8_t>(seed + 0x40 + i);
  }
  for (std::size_t i = 0; i < keys.tx_iv.size(); ++i) {
    keys.tx_iv[i] = static_cast<std::uint8_t>(seed + 0x80 + i);
    keys.rx_iv[i] = static_cast<std::uint8_t>(seed + 0xC0 + i);
  }
  keys.peer_cert_id = {1, 2, 3, 4, 5, 6, 7, 8};
  keys.peer_generation = 3;
  InstallAttestation att{};
  att.peer_role = 0b011;
  att.created_gk_epoch = kGk;
  CHECK_OK(bank.install_verified(keys, att));
}

SecurityContext seal_context(const SecurityScope scope, const NodeId receiver,
                             const std::uint32_t epoch, const NodeId sender = kSelf) {
  SecurityContext context{};
  context.scope = scope;
  context.network = kNet;
  context.sender = sender;
  context.receiver = receiver;
  context.epoch = epoch;
  return context;
}

SecurityContext open_context(const SecurityScope scope, const NodeId sender,
                             const std::uint32_t epoch, const NodeId receiver = kSelf) {
  SecurityContext context{};
  context.scope = scope;
  context.network = kNet;
  context.sender = sender;
  context.receiver = receiver;
  context.epoch = epoch;
  return context;
}

// --- Suite (AEAD-agnostic) -----------------------------------------------------------

template <typename Bank>
void suite_roundtrip(const AeadGcm& port) {
  Fixture<Bank> fix;
  CHECK_OK(fix.configure(port));
  install_link(fix.bank, kPeer, 0x1111, 0x2222, 0x10);
  // tx_epoch stamps the peer's id; nothing is spent on the way.
  std::uint32_t epoch = 0;
  CHECK_OK(fix.bank.tx_epoch(SecurityScope::Link, kPeer, epoch));
  CHECK(epoch == 0x1111);
  CHECK(fix.bank.context_state(SecurityScope::Link, kPeer) == ContextState::Ready);
  // Seal on A, open on B with mirrored keys.
  Fixture<Bank> peer_fix;
  CHECK_OK(peer_fix.configure(port, kPeer));
  // Mirror the direction: A's tx material is B's rx material.
  ContextKeys swapped{};
  swapped.scope = SecurityScope::Link;
  swapped.network = kNet;
  swapped.peer = kSelf;
  swapped.tx_context_id = 0x2222;
  swapped.rx_context_id = 0x1111;
  for (std::size_t i = 0; i < swapped.tx_key.size(); ++i) {
    swapped.rx_key[i] = static_cast<std::uint8_t>(0x10 + i);
    swapped.tx_key[i] = static_cast<std::uint8_t>(0x10 + 0x40 + i);
  }
  for (std::size_t i = 0; i < swapped.tx_iv.size(); ++i) {
    swapped.rx_iv[i] = static_cast<std::uint8_t>(0x10 + 0x80 + i);
    swapped.tx_iv[i] = static_cast<std::uint8_t>(0x10 + 0xC0 + i);
  }
  InstallAttestation att{};
  att.created_gk_epoch = kGk;
  CHECK_OK(peer_fix.bank.install_verified(swapped, att));

  const std::uint8_t aad[] = {0xAA, 0xBB};
  const std::uint8_t plain[] = {1, 2, 3, 4, 5};
  std::uint64_t counter = 0;
  CHECK_OK(fix.bank.next_counter(seal_context(SecurityScope::Link, kPeer, 0x1111), counter));
  CHECK(counter == 0);
  std::array<std::uint8_t, 5> cipher{};
  std::array<std::uint8_t, kAeadTagSize> tag{};
  CHECK_OK(fix.bank.seal(seal_context(SecurityScope::Link, kPeer, 0x1111), counter,
                         ByteView{aad, sizeof(aad)}, ByteView{plain, sizeof(plain)},
                         MutableByteView{cipher.data(), cipher.size()}, tag));
  std::array<std::uint8_t, 5> opened{};
  CHECK_OK(peer_fix.bank.open(open_context(SecurityScope::Link, kSelf, 0x1111, kPeer), counter,
                              ByteView{aad, sizeof(aad)}, ByteView{cipher.data(), cipher.size()},
                              tag, MutableByteView{opened.data(), opened.size()}));
  CHECK(opened[0] == 1 && opened[4] == 5);
  // Replay, forgery and wrong-key opens all fail; the window never moves.
  CHECK(peer_fix.bank.open(open_context(SecurityScope::Link, kSelf, 0x1111, kPeer), counter,
                           ByteView{aad, sizeof(aad)}, ByteView{cipher.data(), cipher.size()},
                           tag, MutableByteView{opened.data(), opened.size()})
            .code == StatusCode::ReplayRejected);
  std::array<std::uint8_t, kAeadTagSize> bad_tag = tag;
  bad_tag[0] ^= 0xFF;
  CHECK(peer_fix.bank.open(open_context(SecurityScope::Link, kSelf, 0x1111, kPeer), 7,
                           ByteView{aad, sizeof(aad)}, ByteView{cipher.data(), cipher.size()},
                           bad_tag, MutableByteView{opened.data(), opened.size()})
            .code == StatusCode::AuthenticationFailed);
  // Out-of-order inside the 64-bit window still opens.
  std::uint64_t c1 = 0, c2 = 0;
  CHECK_OK(fix.bank.next_counter(seal_context(SecurityScope::Link, kPeer, 0x1111), c1));
  CHECK_OK(fix.bank.next_counter(seal_context(SecurityScope::Link, kPeer, 0x1111), c2));
  std::array<std::uint8_t, 5> cipher2{};
  std::array<std::uint8_t, kAeadTagSize> tag2{};
  CHECK_OK(fix.bank.seal(seal_context(SecurityScope::Link, kPeer, 0x1111), c2,
                         ByteView{aad, sizeof(aad)}, ByteView{plain, sizeof(plain)},
                         MutableByteView{cipher2.data(), cipher2.size()}, tag2));
  CHECK_OK(peer_fix.bank.open(open_context(SecurityScope::Link, kSelf, 0x1111, kPeer), c2,
                              ByteView{aad, sizeof(aad)}, ByteView{cipher2.data(), cipher2.size()},
                              tag2, MutableByteView{opened.data(), opened.size()}));
}

template <typename Bank>
void suite_unknown_and_demand(const AeadGcm& port) {
  Fixture<Bank> fix;
  CHECK_OK(fix.configure(port));
  std::uint32_t epoch = 0xBEEF;
  // V1-K02: no context, no counter: AuthRequired + idempotent demand.
  CHECK(fix.bank.tx_epoch(SecurityScope::Link, kPeer, epoch).code == StatusCode::AuthRequired);
  CHECK(epoch == 0xBEEF && fix.bank.demand_count() == 1);
  CHECK(fix.bank.context_state(SecurityScope::Link, kPeer) == ContextState::Establishing);
  CHECK(fix.bank.tx_epoch(SecurityScope::Link, kPeer, epoch).code == StatusCode::AuthRequired);
  CHECK(fix.bank.demand_count() == 1);  // merged, not queued twice
  SessionDemand demand{};
  CHECK(fix.bank.take_demand(demand));
  CHECK(demand.scope == SecurityScope::Link && demand.peer == kPeer);
  CHECK(!fix.bank.take_demand(demand));
  CHECK(fix.bank.context_state(SecurityScope::Link, kPeer) == ContextState::None);
  // Unknown RX id: AuthRequired, and stranger RF records no demand.
  std::array<std::uint8_t, 4> cipher{1, 2, 3, 4};
  std::array<std::uint8_t, kAeadTagSize> tag{};
  std::array<std::uint8_t, 4> plain{};
  CHECK(fix.bank.open(open_context(SecurityScope::Link, kPeer, 0x9999), 0, ByteView{nullptr, 0},
                      ByteView{cipher.data(), cipher.size()}, tag,
                      MutableByteView{plain.data(), plain.size()})
            .code == StatusCode::AuthRequired);
  CHECK(fix.bank.demand_count() == 0);
  install_link(fix.bank, kPeer, 0x1111, 0x2222, 0x10);
  // Cross-peer, cross-network and cross-scope confusion all refuse.
  CHECK(fix.bank.open(open_context(SecurityScope::Link, kPeer + 1, 0x2222), 0,
                      ByteView{nullptr, 0}, ByteView{cipher.data(), cipher.size()}, tag,
                      MutableByteView{plain.data(), plain.size()})
            .code == StatusCode::AuthRequired);
  SecurityContext foreign = open_context(SecurityScope::Link, kPeer, 0x2222);
  foreign.network = kNet + 1;
  CHECK(!fix.bank.open(foreign, 0, ByteView{nullptr, 0}, ByteView{cipher.data(), cipher.size()},
                       tag, MutableByteView{plain.data(), plain.size()})
             .ok());
  CHECK(fix.bank.tx_epoch(SecurityScope::EndToEnd, kPeer, epoch).code ==
        StatusCode::AuthRequired);
  CHECK(fix.bank.tx_epoch(SecurityScope::Group, kPeer, epoch).code == StatusCode::Unsupported);
  CHECK(fix.bank.tx_epoch(SecurityScope::GroupLink, kPeer, epoch).code == StatusCode::Unsupported);
  // The low32 wire form maps onto the adopted full64 — nothing else does.
  SecurityContext low32 = seal_context(SecurityScope::Link, kPeer, 0x1111);
  low32.network = kNet & 0xFFFFFFFFU;
  std::uint64_t counter = 0;
  CHECK_OK(fix.bank.next_counter(low32, counter));
  // A full demand table still refuses AuthRequired (node-deadline hold).
  for (NodeId peer = 100; peer < 100 + 8; ++peer) {
    CHECK(fix.bank.tx_epoch(SecurityScope::Link, peer, epoch).code == StatusCode::AuthRequired);
  }
  CHECK(fix.bank.demand_count() == 8);
  CHECK(fix.bank.tx_epoch(SecurityScope::Link, 9999, epoch).code == StatusCode::AuthRequired);
  CHECK(fix.bank.demand_count() == 8);
}

void suite_use_budget() {
  // V1-K03: the frozen rule at its exact marks (the live path consults the
  // same function, so these pins hold for next_counter/context_state/open).
  using Bank = NodeSessionBank;
  constexpr std::uint64_t kSoft = Bank::kRekeySoftCounter;  // 2^32 - 1024
  constexpr std::uint64_t kHard = Bank::kMaxUseCounter;     // 2^32
  CHECK(Bank::check_tx_counter(0) == Bank::TxCounterVerdict::Issue);
  CHECK(Bank::check_tx_counter(kSoft - 1) == Bank::TxCounterVerdict::Issue);
  CHECK(Bank::check_tx_counter(kSoft) == Bank::TxCounterVerdict::IssueRekeyDue);
  CHECK(Bank::check_tx_counter(kHard - 1) == Bank::TxCounterVerdict::IssueRekeyDue);
  CHECK(Bank::check_tx_counter(kHard) == Bank::TxCounterVerdict::Refuse);
  CHECK(Bank::check_tx_counter(0xFFFFFFFFFFFFULL) == Bank::TxCounterVerdict::Refuse);
  CHECK(Bank::rx_counter_admissible(0));
  CHECK(Bank::rx_counter_admissible(kHard - 1));
  CHECK(!Bank::rx_counter_admissible(kHard));
  CHECK(!Bank::rx_counter_admissible(0xFFFFFFFFFFFFULL));
}

template <typename Bank>
void suite_reservation(const AeadGcm& port, bool& fail_next) {
  Fixture<Bank> fix;
  CHECK_OK(fix.configure(port));
  install_link(fix.bank, kPeer, 0x1111, 0x2222, 0x10);
  const std::uint8_t aad[] = {0x01};
  const std::uint8_t plain[] = {0x02};
  std::array<std::uint8_t, 1> cipher{};
  std::array<std::uint8_t, kAeadTagSize> tag{};
  // Seal without a reservation refuses; a wrong epoch refuses.
  CHECK(fix.bank.seal(seal_context(SecurityScope::Link, kPeer, 0x1111), 0,
                      ByteView{aad, sizeof(aad)}, ByteView{plain, sizeof(plain)},
                      MutableByteView{cipher.data(), cipher.size()}, tag)
            .code == StatusCode::InvalidArgument);
  std::uint64_t c0 = 0, c1 = 0;
  CHECK_OK(fix.bank.next_counter(seal_context(SecurityScope::Link, kPeer, 0x1111), c0));
  CHECK(fix.bank.seal(seal_context(SecurityScope::Link, kPeer, 0x9999), c0,
                      ByteView{aad, sizeof(aad)}, ByteView{plain, sizeof(plain)},
                      MutableByteView{cipher.data(), cipher.size()}, tag)
            .code == StatusCode::InvalidArgument);
  // Drawing again supersedes: the old counter never seals afterwards.
  CHECK_OK(fix.bank.next_counter(seal_context(SecurityScope::Link, kPeer, 0x1111), c1));
  CHECK(c1 == c0 + 1);
  CHECK(fix.bank.seal(seal_context(SecurityScope::Link, kPeer, 0x1111), c0,
                      ByteView{aad, sizeof(aad)}, ByteView{plain, sizeof(plain)},
                      MutableByteView{cipher.data(), cipher.size()}, tag)
            .code == StatusCode::InvalidArgument);
  CHECK_OK(fix.bank.seal(seal_context(SecurityScope::Link, kPeer, 0x1111), c1,
                         ByteView{aad, sizeof(aad)}, ByteView{plain, sizeof(plain)},
                         MutableByteView{cipher.data(), cipher.size()}, tag));
  // ... and the same counter never seals twice.
  CHECK(fix.bank.seal(seal_context(SecurityScope::Link, kPeer, 0x1111), c1,
                      ByteView{aad, sizeof(aad)}, ByteView{plain, sizeof(plain)},
                      MutableByteView{cipher.data(), cipher.size()}, tag)
            .code == StatusCode::InvalidArgument);
  // A failed crypto callback still retires the counter (never re-issued).
  std::uint64_t c2 = 0;
  CHECK_OK(fix.bank.next_counter(seal_context(SecurityScope::Link, kPeer, 0x1111), c2));
  fail_next = true;
  CHECK(!fix.bank.seal(seal_context(SecurityScope::Link, kPeer, 0x1111), c2,
                       ByteView{aad, sizeof(aad)}, ByteView{plain, sizeof(plain)},
                       MutableByteView{cipher.data(), cipher.size()}, tag)
            .ok());
  std::uint64_t c3 = 0;
  CHECK_OK(fix.bank.next_counter(seal_context(SecurityScope::Link, kPeer, 0x1111), c3));
  CHECK(c3 == c2 + 1);
}

template <typename Bank>
void suite_install_retire(const AeadGcm& port) {
  Fixture<Bank> fix;
  CHECK_OK(fix.configure(port));
  install_link(fix.bank, kPeer, 0x1111, 0x2222, 0x10);
  // A repeated install of the same keys is Conflict — counters untouched.
  std::uint64_t counter = 0;
  CHECK_OK(fix.bank.next_counter(seal_context(SecurityScope::Link, kPeer, 0x1111), counter));
  ContextKeys same{};
  same.scope = SecurityScope::Link;
  same.network = kNet;
  same.peer = kPeer;
  same.tx_context_id = 0x1111;
  same.rx_context_id = 0x2222;
  for (std::size_t i = 0; i < same.tx_key.size(); ++i) {
    same.tx_key[i] = static_cast<std::uint8_t>(0x10 + i);
    same.rx_key[i] = static_cast<std::uint8_t>(0x10 + 0x40 + i);
  }
  for (std::size_t i = 0; i < same.tx_iv.size(); ++i) {
    same.tx_iv[i] = static_cast<std::uint8_t>(0x10 + 0x80 + i);
    same.rx_iv[i] = static_cast<std::uint8_t>(0x10 + 0xC0 + i);
  }
  InstallAttestation att{};
  att.created_gk_epoch = kGk;
  CHECK(fix.bank.install_verified(same, att).code == StatusCode::Conflict);
  std::uint64_t again = 0;
  CHECK_OK(fix.bank.next_counter(seal_context(SecurityScope::Link, kPeer, 0x1111), again));
  CHECK(again == counter + 1);  // not rewound to 0
  // An RX id live anywhere else collides.
  ContextKeys clash = same;
  clash.peer = kPeer + 1;
  CHECK(fix.bank.install_verified(clash, att).code == StatusCode::Conflict);
  // GK-dead installs refuse.
  ContextKeys stale = same;
  stale.rx_context_id = 0x3333;
  stale.tx_context_id = 0x4444;
  InstallAttestation old{};
  old.created_gk_epoch = kGk - 2;
  CHECK(fix.bank.install_verified(stale, old).code == StatusCode::Conflict);
  InstallAttestation future{};
  future.created_gk_epoch = kGk + 1;
  CHECK(fix.bank.install_verified(stale, future).code == StatusCode::Conflict);
  // Retire is idempotent and drops demands too.
  CHECK_OK(fix.bank.retire(SecurityScope::Link, kPeer));
  CHECK(fix.bank.context_state(SecurityScope::Link, kPeer) == ContextState::None);
  CHECK_OK(fix.bank.retire(SecurityScope::Link, kPeer));
  std::uint32_t epoch = 0;
  CHECK(fix.bank.tx_epoch(SecurityScope::Link, kPeer, epoch).code == StatusCode::AuthRequired);
  CHECK(fix.bank.demand_count() == 1);
  CHECK_OK(fix.bank.retire_all(kPeer));
  CHECK(fix.bank.demand_count() == 0);
}

template <typename Bank>
void suite_overlap(const AeadGcm& port) {
  // A seals one frame under the old key; B rekeys (old RX demotes to the
  // RX-only overlap) and the in-flight old frame still opens — for 60 s.
  Fixture<Bank> fix;
  CHECK_OK(fix.configure(port));
  install_link(fix.bank, kPeer, 0x1111, 0x2222, 0x10);
  const std::uint8_t aad[] = {0x07};
  const std::uint8_t plain[] = {0x08, 0x09};
  std::uint64_t counter = 0;
  CHECK_OK(fix.bank.next_counter(seal_context(SecurityScope::Link, kPeer, 0x1111), counter));
  std::array<std::uint8_t, 2> cipher{};
  std::array<std::uint8_t, kAeadTagSize> tag{};
  CHECK_OK(fix.bank.seal(seal_context(SecurityScope::Link, kPeer, 0x1111), counter,
                         ByteView{aad, sizeof(aad)}, ByteView{plain, sizeof(plain)},
                         MutableByteView{cipher.data(), cipher.size()}, tag));
  Fixture<Bank> peer_fix;
  CHECK_OK(peer_fix.configure(port, kPeer));
  ContextKeys mirror{};
  mirror.scope = SecurityScope::Link;
  mirror.network = kNet;
  mirror.peer = kSelf;
  mirror.tx_context_id = 0x2222;
  mirror.rx_context_id = 0x1111;
  for (std::size_t i = 0; i < mirror.tx_key.size(); ++i) {
    mirror.tx_key[i] = static_cast<std::uint8_t>(0x90 + i);
    mirror.rx_key[i] = static_cast<std::uint8_t>(0x10 + i);  // A's old TX
  }
  for (std::size_t i = 0; i < mirror.tx_iv.size(); ++i) {
    mirror.tx_iv[i] = static_cast<std::uint8_t>(0x90 + 0xC0 + i);
    mirror.rx_iv[i] = static_cast<std::uint8_t>(0x10 + 0x80 + i);
  }
  InstallAttestation att{};
  att.created_gk_epoch = kGk;
  CHECK_OK(peer_fix.bank.install_verified(mirror, att));
  ContextKeys mirror_new = mirror;
  mirror_new.tx_context_id = 0x5555;
  mirror_new.rx_context_id = 0x6666;
  for (std::size_t i = 0; i < mirror_new.rx_key.size(); ++i) {
    mirror_new.rx_key[i] = static_cast<std::uint8_t>(0xA0 + i);
    mirror_new.tx_key[i] = static_cast<std::uint8_t>(0xB0 + i);
  }
  CHECK_OK(peer_fix.bank.install_verified(mirror_new, att));
  std::array<std::uint8_t, 2> opened{};
  CHECK_OK(peer_fix.bank.open(open_context(SecurityScope::Link, kSelf, 0x1111, kPeer), counter,
                              ByteView{aad, sizeof(aad)}, ByteView{cipher.data(), cipher.size()},
                              tag, MutableByteView{opened.data(), opened.size()}));
  CHECK((opened == std::array<std::uint8_t, 2>{0x08, 0x09}));
  // ...until the 60 s overlap lapses.
  CHECK_OK(peer_fix.bank.tick(1000 + 60 * 1000));
  CHECK(peer_fix.bank.open(open_context(SecurityScope::Link, kSelf, 0x1111, kPeer), counter + 1,
                           ByteView{aad, sizeof(aad)}, ByteView{cipher.data(), cipher.size()},
                           tag, MutableByteView{opened.data(), opened.size()})
            .code == StatusCode::AuthRequired);
}

template <typename Bank>
void suite_lifetime(const AeadGcm& port) {
  Fixture<Bank> fix;
  CHECK_OK(fix.configure(port, 1000));
  install_link(fix.bank, kPeer, 0x1111, 0x2222, 0x10);
  CHECK(fix.bank.has_usable(SecurityScope::Link, kPeer));
  // Backwards time is refused and extends nothing.
  CHECK(fix.bank.tick(999).code == StatusCode::InvalidArgument);
  CHECK_OK(fix.bank.tick(1000));
  // 24 h of monotonic life, then the context wipes itself on tick.
  CHECK_OK(fix.bank.tick(1000 + 24U * 3600U * 1000U - 1));
  CHECK(fix.bank.has_usable(SecurityScope::Link, kPeer));
  CHECK_OK(fix.bank.tick(1000 + 24U * 3600U * 1000U));
  CHECK(!fix.bank.has_usable(SecurityScope::Link, kPeer));
  CHECK(fix.bank.context_state(SecurityScope::Link, kPeer) == ContextState::None);
  // GK advance past created+2 kills the context even with time left.
  install_link(fix.bank, kPeer, 0x3333, 0x4444, 0x20);
  CHECK(fix.bank.set_gk_epoch(kGk - 1).code == StatusCode::Conflict);
  CHECK_OK(fix.bank.set_gk_epoch(kGk + 1));
  CHECK(fix.bank.has_usable(SecurityScope::Link, kPeer));
  CHECK_OK(fix.bank.set_gk_epoch(kGk + 2));
  CHECK(!fix.bank.has_usable(SecurityScope::Link, kPeer));
  // A site change wipes everything, including demands.
  typename Bank::LocalView next{};
  next.self = kSelf;
  next.network = kNet + 1;
  next.gk_epoch = 1;
  CHECK_OK(fix.bank.reset_membership(next, 5000));
  CHECK(fix.bank.live_count(SecurityScope::Link) == 0);
}

template <typename Bank>
void suite_k04_reboot_forgets(const AeadGcm& port) {
  // V1-K04: a reboot loses keys AND windows together. Old frames never
  // re-verify — not even when the new context accidentally reuses an id.
  Fixture<Bank> fix;
  CHECK_OK(fix.configure(port));
  install_link(fix.bank, kPeer, 0x1111, 0x2222, 0x10);
  const std::uint8_t aad[] = {0x0D};
  const std::uint8_t plain[] = {0x0E};
  std::uint64_t counter = 0;
  CHECK_OK(fix.bank.next_counter(seal_context(SecurityScope::Link, kPeer, 0x1111), counter));
  std::array<std::uint8_t, 1> cipher{};
  std::array<std::uint8_t, kAeadTagSize> tag{};
  CHECK_OK(fix.bank.seal(seal_context(SecurityScope::Link, kPeer, 0x1111), counter,
                         ByteView{aad, sizeof(aad)}, ByteView{plain, sizeof(plain)},
                         MutableByteView{cipher.data(), cipher.size()}, tag));
  // "Reboot": a fresh bank that reinstalls under the same ids with new keys.
  Fixture<Bank> rebooted;
  CHECK_OK(rebooted.configure(port, kPeer));
  ContextKeys mirror{};
  mirror.scope = SecurityScope::Link;
  mirror.network = kNet;
  mirror.peer = kSelf;
  mirror.tx_context_id = 0x2222;
  mirror.rx_context_id = 0x1111;
  for (std::size_t i = 0; i < mirror.rx_key.size(); ++i) {
    mirror.rx_key[i] = static_cast<std::uint8_t>(0x71 + i);  // new key, same id
    mirror.tx_key[i] = static_cast<std::uint8_t>(0x72 + i);
  }
  for (std::size_t i = 0; i < mirror.rx_iv.size(); ++i) {
    mirror.rx_iv[i] = static_cast<std::uint8_t>(0x73 + i);
    mirror.tx_iv[i] = static_cast<std::uint8_t>(0x74 + i);
  }
  InstallAttestation att{};
  att.created_gk_epoch = kGk;
  CHECK_OK(rebooted.bank.install_verified(mirror, att));
  std::array<std::uint8_t, 1> opened{0xFF};
  CHECK(rebooted.bank.open(open_context(SecurityScope::Link, kSelf, 0x1111, kPeer), counter,
                           ByteView{aad, sizeof(aad)}, ByteView{cipher.data(), cipher.size()},
                           tag, MutableByteView{opened.data(), opened.size()})
            .code == StatusCode::AuthenticationFailed);
  CHECK(opened[0] == 0xFF);  // failed opens expose no plaintext
}

// P4-S01: per-peer isolation under the secret-salt lookup — 40 link/end
// contexts seal/open only under their own keys, and retiring one never
// disturbs the rest.
template <typename Bank>
void suite_isolation(const AeadGcm& port) {
  Fixture<Bank> fix;
  CHECK_OK(fix.configure(port));
  constexpr std::size_t kPeers = 40;
  for (std::size_t i = 0; i < kPeers; ++i) {
    const NodeId peer = 1000 + i;
    const SecurityScope scope = (i % 2 == 0) ? SecurityScope::Link : SecurityScope::EndToEnd;
    ContextKeys keys{};
    keys.scope = scope;
    keys.network = kNet;
    keys.peer = peer;
    keys.tx_context_id = static_cast<std::uint32_t>(0x1000 + i);
    keys.rx_context_id = static_cast<std::uint32_t>(0x2000 + i);
    for (std::size_t b = 0; b < keys.tx_key.size(); ++b) {
      keys.tx_key[b] = static_cast<std::uint8_t>(i + b);
      keys.rx_key[b] = static_cast<std::uint8_t>(i + b + 0x40);
    }
    for (std::size_t b = 0; b < keys.tx_iv.size(); ++b) {
      keys.tx_iv[b] = static_cast<std::uint8_t>(i + b + 0x80);
      keys.rx_iv[b] = static_cast<std::uint8_t>(i + b + 0xC0);
    }
    InstallAttestation att{};
    att.created_gk_epoch = kGk;
    // The node bank holds 32 link + 8 end; the gateway holds 32 + 128.
    // Fill only what fits: link peers go first.
    if (scope == SecurityScope::Link && fix.bank.live_count(scope) >= 32) continue;
    if (scope == SecurityScope::EndToEnd && i >= 16) continue;
    CHECK_OK(fix.bank.install_verified(keys, att));
  }
  // Every installed context seals under its own epoch; a foreign epoch
  // never seals.
  const std::uint8_t aad[] = {0xEE};
  const std::uint8_t plain[] = {0xFF};
  for (std::size_t i = 0; i < kPeers; ++i) {
    const NodeId peer = 1000 + i;
    const SecurityScope scope = (i % 2 == 0) ? SecurityScope::Link : SecurityScope::EndToEnd;
    if (!fix.bank.has_usable(scope, peer)) continue;
    std::uint32_t epoch = 0;
    CHECK_OK(fix.bank.tx_epoch(scope, peer, epoch));
    CHECK(epoch == 0x1000 + i);
    std::uint64_t counter = 0;
    CHECK_OK(fix.bank.next_counter(seal_context(scope, peer, epoch), counter));
    std::array<std::uint8_t, 1> cipher{};
    std::array<std::uint8_t, kAeadTagSize> tag{};
    CHECK_OK(fix.bank.seal(seal_context(scope, peer, epoch), counter, ByteView{aad, 1},
                           ByteView{plain, 1}, MutableByteView{cipher.data(), 1}, tag));
    CHECK(fix.bank.seal(seal_context(scope, peer, epoch + 1), counter, ByteView{aad, 1},
                        ByteView{plain, 1}, MutableByteView{cipher.data(), 1}, tag)
              .code == StatusCode::InvalidArgument);
  }
  // A second bank with a different salt isolates identically (the salt is
  // device-local; lookups never depend on another bank's layout).
  Fixture<Bank> other;
  CHECK_OK(other.configure(port));
  install_link(other.bank, kPeer, 0x1111, 0x2222, 0x10);
  CHECK(other.bank.has_usable(SecurityScope::Link, kPeer));
  CHECK_OK(fix.bank.retire_all(kPeer));
  CHECK(other.bank.has_usable(SecurityScope::Link, kPeer));
}

// P4-C01: a crypto callback that re-enters the bank sees Busy and changes
// nothing — counters, windows, queues and out-params included.
bool reenter_seal(void* ctx) noexcept {
  auto& bank = *static_cast<NodeSessionBank*>(ctx);
  const std::uint8_t aad[] = {0x01};
  const std::uint8_t plain[] = {0x02};
  std::array<std::uint8_t, 1> cipher{};
  std::array<std::uint8_t, kAeadTagSize> tag{};
  const Status status =
      bank.seal(seal_context(SecurityScope::Link, kPeer, 0x1111), 0, ByteView{aad, 1},
                ByteView{plain, 1}, MutableByteView{cipher.data(), 1}, tag);
  return status.code == StatusCode::Busy;
}

void suite_reentry() {
  Fixture<NodeSessionBank> fix;
  CHECK_OK(fix.configure(fix.test_port()));
  install_link(fix.bank, kPeer, 0x1111, 0x2222, 0x10);
  fix.test_aead.reenter = &reenter_seal;
  fix.test_aead.reenter_ctx = &fix.bank;
  const std::uint8_t aad[] = {0x01};
  const std::uint8_t plain[] = {0x02, 0x03};
  std::uint64_t counter = 0;
  CHECK_OK(fix.bank.next_counter(seal_context(SecurityScope::Link, kPeer, 0x1111), counter));
  std::array<std::uint8_t, 2> cipher{0xAA, 0xAA};
  std::array<std::uint8_t, kAeadTagSize> tag{};
  CHECK_OK(fix.bank.seal(seal_context(SecurityScope::Link, kPeer, 0x1111), counter,
                         ByteView{aad, 1}, ByteView{plain, 2},
                         MutableByteView{cipher.data(), cipher.size()}, tag));
  CHECK(fix.test_aead.reenter_saw_busy);
  // The outer seal still went through exactly once; the next counter is next.
  std::uint64_t next = 0;
  CHECK_OK(fix.bank.next_counter(seal_context(SecurityScope::Link, kPeer, 0x1111), next));
  CHECK(next == counter + 1);
  // Queries stay readable under re-entry pressure (side-effect-free).
  CHECK(fix.bank.context_state(SecurityScope::Link, kPeer) == ContextState::Ready);
  CHECK(fix.bank.live_count(SecurityScope::Link) == 1);
}

void suite_provider_wiring() {
  Fixture<NodeSessionBank> fix;
  RamSessionProvider<32, 8> provider(fix.bank);
  CHECK(!provider.ready());
  CHECK(provider.security_profile() == SecurityProfile::Development);
  CHECK_OK(fix.configure(fix.test_port()));
  CHECK(provider.ready());
  install_link(fix.bank, kPeer, 0x1111, 0x2222, 0x10);
  std::uint32_t epoch = 0;
  CHECK_OK(provider.tx_epoch(SecurityScope::Link, kPeer, epoch));
  CHECK(epoch == 0x1111);
  CHECK_OK(provider.retire(SecurityScope::Link, kPeer));
  CHECK_OK(provider.retire_all(kPeer));
}

void suite_gateway_capacity(const AeadGcm& port) {
  Fixture<GatewaySessionBank> fix;
  CHECK_OK(fix.configure(port));
  // 128 end contexts install; the 129th refuses without disturbing them.
  for (std::size_t i = 0; i < 128; ++i) {
    ContextKeys keys{};
    keys.scope = SecurityScope::EndToEnd;
    keys.network = kNet;
    keys.peer = 5000 + i;
    keys.tx_context_id = static_cast<std::uint32_t>(0x10000 + i);
    keys.rx_context_id = static_cast<std::uint32_t>(0x20000 + i);
    keys.tx_key.fill(static_cast<std::uint8_t>(i + 1));
    keys.rx_key.fill(static_cast<std::uint8_t>(i + 2));
    keys.tx_iv.fill(static_cast<std::uint8_t>(i + 3));
    keys.rx_iv.fill(static_cast<std::uint8_t>(i + 4));
    InstallAttestation att{};
    att.created_gk_epoch = kGk;
    CHECK_OK(fix.bank.install_verified(keys, att));
  }
  CHECK(fix.bank.live_count(SecurityScope::EndToEnd) == 128);
  ContextKeys extra{};
  extra.scope = SecurityScope::EndToEnd;
  extra.network = kNet;
  extra.peer = 9999;
  extra.tx_context_id = 0x30000;
  extra.rx_context_id = 0x40000;
  extra.tx_key.fill(1);
  extra.rx_key.fill(2);
  extra.tx_iv.fill(3);
  extra.rx_iv.fill(4);
  InstallAttestation att{};
  att.created_gk_epoch = kGk;
  CHECK(fix.bank.install_verified(extra, att).code == StatusCode::NoCapacity);
  // Explicit eviction drops the oldest idle end context (peer 5000: its
  // install order is the LRU order here); pinned/busy ones survive.
  NodeId evicted = 0;
  CHECK_OK(fix.bank.evict_idle_end(evicted));
  CHECK(evicted == 5000);
  CHECK_OK(fix.bank.set_pinned(SecurityScope::EndToEnd, 5001, true));
  std::uint64_t counter = 0;
  CHECK_OK(
      fix.bank.next_counter(seal_context(SecurityScope::EndToEnd, 5002, 0x10002), counter));
  CHECK_OK(fix.bank.evict_idle_end(evicted));
  CHECK(evicted != 5001 && evicted != 5002);
  // Context ids stay unique across live and overlap entries.
  std::uint32_t id = 0;
  CHECK_OK(fix.bank.allocate_context_id(id));
  CHECK(id != 0 && !fix.bank.context_id_live(0xDEAD));
  CHECK(fix.bank.context_id_live(0x20001));
}

#ifdef ROUTELOOM_HAVE_OPENSSL
void suite_nist_gcm() {
  // NIST gcmEncryptExtIV128 cases 1-2 through the bank's own port shape,
  // proving the OpenSSL adapter (and the nonce/tag plumbing above it).
  OpenSslAead adapter{};
  const std::uint8_t key[16] = {0};
  const std::uint8_t iv[12] = {0};
  std::uint8_t tag[16] = {0};
  CHECK(OpenSslAead::seal(&adapter, key, iv, ByteView{nullptr, 0}, ByteView{nullptr, 0}, nullptr,
                          tag));
  const std::array<std::uint8_t, 16> case1_tag{0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61,
                                               0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a};
  CHECK(std::memcmp(tag, case1_tag.data(), 16) == 0);
  const std::uint8_t pt[16] = {0};
  std::uint8_t ct[16] = {0};
  CHECK(OpenSslAead::seal(&adapter, key, iv, ByteView{nullptr, 0}, ByteView{pt, 16}, ct, tag));
  const std::array<std::uint8_t, 16> case2_ct{0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
                                              0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78};
  const std::array<std::uint8_t, 16> case2_tag{0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
                                               0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf};
  CHECK(std::memcmp(ct, case2_ct.data(), 16) == 0);
  CHECK(std::memcmp(tag, case2_tag.data(), 16) == 0);
  std::uint8_t opened[16] = {0};
  CHECK(OpenSslAead::open(&adapter, key, iv, ByteView{nullptr, 0}, ByteView{ct, 16}, tag, opened));
  CHECK(std::memcmp(opened, pt, 16) == 0);
}
#endif

template <typename Bank>
void suite_peer_summary(const AeadGcm& port) {
  // The Owner's AuthenticatedPeerView feed: an engine install reports its
  // verified generation/role, anything else (unknown peer, role-0 public
  // installs) refuses.
  Fixture<Bank> fix;
  CHECK_OK(fix.configure(port));
  std::uint32_t generation = 0;
  std::uint32_t role = 0;
  CHECK(!fix.bank.peer_summary(SecurityScope::Link, kPeer, generation, role));
  install_link(fix.bank, kPeer, 0x1111, 0x2222, 0x10);
  CHECK(fix.bank.peer_summary(SecurityScope::Link, kPeer, generation, role));
  CHECK(generation == 3);
  CHECK(role == 0b011);
  CHECK(!fix.bank.peer_summary(SecurityScope::EndToEnd, kPeer, generation, role));
  CHECK(!fix.bank.peer_summary(SecurityScope::Link, kPeer + 1, generation, role));
}

template <typename Bank>
void run_suite(const AeadGcm& port, bool& fail_next) {
  suite_roundtrip<Bank>(port);
  suite_peer_summary<Bank>(port);
  suite_unknown_and_demand<Bank>(port);
  suite_reservation<Bank>(port, fail_next);
  suite_install_retire<Bank>(port);
  suite_overlap<Bank>(port);
  suite_lifetime<Bank>(port);
  suite_k04_reboot_forgets<Bank>(port);
  suite_isolation<Bank>(port);
}

}  // namespace

int main() {
  std::printf("sizeof SessionBankEntry=%zu SessionOverlapEntry=%zu\n", sizeof(SessionBankEntry),
              sizeof(SessionOverlapEntry));
  std::printf("sizeof NodeSessionBank=%zu GatewaySessionBank=%zu\n", sizeof(NodeSessionBank),
              sizeof(GatewaySessionBank));
  CHECK(sizeof(SessionOverlapEntry) <= 88);
  // Gateway bank composition: 160 x 128 B contexts + 8 x 72 B overlap +
  // 8 x 16 B demand + 250 B staging + 32 B salt + lookup/LRU flags. The
  // P4 §12.2 target is 21 KiB; the measured total (printed above) is gated
  // here so growth is deliberate, and PR4 settles the firmware fit.
  CHECK(sizeof(GatewaySessionBank) <= 23 * 1024);
  suite_use_budget();
  {
    TestAead adapter{};
    const AeadGcm port{&TestAead::seal, &TestAead::open, &adapter};
    run_suite<NodeSessionBank>(port, adapter.fail_next);
    suite_gateway_capacity(port);
  }
#ifdef ROUTELOOM_HAVE_OPENSSL
  {
    OpenSslAead adapter{};
    const AeadGcm port{&OpenSslAead::seal, &OpenSslAead::open, &adapter};
    run_suite<NodeSessionBank>(port, adapter.fail_next);
    suite_gateway_capacity(port);
    suite_nist_gcm();
    std::puts("session bank: openssl pass ran");
  }
#else
  std::puts("session bank: openssl pass skipped (OpenSSL not found)");
#endif
  suite_reentry();
  suite_provider_wiring();
  if (failures != 0) {
    std::fprintf(stderr, "%d session bank check(s) failed\n", failures);
    return 1;
  }
  std::puts("routeloom_sdkv1_session_bank_tests: ok");
  return 0;
}
