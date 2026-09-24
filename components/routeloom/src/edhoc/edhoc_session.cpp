// RouteLoom's libedhoc backend: bounded memory, bounded key store, suite-2
// crypto callbacks (micro-ecc P-256, routeloom SHA-256/HKDF, injected
// AES-CCM) and the kid-only credential bridge. See routeloom/edhoc.hpp.

#include "routeloom/edhoc.hpp"

#include <algorithm>
#include <cstring>

#include "libedhoc_api.hpp"
#include "routeloom/kdf.hpp"
#include "routeloom/secure_clear.hpp"
#include "uECC.h"

extern "C" std::size_t routeloom_edhoc_peer_cid(const struct edhoc_context* ctx,
                                                        std::uint8_t* out,
                                                        std::size_t capacity) noexcept;

namespace routeloom::edhoc {
namespace {

// The arena of the session whose libedhoc call is on this thread's stack.
// libedhoc's custom memory hooks take no context argument, so Session sets
// this around every call into the library (ArenaScope) and clears it after.
thread_local Arena* g_current_arena = nullptr;

class ArenaScope {
 public:
  explicit ArenaScope(Arena& arena) noexcept : previous_(g_current_arena) {
    g_current_arena = &arena;
  }
  ~ArenaScope() { g_current_arena = previous_; }
  ArenaScope(const ArenaScope&) = delete;
  ArenaScope& operator=(const ArenaScope&) = delete;

 private:
  Arena* previous_;
};

constexpr std::size_t align_up(const std::size_t value) noexcept {
  return (value + (Arena::kAlignment - 1)) & ~(Arena::kAlignment - 1);
}

std::uint32_t load_handle(const void* handle) noexcept {
  std::uint8_t bytes[KeyStore::kHandleSize];
  std::memcpy(bytes, handle, sizeof(bytes));
  return static_cast<std::uint32_t>(bytes[0]) |
         (static_cast<std::uint32_t>(bytes[1]) << 8) |
         (static_cast<std::uint32_t>(bytes[2]) << 16) |
         (static_cast<std::uint32_t>(bytes[3]) << 24);
}

void store_handle(void* handle, const std::uint32_t value) noexcept {
  const std::uint8_t bytes[KeyStore::kHandleSize] = {
      static_cast<std::uint8_t>(value), static_cast<std::uint8_t>(value >> 8),
      static_cast<std::uint8_t>(value >> 16), static_cast<std::uint8_t>(value >> 24)};
  std::memcpy(handle, bytes, sizeof(bytes));
}

// ---- P-256 helpers (micro-ecc; big-endian byte strings) --------------------

// SHA-256 uECC_HashContext for uECC_sign_deterministic.
struct DeterministicSha256 {
  uECC_HashContext base;
  Sha256 sha;
  std::array<std::uint8_t, 2 * 32 + 64> tmp{};
};

DeterministicSha256* det_cast(const uECC_HashContext* context) noexcept {
  // `base` is the first member; the context object is never const itself.
  return const_cast<DeterministicSha256*>(
      reinterpret_cast<const DeterministicSha256*>(context));
}
void det_init(const uECC_HashContext* context) { det_cast(context)->sha.reset(); }
void det_update(const uECC_HashContext* context, const std::uint8_t* message,
                const unsigned size) {
  det_cast(context)->sha.update(ByteView{message, size});
}
void det_finish(const uECC_HashContext* context, std::uint8_t* result) {
  ScopeDigest digest{};
  det_cast(context)->sha.finish(digest);
  std::memcpy(result, digest.data(), digest.size());
  secure_clear(digest);
}

// Accepts the three encodings a suite-2 peer key arrives in: x-only (EDHOC
// G_X / G_Y and RFC 9529 static keys, 32), X || Y (RouteLoom, 64) and SEC1
// uncompressed (65). The x-only form is decompressed with the even root;
// ECDH only uses the x-coordinate of the product, which is the same for
// either root. The point is always validated (on curve, in range): micro-ecc's
// shared-secret routine does not check its input.
bool load_peer_point(const std::uint8_t* key, const std::size_t size,
                     std::array<std::uint8_t, kP256PublicKeySize>& point) noexcept {
  if (key == nullptr) {
    return false;
  }
  if (size == kP256CoordinateSize) {
    std::array<std::uint8_t, 1 + kP256CoordinateSize> compressed{};
    compressed[0] = 0x02;
    std::memcpy(compressed.data() + 1, key, kP256CoordinateSize);
    uECC_decompress(compressed.data(), point.data(), uECC_secp256r1());
  } else if (size == kP256PublicKeySize) {
    std::memcpy(point.data(), key, kP256PublicKeySize);
  } else if (size == 1 + kP256PublicKeySize && key[0] == 0x04) {
    std::memcpy(point.data(), key + 1, kP256PublicKeySize);
  } else {
    return false;
  }
  return uECC_valid_public_key(point.data(), uECC_secp256r1()) != 0;
}

bool ecdh(const ByteView scalar, const std::uint8_t* peer, const std::size_t peer_size,
          std::array<std::uint8_t, kP256CoordinateSize>& secret) noexcept {
  if (scalar.size != kP256ScalarSize) {
    return false;
  }
  std::array<std::uint8_t, kP256PublicKeySize> point{};
  if (!load_peer_point(peer, peer_size, point)) {
    return false;
  }
  return uECC_shared_secret(point.data(), scalar.data, secret.data(),
                            uECC_secp256r1()) != 0;
}

}  // namespace

// ---------------------------------------------------------------------------
// Arena

void* Arena::allocate(const std::size_t size) noexcept {
  const std::size_t need = align_up(size == 0 ? 1 : size);
  if (size > kCapacity || need > kCapacity || count_ >= kMaxBlocks) {
    ++failures_;
    return nullptr;
  }
  // First fit in offset order: the gap before blocks_[i], then the tail.
  std::size_t cursor = 0;
  std::size_t insert_at = count_;
  for (std::size_t i = 0; i < count_; ++i) {
    if (blocks_[i].offset - cursor >= need) {
      insert_at = i;
      break;
    }
    cursor = blocks_[i].offset + align_up(blocks_[i].size);
  }
  if (insert_at == count_ && kCapacity - cursor < need) {
    ++failures_;
    return nullptr;
  }
  for (std::size_t i = count_; i > insert_at; --i) {
    blocks_[i] = blocks_[i - 1];
  }
  blocks_[insert_at] = Block{static_cast<std::uint32_t>(cursor),
                             static_cast<std::uint32_t>(size)};
  ++count_;
  std::memset(bytes_.data() + cursor, 0, need);
  high_water_ = std::max(high_water_, cursor + need);
  max_live_blocks_ = std::max(max_live_blocks_, count_);
  return bytes_.data() + cursor;
}

void Arena::release(void* block) noexcept {
  if (block == nullptr) {
    return;
  }
  const auto* byte = static_cast<const std::uint8_t*>(block);
  if (byte < bytes_.data() || byte >= bytes_.data() + kCapacity) {
    return;  // not ours; never touch foreign memory
  }
  const auto offset = static_cast<std::uint32_t>(byte - bytes_.data());
  for (std::size_t i = 0; i < count_; ++i) {
    if (blocks_[i].offset == offset) {
      secure_clear(bytes_.data() + offset, align_up(blocks_[i].size));
      for (std::size_t j = i + 1; j < count_; ++j) {
        blocks_[j - 1] = blocks_[j];
      }
      --count_;
      return;
    }
  }
}

void Arena::reset() noexcept {
  secure_clear(bytes_.data(), bytes_.size());
  count_ = 0;
}

std::size_t Arena::in_use() const noexcept {
  std::size_t total = 0;
  for (std::size_t i = 0; i < count_; ++i) {
    total += align_up(blocks_[i].size);
  }
  return total;
}

// ---------------------------------------------------------------------------
// KeyStore

const KeyStore::Slot* KeyStore::resolve(const void* handle) const noexcept {
  if (handle == nullptr) {
    return nullptr;
  }
  const std::uint32_t value = load_handle(handle);
  const std::uint32_t index = value & 0xFFu;
  if (index == 0 || index > kSlots) {
    return nullptr;
  }
  const Slot& slot = slots_[index - 1];
  if (slot.usage == KeyUsage::None || slot.generation != (value >> 8)) {
    return nullptr;
  }
  return &slot;
}

bool KeyStore::import(const KeyUsage usage, const ByteView material,
                      void* handle_out) noexcept {
  if (handle_out == nullptr || usage == KeyUsage::None || material.data == nullptr ||
      material.size == 0 || material.size > kMaxKeySize) {
    return false;
  }
  for (std::size_t i = 0; i < kSlots; ++i) {
    Slot& slot = slots_[i];
    if (slot.usage != KeyUsage::None) {
      continue;
    }
    // Generations are 1..0xFFFF so a live handle is never all-zero and a
    // stale handle to a reused slot does not resolve.
    slot.generation = static_cast<std::uint16_t>(slot.generation == 0xFFFFu
                                                     ? 1u
                                                     : slot.generation + 1u);
    std::memcpy(slot.bytes.data(), material.data, material.size);
    slot.size = static_cast<std::uint8_t>(material.size);
    slot.usage = usage;
    store_handle(handle_out, (static_cast<std::uint32_t>(slot.generation) << 8) |
                                 static_cast<std::uint32_t>(i + 1));
    high_water_ = std::max(high_water_, live());
    return true;
  }
  return false;
}

ByteView KeyStore::find(const void* handle, const KeyUsage usage) const noexcept {
  const Slot* slot = resolve(handle);
  if (slot == nullptr || slot->usage != usage) {
    return ByteView{};
  }
  return ByteView{slot->bytes.data(), slot->size};
}

ByteView KeyStore::peek(const void* handle) const noexcept {
  const Slot* slot = resolve(handle);
  return slot == nullptr ? ByteView{} : ByteView{slot->bytes.data(), slot->size};
}

bool KeyStore::destroy(const void* handle) noexcept {
  if (handle == nullptr) {
    return false;
  }
  if (load_handle(handle) == 0) {
    return true;  // null handle
  }
  const Slot* found = resolve(handle);
  if (found == nullptr) {
    return false;
  }
  Slot& slot = slots_[static_cast<std::size_t>(found - slots_.data())];
  secure_clear(slot.bytes);
  slot.size = 0;
  slot.usage = KeyUsage::None;
  return true;
}

void KeyStore::clear() noexcept {
  for (Slot& slot : slots_) {
    secure_clear(slot.bytes);
    slot.size = 0;
    slot.usage = KeyUsage::None;
  }
}

std::size_t KeyStore::live() const noexcept {
  std::size_t n = 0;
  for (const Slot& slot : slots_) {
    n += slot.usage != KeyUsage::None ? 1 : 0;
  }
  return n;
}

// ---------------------------------------------------------------------------
// libedhoc callbacks

struct Session::Backend {
  static Session& self(void* user) noexcept { return *static_cast<Session*>(user); }

  // New ephemeral P-256 key: rejection-sample a scalar in [1, n-1] from the
  // session RNG (uECC_compute_public_key rejects 0 and >= n).
  static bool make_ephemeral(Session& s, std::array<std::uint8_t, kP256ScalarSize>& scalar,
                             std::array<std::uint8_t, kP256PublicKeySize>& point) noexcept {
    for (int attempt = 0; attempt < 8; ++attempt) {
      if (!s.config_.random(s.config_.random_ctx, scalar.data(), scalar.size())) {
        return false;
      }
      if (uECC_compute_public_key(scalar.data(), point.data(), uECC_secp256r1()) != 0) {
        return true;
      }
    }
    return false;
  }

  static int destroy_key(void* user, void* key_id) {
    return self(user).keys_.destroy(key_id) ? EDHOC_SUCCESS : EDHOC_ERROR_CRYPTO_FAILURE;
  }

  static int generate_key_pair(void* user, void* decaps_key_id, std::uint8_t* encaps_key,
                               std::size_t encaps_key_size, std::size_t* encaps_key_length) {
    Session& s = self(user);
    if (decaps_key_id == nullptr || encaps_key == nullptr || encaps_key_length == nullptr ||
        encaps_key_size < kP256CoordinateSize) {
      return EDHOC_ERROR_INVALID_ARGUMENT;
    }
    std::array<std::uint8_t, kP256ScalarSize> scalar{};
    std::array<std::uint8_t, kP256PublicKeySize> point{};
    const bool ok = make_ephemeral(s, scalar, point) &&
                    s.keys_.import(KeyUsage::Ephemeral,
                                   ByteView{scalar.data(), scalar.size()}, decaps_key_id);
    secure_clear(scalar);
    if (!ok) {
      return EDHOC_ERROR_CRYPTO_FAILURE;
    }
    std::memcpy(encaps_key, point.data(), kP256CoordinateSize);
    *encaps_key_length = kP256CoordinateSize;
    return EDHOC_SUCCESS;
  }

  // NIKE "encapsulation" (Responder): own ephemeral Y, G_XY = ECDH(Y, G_X),
  // ciphertext = G_Y; Y stays in the store for the static-DH G_IY.
  static int encapsulate(void* user, const std::uint8_t* encaps_key,
                         std::size_t encaps_key_length, void* decaps_key_id,
                         void* shared_secret_key_id, std::uint8_t* ciphertext,
                         std::size_t ciphertext_size, std::size_t* ciphertext_length) {
    Session& s = self(user);
    if (encaps_key == nullptr || decaps_key_id == nullptr || shared_secret_key_id == nullptr ||
        ciphertext == nullptr || ciphertext_length == nullptr ||
        ciphertext_size < kP256CoordinateSize) {
      return EDHOC_ERROR_INVALID_ARGUMENT;
    }
    std::array<std::uint8_t, kP256ScalarSize> scalar{};
    std::array<std::uint8_t, kP256PublicKeySize> point{};
    std::array<std::uint8_t, kP256CoordinateSize> secret{};
    bool ok = make_ephemeral(s, scalar, point) &&
              ecdh(ByteView{scalar.data(), scalar.size()}, encaps_key, encaps_key_length,
                   secret);
    ok = ok && s.keys_.import(KeyUsage::Kdf, ByteView{secret.data(), secret.size()},
                              shared_secret_key_id);
    if (ok && !s.keys_.import(KeyUsage::Ephemeral, ByteView{scalar.data(), scalar.size()},
                              decaps_key_id)) {
      s.keys_.destroy(shared_secret_key_id);
      ok = false;
    }
    secure_clear(scalar);
    secure_clear(secret);
    if (!ok) {
      return EDHOC_ERROR_CRYPTO_FAILURE;
    }
    std::memcpy(ciphertext, point.data(), kP256CoordinateSize);
    *ciphertext_length = kP256CoordinateSize;
    return EDHOC_SUCCESS;
  }

  static int decapsulate(void* user, const void* decaps_key_id, const std::uint8_t* ciphertext,
                         std::size_t ciphertext_length, void* shared_secret_key_id) {
    Session& s = self(user);
    if (shared_secret_key_id == nullptr) {
      return EDHOC_ERROR_INVALID_ARGUMENT;
    }
    std::array<std::uint8_t, kP256CoordinateSize> secret{};
    const bool ok =
        ecdh(s.keys_.find(decaps_key_id, KeyUsage::Ephemeral), ciphertext, ciphertext_length,
             secret) &&
        s.keys_.import(KeyUsage::Kdf, ByteView{secret.data(), secret.size()},
                       shared_secret_key_id);
    secure_clear(secret);
    return ok ? EDHOC_SUCCESS : EDHOC_ERROR_CRYPTO_FAILURE;
  }

  // Static DH (methods 1-3): one side's static key, the other's ephemeral.
  static int key_agreement(void* user, const void* private_key_id,
                           const std::uint8_t* peer_public_key,
                           std::size_t peer_public_key_length, void* shared_secret_key_id) {
    Session& s = self(user);
    if (shared_secret_key_id == nullptr) {
      return EDHOC_ERROR_INVALID_ARGUMENT;
    }
    ByteView scalar = s.keys_.find(private_key_id, KeyUsage::Ephemeral);
    if (scalar.size == 0) {
      scalar = s.keys_.find(private_key_id, KeyUsage::Authentication);
    }
    std::array<std::uint8_t, kP256CoordinateSize> secret{};
    const bool ok = ecdh(scalar, peer_public_key, peer_public_key_length, secret) &&
                    s.keys_.import(KeyUsage::Kdf, ByteView{secret.data(), secret.size()},
                                   shared_secret_key_id);
    secure_clear(secret);
    return ok ? EDHOC_SUCCESS : EDHOC_ERROR_CRYPTO_FAILURE;
  }

  // ES256 over the full input (COSE Sig_structure): SHA-256, then
  // deterministic ECDSA (no RNG involvement).
  static int sign(void* user, const void* private_key_id, const std::uint8_t* input,
                  std::size_t input_length, std::uint8_t* signature,
                  std::size_t signature_size, std::size_t* signature_length) {
    Session& s = self(user);
    const ByteView scalar = s.keys_.find(private_key_id, KeyUsage::Authentication);
    if (scalar.size != kP256ScalarSize || (input == nullptr && input_length != 0) ||
        signature == nullptr || signature_length == nullptr ||
        signature_size < kEs256SignatureSize) {
      return EDHOC_ERROR_INVALID_ARGUMENT;
    }
    ScopeDigest digest{};
    sha256(ByteView{input, input_length}, digest);
    DeterministicSha256 context{};
    context.base = {&det_init, &det_update, &det_finish, 64, 32, context.tmp.data()};
    const int ok = uECC_sign_deterministic(scalar.data, digest.data(),
                                           static_cast<unsigned>(digest.size()),
                                           &context.base, signature, uECC_secp256r1());
    secure_clear(context.tmp);
    secure_clear(digest);
    if (ok == 0) {
      return EDHOC_ERROR_CRYPTO_FAILURE;
    }
    *signature_length = kEs256SignatureSize;
    return EDHOC_SUCCESS;
  }

  static int verify(void* /*user*/, const std::uint8_t* public_key,
                    std::size_t public_key_length, const std::uint8_t* input,
                    std::size_t input_length, const std::uint8_t* signature,
                    std::size_t signature_length) {
    if (public_key == nullptr || (input == nullptr && input_length != 0) ||
        signature == nullptr || signature_length != kEs256SignatureSize ||
        public_key_length == kP256CoordinateSize) {  // x-only is ambiguous for ECDSA
      return EDHOC_ERROR_INVALID_ARGUMENT;
    }
    std::array<std::uint8_t, kP256PublicKeySize> point{};
    if (!load_peer_point(public_key, public_key_length, point)) {
      return EDHOC_ERROR_CRYPTO_FAILURE;
    }
    ScopeDigest digest{};
    sha256(ByteView{input, input_length}, digest);
    const int ok = uECC_verify(point.data(), digest.data(),
                               static_cast<unsigned>(digest.size()), signature,
                               uECC_secp256r1());
    return ok != 0 ? EDHOC_SUCCESS : EDHOC_ERROR_CRYPTO_FAILURE;
  }

  static int extract(void* user, const void* ikm_key_id, const std::uint8_t* salt,
                     std::size_t salt_length, void* prk_key_id) {
    Session& s = self(user);
    const ByteView ikm = s.keys_.find(ikm_key_id, KeyUsage::Kdf);
    if (ikm.size == 0 || salt == nullptr || salt_length == 0 || prk_key_id == nullptr) {
      return EDHOC_ERROR_INVALID_ARGUMENT;
    }
    ScopeDigest prk{};
    hkdf_sha256_extract(ByteView{salt, salt_length}, ikm, prk);
    const bool ok = s.keys_.import(KeyUsage::Kdf, ByteView{prk.data(), prk.size()}, prk_key_id);
    secure_clear(prk);
    return ok ? EDHOC_SUCCESS : EDHOC_ERROR_CRYPTO_FAILURE;
  }

  static int expand(void* user, const void* prk_key_id, const std::uint8_t* info,
                    std::size_t info_length, enum edhoc_key_usage usage,
                    void* output_key_id) {
    Session& s = self(user);
    const ByteView prk = s.keys_.find(prk_key_id, KeyUsage::Kdf);
    if (prk.size == 0 || info == nullptr || info_length == 0 || output_key_id == nullptr) {
      return EDHOC_ERROR_INVALID_ARGUMENT;
    }
    KeyUsage out_usage = KeyUsage::None;
    std::size_t out_size = 0;
    switch (usage) {
      case EDHOC_KEY_USAGE_KDF:
        out_usage = KeyUsage::Kdf;
        out_size = kSuite2HashSize;
        break;
      case EDHOC_KEY_USAGE_AEAD:
        out_usage = KeyUsage::Aead;
        out_size = kSuite2AeadKeySize;
        break;
      default:
        return EDHOC_ERROR_INVALID_ARGUMENT;
    }
    std::array<std::uint8_t, kSuite2HashSize> okm{};
    bool ok = hkdf_sha256_expand(prk, ByteView{info, info_length},
                                 MutableByteView{okm.data(), out_size})
                  .ok();
    ok = ok && s.keys_.import(out_usage, ByteView{okm.data(), out_size}, output_key_id);
    secure_clear(okm);
    return ok ? EDHOC_SUCCESS : EDHOC_ERROR_CRYPTO_FAILURE;
  }

  static int expand_raw(void* user, const void* prk_key_id, const std::uint8_t* info,
                        std::size_t info_length, std::uint8_t* output,
                        std::size_t output_length) {
    Session& s = self(user);
    const ByteView prk = s.keys_.find(prk_key_id, KeyUsage::Kdf);
    if (prk.size == 0 || info == nullptr || info_length == 0 || output == nullptr ||
        output_length == 0) {
      return EDHOC_ERROR_INVALID_ARGUMENT;
    }
    return hkdf_sha256_expand(prk, ByteView{info, info_length},
                              MutableByteView{output, output_length})
                   .ok()
               ? EDHOC_SUCCESS
               : EDHOC_ERROR_CRYPTO_FAILURE;
  }

  static int aead_encrypt(void* user, const void* key_id, const std::uint8_t* nonce,
                          std::size_t nonce_length, const std::uint8_t* additional_data,
                          std::size_t additional_data_length, const std::uint8_t* plaintext,
                          std::size_t plaintext_length, std::uint8_t* ciphertext,
                          std::size_t ciphertext_size, std::size_t* ciphertext_length) {
    Session& s = self(user);
    const ByteView key = s.keys_.find(key_id, KeyUsage::Aead);
    if (key.size != kSuite2AeadKeySize || nonce == nullptr ||
        nonce_length != kSuite2AeadNonceSize ||
        (additional_data == nullptr && additional_data_length != 0) ||
        (plaintext == nullptr && plaintext_length != 0) || ciphertext == nullptr ||
        ciphertext_length == nullptr || plaintext_length > ciphertext_size ||
        ciphertext_size - plaintext_length < kSuite2AeadTagSize) {
      return EDHOC_ERROR_INVALID_ARGUMENT;
    }
    if (!s.aead_->seal(s.aead_->ctx, key.data, nonce,
                       ByteView{additional_data, additional_data_length},
                       ByteView{plaintext, plaintext_length}, ciphertext)) {
      return EDHOC_ERROR_CRYPTO_FAILURE;
    }
    *ciphertext_length = plaintext_length + kSuite2AeadTagSize;
    return EDHOC_SUCCESS;
  }

  static int aead_decrypt(void* user, const void* key_id, const std::uint8_t* nonce,
                          std::size_t nonce_length, const std::uint8_t* additional_data,
                          std::size_t additional_data_length, const std::uint8_t* ciphertext,
                          std::size_t ciphertext_length, std::uint8_t* plaintext,
                          std::size_t plaintext_size, std::size_t* plaintext_length) {
    Session& s = self(user);
    const ByteView key = s.keys_.find(key_id, KeyUsage::Aead);
    if (key.size != kSuite2AeadKeySize || nonce == nullptr ||
        nonce_length != kSuite2AeadNonceSize ||
        (additional_data == nullptr && additional_data_length != 0) ||
        ciphertext == nullptr || ciphertext_length < kSuite2AeadTagSize ||
        plaintext_length == nullptr ||
        plaintext_size < ciphertext_length - kSuite2AeadTagSize ||
        (plaintext == nullptr && ciphertext_length != kSuite2AeadTagSize)) {
      return EDHOC_ERROR_INVALID_ARGUMENT;
    }
    // A zero-length plaintext (message_4 with no EAD) still needs a valid
    // output pointer for the AEAD hook.
    std::uint8_t empty = 0;
    if (!s.aead_->open(s.aead_->ctx, key.data, nonce,
                       ByteView{additional_data, additional_data_length},
                       ByteView{ciphertext, ciphertext_length},
                       plaintext != nullptr ? plaintext : &empty)) {
      return EDHOC_ERROR_CRYPTO_FAILURE;
    }
    *plaintext_length = ciphertext_length - kSuite2AeadTagSize;
    return EDHOC_SUCCESS;
  }

  static HashOp* hash_op(Session& s, void* operation) noexcept {
    for (HashOp& op : s.hashes_) {
      if (&op == operation && op.busy) {
        return &op;
      }
    }
    return nullptr;
  }

  static void release_hash(HashOp& op) noexcept {
    op.sha = Sha256{};  // drops the buffered transcript bytes
    op.busy = false;
  }

  static int hash_init(void* user, void** operation) {
    Session& s = self(user);
    if (operation == nullptr) {
      return EDHOC_ERROR_INVALID_ARGUMENT;
    }
    for (HashOp& op : s.hashes_) {
      if (!op.busy) {
        op.sha.reset();
        op.busy = true;
        *operation = &op;
        return EDHOC_SUCCESS;
      }
    }
    return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
  }

  static int hash_update(void* user, void* operation, const std::uint8_t* input,
                         std::size_t input_length) {
    HashOp* op = hash_op(self(user), operation);
    if (op == nullptr || (input == nullptr && input_length != 0)) {
      return EDHOC_ERROR_INVALID_ARGUMENT;
    }
    op->sha.update(ByteView{input, input_length});
    return EDHOC_SUCCESS;
  }

  static int hash_finish(void* user, void* operation, std::uint8_t* hash,
                         std::size_t hash_size, std::size_t* hash_length) {
    HashOp* op = hash_op(self(user), operation);
    if (op == nullptr) {
      return EDHOC_ERROR_INVALID_ARGUMENT;
    }
    if (hash == nullptr || hash_length == nullptr || hash_size < kSuite2HashSize) {
      release_hash(*op);
      return EDHOC_ERROR_INVALID_ARGUMENT;
    }
    ScopeDigest digest{};
    op->sha.finish(digest);
    release_hash(*op);
    std::memcpy(hash, digest.data(), digest.size());
    *hash_length = digest.size();
    return EDHOC_SUCCESS;
  }

  static int hash_abort(void* user, void* operation) {
    HashOp* op = hash_op(self(user), operation);
    if (op != nullptr) {
      release_hash(*op);
    }
    return EDHOC_SUCCESS;
  }

  static void zeroize(void* buffer, std::size_t length) {
    if (buffer != nullptr) {
      secure_clear(buffer, length);
    }
  }

  static Role role_of(const edhoc_call_context* call) noexcept {
    return call != nullptr && call->role == EDHOC_ROLE_RESPONDER ? Role::Responder
                                                                 : Role::Initiator;
  }

  static int select_local(void* user, const edhoc_call_context* call,
                          edhoc_credential_selected* selected) {
    Session& s = self(user);
    if (selected == nullptr) {
      return EDHOC_ERROR_INVALID_ARGUMENT;
    }
    LocalCredential local{};
    const Status status = s.config_.credentials->local(role_of(call), local);
    bool ok = status.ok() && local.kid.data != nullptr && local.kid.size != 0 &&
              local.kid.size <= kKidMaxSize && local.credential.data != nullptr &&
              local.credential.size != 0;
    if (ok) {
      s.keys_.destroy(s.local_key_.data());
      s.local_key_.fill(0);
      ok = s.keys_.import(KeyUsage::Authentication,
                          ByteView{local.private_key.data(), local.private_key.size()},
                          s.local_key_.data());
    }
    secure_clear(local.private_key);
    if (!ok) {
      return EDHOC_ERROR_CREDENTIALS_FAILURE;
    }
    selected->asymmetric.label = EDHOC_COSE_HEADER_KID;
    selected->asymmetric.kid.identifier.value = local.kid.data;
    selected->asymmetric.kid.identifier.length = local.kid.size;
    selected->asymmetric.kid.credential.value = local.credential.data;
    selected->asymmetric.kid.credential.length = local.credential.size;
    selected->asymmetric.kid.format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED;
    std::memcpy(selected->asymmetric.private_key_id, s.local_key_.data(),
                s.local_key_.size());
    return EDHOC_SUCCESS;
  }

  static int authenticate_peer(void* user, const edhoc_call_context* call,
                               const edhoc_credential_received* received,
                               edhoc_credential_trusted* trusted) {
    Session& s = self(user);
    if (received == nullptr || trusted == nullptr) {
      return EDHOC_ERROR_INVALID_ARGUMENT;
    }
    if (received->label != EDHOC_COSE_HEADER_KID ||
        received->kid.identifier.value == nullptr || received->kid.identifier.length == 0 ||
        received->kid.identifier.length > kKidMaxSize) {
      return EDHOC_ERROR_CREDENTIALS_FAILURE;  // RouteLoom references by kid only
    }
    PeerCredential peer{};
    const Status status = s.config_.credentials->peer(
        role_of(call),
        ByteView{received->kid.identifier.value, received->kid.identifier.length}, peer);
    if (!status.ok() || peer.credential.data == nullptr || peer.credential.size == 0 ||
        uECC_valid_public_key(peer.public_key.data(), uECC_secp256r1()) == 0) {
      return EDHOC_ERROR_CREDENTIALS_FAILURE;
    }
    s.peer_public_key_ = peer.public_key;
    trusted->asymmetric.credential.value = peer.credential.data;
    trusted->asymmetric.credential.length = peer.credential.size;
    trusted->asymmetric.format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED;
    trusted->asymmetric.public_key.value = s.peer_public_key_.data();
    trusted->asymmetric.public_key.length = s.peer_public_key_.size();
    return EDHOC_SUCCESS;
  }

  // --- EAD (RFC 9528 §3.8), bound only when SessionConfig::ead is set -------

  static int message_number(const edhoc_call_context* call) noexcept {
    return call == nullptr ? 0 : static_cast<int>(call->message) + 1;
  }

  static int ead_compose(void* user, const edhoc_call_context* call, edhoc_ead_token* tokens,
                         const std::size_t capacity, std::size_t* count) {
    if (user == nullptr || tokens == nullptr || count == nullptr) {
      return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
    }
    Session& s = *static_cast<Session*>(user);
    *count = 0;
    if (s.config_.ead == nullptr) return EDHOC_SUCCESS;
    std::array<EadItem, kEadItemsMax> items{};
    const std::size_t room = std::min(capacity, items.size());
    std::size_t written = 0;
    const Status status = s.config_.ead->compose(message_number(call), items.data(), room, written);
    if (!status.ok() || written > room) return EDHOC_ERROR_EAD_COMPOSE_FAILURE;
    for (std::size_t i = 0; i < written; ++i) {
      tokens[i].label = items[i].label;
      tokens[i].value.value = items[i].value.data;
      tokens[i].value.length = items[i].value.size;
    }
    *count = written;
    return EDHOC_SUCCESS;
  }

  static int ead_process(void* user, const edhoc_call_context* call,
                         const edhoc_ead_token* tokens, const std::size_t count) {
    if (user == nullptr || (tokens == nullptr && count != 0) || count > kEadItemsMax) {
      return EDHOC_ERROR_EAD_PROCESS_FAILURE;
    }
    Session& s = *static_cast<Session*>(user);
    if (s.config_.ead == nullptr) return EDHOC_ERROR_EAD_PROCESS_FAILURE;
    std::array<EadItem, kEadItemsMax> items{};
    for (std::size_t i = 0; i < count; ++i) {
      items[i].label = tokens[i].label;
      items[i].value = ByteView{tokens[i].value.value, tokens[i].value.length};
    }
    const Status status = s.config_.ead->process(message_number(call), items.data(), count);
    return status.ok() ? EDHOC_SUCCESS : EDHOC_ERROR_EAD_PROCESS_FAILURE;
  }

  static const edhoc_crypto kCrypto;
  static const edhoc_credentials kCredentials;
  static const edhoc_platform kPlatform;
  static const edhoc_ead kEad;
};

const edhoc_ead Session::Backend::kEad = {
    &Session::Backend::ead_compose,
    &Session::Backend::ead_process,
};

const edhoc_crypto Session::Backend::kCrypto = {
    &Session::Backend::destroy_key,  &Session::Backend::generate_key_pair,
    &Session::Backend::encapsulate,  &Session::Backend::decapsulate,
    &Session::Backend::key_agreement, &Session::Backend::sign,
    &Session::Backend::verify,       &Session::Backend::extract,
    &Session::Backend::expand,       &Session::Backend::expand_raw,
    &Session::Backend::aead_encrypt, &Session::Backend::aead_decrypt,
    &Session::Backend::hash_init,    &Session::Backend::hash_update,
    &Session::Backend::hash_finish,  &Session::Backend::hash_abort,
};

const edhoc_credentials Session::Backend::kCredentials = {
    &Session::Backend::select_local,
    &Session::Backend::authenticate_peer,
};

const edhoc_platform Session::Backend::kPlatform = {&Session::Backend::zeroize};

// ---------------------------------------------------------------------------
// Session

namespace {

edhoc_cipher_suite suite_parameters(const std::int32_t value) noexcept {
  // RFC 9528 §3.6 / Table 13, cipher suite 2 lengths. Other suite values
  // only appear in SUITES_I for negotiation and are never selected
  // (begin() requires the selected suite to be 2).
  edhoc_cipher_suite suite{};
  suite.value = value;
  suite.supports_dh_nike = true;
  suite.kem_encapsulation_key_length = kP256CoordinateSize;
  suite.kem_ciphertext_length = kP256CoordinateSize;
  suite.nike_key_length = kP256CoordinateSize;
  suite.sign_length = kEs256SignatureSize;
  suite.aead_key_length = kSuite2AeadKeySize;
  suite.aead_tag_length = kSuite2AeadTagSize;
  suite.aead_iv_length = kSuite2AeadNonceSize;
  suite.hash_length = kSuite2HashSize;
  suite.mac_length = kSuite2AeadTagSize;  // static-DH MAC length (method 3)
  return suite;
}

Status map_error(const int result, const char* detail) noexcept {
  switch (result) {
    case EDHOC_SUCCESS:
      return Status::success();
    case EDHOC_ERROR_BUFFER_TOO_SMALL:
    case EDHOC_ERROR_NOT_ENOUGH_MEMORY:
      return Status::error(StatusCode::NoCapacity, detail);
    case EDHOC_ERROR_BAD_STATE:
      return Status::error(StatusCode::InvalidState, detail);
    case EDHOC_ERROR_INVALID_ARGUMENT:
      return Status::error(StatusCode::InvalidArgument, detail);
    case EDHOC_ERROR_NOT_SUPPORTED:
    case EDHOC_ERROR_NOT_PERMITTED:
      return Status::error(StatusCode::Unsupported, detail);
    case EDHOC_ERROR_CREDENTIALS_FAILURE:
    case EDHOC_ERROR_INVALID_SIGN_OR_MAC_2:
    case EDHOC_ERROR_INVALID_SIGN_OR_MAC_3:
    case EDHOC_ERROR_CRYPTO_FAILURE:
      return Status::error(StatusCode::AuthenticationFailed, detail);
    default:
      return Status::error(StatusCode::ProtocolError, detail);
  }
}

}  // namespace

Session::~Session() { end(); }

edhoc_context* Session::native() noexcept {
  return reinterpret_cast<edhoc_context*>(context_storage_.data());
}

Status Session::peer_connection_id(MutableByteView out, std::size_t& length) noexcept {
  length = 0;
  if (!active_) return Status::error(StatusCode::InvalidState, "edhoc session not active");
  if (out.data == nullptr) {
    return Status::error(StatusCode::InvalidArgument, "edhoc peer cid buffer");
  }
  const std::size_t negotiated =
      routeloom_edhoc_peer_cid(native(), out.data, out.size);
  if (negotiated == 0) {
    return Status::error(StatusCode::NotFound, "edhoc peer cid not negotiated");
  }
  if (negotiated > out.size) {
    return Status::error(StatusCode::NoCapacity, "edhoc peer cid too long");
  }
  length = negotiated;
  return Status::success();
}

Status Session::finish_call(const int result, const char* detail) noexcept {
  last_error_ = result;
  return map_error(result, detail);
}

Status Session::begin(const SessionConfig& config) noexcept {
  if (active_) {
    return Status::error(StatusCode::InvalidState, "edhoc session already active");
  }
  if (config.credentials == nullptr || config.random == nullptr ||
      config.suite_count == 0 || config.suite_count > config.suites.size() ||
      config.suites[config.suite_count - 1] != kCipherSuite2 ||
      (config.role == Role::Responder && config.suite_count != 1) ||
      config.connection_id.data == nullptr || config.connection_id.size == 0 ||
      config.connection_id.size > kConnectionIdMaxSize ||
      static_cast<std::uint8_t>(config.method) > 3) {
    return Status::error(StatusCode::InvalidArgument, "edhoc session config");
  }
  const AeadCcm* aead = config.aead != nullptr ? config.aead : builtin_aead_ccm();
  if (aead == nullptr || aead->seal == nullptr || aead->open == nullptr) {
    return Status::error(StatusCode::Unsupported, "edhoc aes-ccm backend");
  }
  if (edhoc_context_size() > context_storage_.size()) {
    return Status::error(StatusCode::InternalError, "edhoc context storage");
  }

  config_ = config;
  aead_ = aead;
  context_storage_.fill(0);
  arena_.reset();
  keys_.clear();
  local_key_.fill(0);
  for (HashOp& op : hashes_) {
    Backend::release_hash(op);
  }

  edhoc_context* ctx = native();
  std::array<edhoc_cipher_suite, ROUTELOOM_EDHOC_SUITES_MAX> suites{};
  for (std::size_t i = 0; i < config.suite_count; ++i) {
    suites[i] = suite_parameters(config.suites[i]);
  }
  const edhoc_method method = static_cast<edhoc_method>(config.method);
  const edhoc_buffer cid{config.connection_id.data, config.connection_id.size};

  int result = edhoc_context_init(ctx);
  if (result == EDHOC_SUCCESS) {
    active_ = true;
    result = edhoc_set_methods(ctx, &method, 1);
  }
  if (result == EDHOC_SUCCESS) {
    result = edhoc_set_cipher_suites(ctx, suites.data(), config.suite_count);
  }
  if (result == EDHOC_SUCCESS) {
    result = edhoc_set_connection_id(ctx, &cid);
  }
  if (result == EDHOC_SUCCESS) {
    result = edhoc_set_user_context(ctx, this);
  }
  if (result == EDHOC_SUCCESS) {
    result = edhoc_bind_crypto(ctx, &Backend::kCrypto);
  }
  if (result == EDHOC_SUCCESS) {
    result = edhoc_bind_credentials(ctx, &Backend::kCredentials);
  }
  if (result == EDHOC_SUCCESS) {
    result = edhoc_bind_platform(ctx, &Backend::kPlatform);
  }
  if (result == EDHOC_SUCCESS && config.ead != nullptr) {
    result = edhoc_bind_ead(ctx, &Backend::kEad);
  }
  const Status status = finish_call(result, "edhoc session setup");
  if (!status.ok()) {
    end();
  }
  return status;
}

void Session::end() noexcept {
  if (active_) {
    ArenaScope scope(arena_);
    (void)edhoc_context_deinit(native());
    active_ = false;
  }
  secure_clear(context_storage_.data(), context_storage_.size());
  arena_.reset();
  keys_.clear();
  local_key_.fill(0);
  secure_clear(peer_public_key_);
  for (HashOp& op : hashes_) {
    Backend::release_hash(op);
  }
}

#define ROUTELOOM_EDHOC_CALL(detail, expr)                                  \
  do {                                                                      \
    if (!active_) {                                                         \
      return Status::error(StatusCode::InvalidState, "edhoc session idle"); \
    }                                                                       \
    ArenaScope scope(arena_);                                               \
    return finish_call((expr), detail);                                     \
  } while (false)

Status Session::compose_message_1(const MutableByteView out, std::size_t& length) noexcept {
  ROUTELOOM_EDHOC_CALL("edhoc message_1 compose",
                       edhoc_message_1_compose(native(), out.data, out.size, &length));
}
Status Session::process_message_1(const ByteView message) noexcept {
  ROUTELOOM_EDHOC_CALL("edhoc message_1 process",
                       edhoc_message_1_process(native(), message.data, message.size));
}
Status Session::compose_message_2(const MutableByteView out, std::size_t& length) noexcept {
  ROUTELOOM_EDHOC_CALL("edhoc message_2 compose",
                       edhoc_message_2_compose(native(), out.data, out.size, &length));
}
Status Session::process_message_2(const ByteView message) noexcept {
  ROUTELOOM_EDHOC_CALL("edhoc message_2 process",
                       edhoc_message_2_process(native(), message.data, message.size));
}
Status Session::compose_message_3(const MutableByteView out, std::size_t& length) noexcept {
  ROUTELOOM_EDHOC_CALL("edhoc message_3 compose",
                       edhoc_message_3_compose(native(), out.data, out.size, &length));
}
Status Session::process_message_3(const ByteView message) noexcept {
  ROUTELOOM_EDHOC_CALL("edhoc message_3 process",
                       edhoc_message_3_process(native(), message.data, message.size));
}
Status Session::compose_message_4(const MutableByteView out, std::size_t& length) noexcept {
  ROUTELOOM_EDHOC_CALL("edhoc message_4 compose",
                       edhoc_message_4_compose(native(), out.data, out.size, &length));
}
Status Session::process_message_4(const ByteView message) noexcept {
  ROUTELOOM_EDHOC_CALL("edhoc message_4 process",
                       edhoc_message_4_process(native(), message.data, message.size));
}

Status Session::compose_error(const std::int32_t code, const std::int32_t* suites,
                              const std::size_t suite_count, const MutableByteView out,
                              std::size_t& length) noexcept {
  std::array<std::int32_t, ROUTELOOM_EDHOC_SUITES_MAX> copy{};
  if (suite_count > copy.size() || (suite_count != 0 && suites == nullptr)) {
    return Status::error(StatusCode::InvalidArgument, "edhoc error suites");
  }
  std::copy(suites, suites + suite_count, copy.begin());
  edhoc_error_info info{};
  info.cipher_suites = copy.data();
  info.entries_size = copy.size();
  info.entries_length = suite_count;
  ROUTELOOM_EDHOC_CALL(
      "edhoc error compose",
      edhoc_message_error_compose(native(), out.data, out.size, &length,
                                  static_cast<edhoc_error_code>(code),
                                  suite_count != 0 ? &info : nullptr));
}

Status Session::process_error(const ByteView message, std::int32_t& code,
                              std::int32_t* suites, const std::size_t suites_capacity,
                              std::size_t& suite_count) noexcept {
  edhoc_error_code received = EDHOC_ERROR_CODE_SUCCESS;
  edhoc_error_info info{};
  info.cipher_suites = suites;
  info.entries_size = suites != nullptr ? suites_capacity : 0;
  suite_count = 0;
  if (!active_) {
    return Status::error(StatusCode::InvalidState, "edhoc session idle");
  }
  ArenaScope scope(arena_);
  const Status status = finish_call(
      edhoc_message_error_process(native(), message.data, message.size, &received,
                                  suites != nullptr ? &info : nullptr),
      "edhoc error process");
  code = static_cast<std::int32_t>(received);
  suite_count = info.entries_length;
  return status;
}

Status Session::exporter(const std::size_t label, const ByteView context,
                         const MutableByteView out) noexcept {
  ROUTELOOM_EDHOC_CALL("edhoc exporter",
                       edhoc_export_raw(native(), label, context.data, context.size,
                                        out.data, out.size));
}

Status Session::key_update(const ByteView context) noexcept {
  ROUTELOOM_EDHOC_CALL("edhoc key update",
                       edhoc_export_key_update(native(), context.data, context.size));
}

Status Session::oscore_context(const MutableByteView master_secret,
                               const MutableByteView master_salt,
                               const MutableByteView sender_id,
                               std::size_t& sender_id_length,
                               const MutableByteView recipient_id,
                               std::size_t& recipient_id_length) noexcept {
  ROUTELOOM_EDHOC_CALL(
      "edhoc oscore export",
      edhoc_export_oscore_context_raw(native(), master_secret.data, master_secret.size,
                                      master_salt.data, master_salt.size, sender_id.data,
                                      sender_id.size, &sender_id_length,
                                      recipient_id.data, recipient_id.size,
                                      &recipient_id_length));
}

#undef ROUTELOOM_EDHOC_CALL

}  // namespace routeloom::edhoc

// libedhoc custom memory backend (CONFIG_LIBEDHOC_MEM_BACKEND = 2). Outside a
// Session call there is no arena and every allocation fails.
extern "C" void* edhoc_mem_alloc(std::size_t size) {
  routeloom::edhoc::Arena* arena = routeloom::edhoc::g_current_arena;
  return arena != nullptr ? arena->allocate(size) : nullptr;
}

extern "C" void edhoc_mem_free(void* ptr) {
  routeloom::edhoc::Arena* arena = routeloom::edhoc::g_current_arena;
  if (arena != nullptr) {
    arena->release(ptr);
  }
}
