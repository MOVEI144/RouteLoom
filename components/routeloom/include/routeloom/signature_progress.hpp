#pragma once

#include "routeloom/crypto_progress.hpp"
#include "routeloom/rlcw1.hpp"

namespace routeloom::sdkv1 {

// A verification attempt can check a certificate chain and a signed object.
// Retain exact primitive results only during that attempt's Owner replay.
// reset() separates attempts; cancellation never releases a running job.
class SignatureProgress final : public Es256Verifier {
 public:
  explicit SignatureProgress(const Es256Verifier& backend = default_es256_verifier()) noexcept
      : backend_(backend) {}
  Status bind(CryptoWorker* worker) noexcept { return progress_.bind(worker); }
  Status reset() noexcept;
  Status cancel() noexcept;
  bool pending() const noexcept { return progress_.pending(); }
  bool verification_pending() const noexcept override { return pending() || waiting_; }
  bool cancelled() const noexcept { return progress_.pending() && progress_.cancelled(); }
  bool waiting() const noexcept { return waiting_; }
  bool ready() const noexcept { return progress_.ready(); }
  void resume() const noexcept { waiting_ = false; }
  bool verify_digest(const P256PublicKey& key, const Digest256& digest,
                     const Es256Signature& signature) const noexcept override {
    return !progress_.asynchronous() && backend_.verify_digest(key, digest, signature);
  }
  Status progress_digest(const P256PublicKey& key, const Digest256& digest,
                         const Es256Signature& signature, bool& verified) const noexcept override;

 private:
  static Status run(void* context) noexcept;
  struct Result {
    Digest256 identity{};
    bool verified{false};
  };
  const Es256Verifier& backend_;
  mutable CryptoProgress progress_{};
  mutable P256PublicKey key_{};
  mutable Digest256 digest_{};
  mutable Es256Signature signature_{};
  mutable Digest256 identity_{};
  // One retained join verifies SiteCert, MemberCert and its staged RRS1.
  mutable std::array<Result, 3> results_{};
  mutable std::size_t result_count_{0};
  mutable bool verified_{false};
  mutable bool waiting_{false};
};

}  // namespace routeloom::sdkv1
