#include "routeloom/signature_progress.hpp"

#include "routeloom/discovery_scope.hpp"
#include "routeloom/secure_clear.hpp"

namespace routeloom::sdkv1 {

Status SignatureProgress::reset() noexcept {
  if (pending()) return Status::error(StatusCode::Busy, "signature loan active");
  secure_clear(key_);
  secure_clear(digest_);
  secure_clear(signature_);
  secure_clear(identity_);
  results_ = {};
  result_count_ = 0;
  verified_ = false;
  waiting_ = false;
  return Status::success();
}

Status SignatureProgress::cancel() noexcept {
  progress_.cancel();
  if (pending()) {
    Status ignored{};
    if (!progress_.poll(ignored)) return Status::error(StatusCode::Busy, "signature cancelling");
  }
  return reset();
}

Status SignatureProgress::run(void* context) noexcept {
  auto& job = *static_cast<SignatureProgress*>(context);
  job.verified_ = job.backend_.verify_digest(job.key_, job.digest_, job.signature_);
  return Status::success();
}

Status SignatureProgress::progress_digest(const P256PublicKey& key, const Digest256& digest,
                                          const Es256Signature& signature,
                                          bool& verified) const noexcept {
  verified = false;
  if (cancelled()) return Status::error(StatusCode::Expired, "signature attempt cancelled");
  if (!progress_.asynchronous()) {
    verified = backend_.verify_digest(key, digest, signature);
    return Status::success();
  }
  Sha256 hash;
  hash.update(ByteView{key.data(), key.size()});
  hash.update(ByteView{digest.data(), digest.size()});
  hash.update(ByteView{signature.data(), signature.size()});
  Digest256 identity{};
  hash.finish(identity);
  for (std::size_t i = 0; i < result_count_; ++i) {
    if (results_[i].identity == identity) {
      verified = results_[i].verified;
      return Status::success();
    }
  }
  if (result_count_ == results_.size()) {
    return Status::error(StatusCode::NoCapacity, "signature attempt bound");
  }
  if (pending()) {
    if (identity != identity_) {
      waiting_ = true;
      return Status::error(StatusCode::Busy, "signature attempt changed");
    }
    Status result{};
    const Status returned = progress_.poll(result);
    if (!returned) {
      waiting_ = true;
      return returned;
    }
    if (!result) return result;
    verified = verified_;
    results_[result_count_++] = Result{identity, verified};
    return Status::success();
  }
  key_ = key;
  digest_ = digest;
  signature_ = signature;
  identity_ = identity;
  const Status submitted = progress_.start(const_cast<SignatureProgress*>(this), &run);
  waiting_ = submitted.code == StatusCode::WouldBlock || submitted.code == StatusCode::Busy;
  return submitted;
}

}  // namespace routeloom::sdkv1
