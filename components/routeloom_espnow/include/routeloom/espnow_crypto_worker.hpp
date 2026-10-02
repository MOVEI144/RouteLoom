#pragma once

#include "routeloom/crypto_worker.hpp"

namespace routeloom::espnow {

// Boot-lifetime, statically allocated task and mailbox. nullptr on task
// creation failure; firmware must fail closed rather than run P-256 on Owner.
CryptoWorker* start_crypto_worker(CryptoWorker::Wake completion = nullptr,
                                  void* completion_context = nullptr) noexcept;

}  // namespace routeloom::espnow
