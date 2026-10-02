#pragma once

#include "routeloom/crypto_worker.hpp"

namespace routeloom::espnow {

// Call from the Owner task; the boot-lifetime task matches its priority.
// nullptr while an earlier loan remains or on task creation failure;
// firmware must fail closed rather than run P-256 on Owner.
CryptoWorker* start_crypto_worker(CryptoWorker::Wake completion = nullptr,
                                  void* completion_context = nullptr) noexcept;

// Detach before destroying the registered context, after draining its loan.
// Completion callbacks must only notify; they run under a critical section.
void detach_crypto_worker(void* completion_context) noexcept;

}  // namespace routeloom::espnow
