#pragma once

#include <array>
#include <cstddef>
#include <memory>
#include <new>
#include <utility>

namespace routeloom {

template <typename T, std::size_t Capacity>
class FixedQueue {
 public:
  static_assert(Capacity > 0, "FixedQueue capacity must be positive");

  bool push(const T& value) noexcept {
    if (size_ == Capacity) return false;
    items_[tail_] = value;
    tail_ = (tail_ + 1) % Capacity;
    ++size_;
    return true;
  }

  bool push(T&& value) noexcept {
    if (size_ == Capacity) return false;
    items_[tail_] = std::move(value);
    tail_ = (tail_ + 1) % Capacity;
    ++size_;
    return true;
  }

  bool pop(T& out) noexcept {
    if (size_ == 0) return false;
    out = std::move(items_[head_]);
    head_ = (head_ + 1) % Capacity;
    --size_;
    return true;
  }

  T* front() noexcept { return size_ == 0 ? nullptr : &items_[head_]; }
  const T* front() const noexcept { return size_ == 0 ? nullptr : &items_[head_]; }
  bool empty() const noexcept { return size_ == 0; }
  bool full() const noexcept { return size_ == Capacity; }
  std::size_t size() const noexcept { return size_; }
  constexpr std::size_t capacity() const noexcept { return Capacity; }

  void clear() noexcept {
    head_ = 0;
    tail_ = 0;
    size_ = 0;
  }

 private:
  std::array<T, Capacity> items_{};
  std::size_t head_{0};
  std::size_t tail_{0};
  std::size_t size_{0};
};

template <typename T, std::size_t Capacity>
class FixedPool {
 public:
  static_assert(Capacity > 0, "FixedPool capacity must be positive");

  template <typename Predicate>
  T* find(Predicate predicate) noexcept {
    for (std::size_t i = 0; i < Capacity; ++i) {
      if (used_[i] && predicate(items_[i])) return &items_[i];
    }
    return nullptr;
  }

  template <typename Predicate>
  const T* find(Predicate predicate) const noexcept {
    for (std::size_t i = 0; i < Capacity; ++i) {
      if (used_[i] && predicate(items_[i])) return &items_[i];
    }
    return nullptr;
  }

  T* allocate() noexcept {
    for (std::size_t i = 0; i < Capacity; ++i) {
      if (!used_[i]) {
        reset(items_[i]);
        used_[i] = true;
        return &items_[i];
      }
    }
    return nullptr;
  }

  bool release(T* item) noexcept {
    if (item == nullptr) return false;
    const auto begin = items_.data();
    const auto end = begin + Capacity;
    if (item < begin || item >= end) return false;
    const auto index = static_cast<std::size_t>(item - begin);
    if (!used_[index]) return false;
    used_[index] = false;
    reset(items_[index]);
    return true;
  }

  template <typename Fn>
  void for_each(Fn fn) noexcept {
    for (std::size_t i = 0; i < Capacity; ++i) {
      if (used_[i]) fn(items_[i]);
    }
  }

  template <typename Fn>
  void for_each(Fn fn) const noexcept {
    for (std::size_t i = 0; i < Capacity; ++i) {
      if (used_[i]) fn(items_[i]);
    }
  }

  std::size_t size() const noexcept {
    std::size_t count = 0;
    for (const bool value : used_) count += value ? 1U : 0U;
    return count;
  }

  void clear() noexcept {
    for (std::size_t i = 0; i < Capacity; ++i) {
      if (used_[i]) {
        used_[i] = false;
        reset(items_[i]);
      }
    }
  }

  constexpr std::size_t capacity() const noexcept { return Capacity; }

 private:
  // Reconstruct instead of assigning T{} so the pool also supports entries
  // containing non-assignable RAII members (for example CounterLease).
  static void reset(T& item) noexcept {
    item.~T();
    ::new (static_cast<void*>(std::addressof(item))) T();
  }

  std::array<T, Capacity> items_{};
  std::array<bool, Capacity> used_{};
};

}  // namespace routeloom
