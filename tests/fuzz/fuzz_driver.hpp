#pragma once

// Shared libFuzzer harness plumbing for the RouteLoom parser fuzzers.
//
// Each fuzz_<target>.cpp defines:
//
//   extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);
//   ROUTELOOM_FUZZ_MAIN()
//
// Two build modes:
//   * libFuzzer build (-fsanitize=fuzzer, clang): __has_feature(fuzzer) is
//     true, libFuzzer supplies main() and drives LLVMFuzzerTestOneInput with
//     coverage guidance. ROUTELOOM_FUZZ_MAIN() expands to nothing.
//   * Replay build (default, any compiler incl. gcc): ROUTELOOM_FUZZ_MAIN()
//     emits a dependency-free main() that replays corpus files/directories
//     and optionally runs a deterministic seeded mutation loop:
//       fuzz_x corpus_dir [file...]            # replay each input once
//       fuzz_x corpus_dir -runs=N -seed=S      # corpus replay + N mutations
//     This is what ctest invokes, so the corpus is regression-tested on
//     every platform, not only where libFuzzer exists.
//
// Dependency-free by design: <filesystem>/<fstream> only, no test framework,
// no clang-only assumptions (the __has_feature probe is itself guarded).

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#if defined(__has_feature)
#  if __has_feature(fuzzer)
#    define ROUTELOOM_HAS_LIBFUZZER 1
#  endif
#endif

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size);

#ifndef ROUTELOOM_HAS_LIBFUZZER

namespace routeloom_fuzz {

// xorshift64 — deterministic, identical results on every platform/compiler.
struct Rng {
  std::uint64_t state;
  std::uint64_t next() noexcept {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return state;
  }
  std::size_t below(std::size_t bound) noexcept {
    return bound == 0 ? 0 : static_cast<std::size_t>(next() % bound);
  }
};

inline bool read_file(const std::filesystem::path& path,
                      std::vector<std::uint8_t>& out) {
  std::ifstream file(path, std::ios::binary);
  if (!file) return false;
  file.seekg(0, std::ios::end);
  const auto len = file.tellg();
  if (len < 0) return false;
  file.seekg(0, std::ios::beg);
  out.resize(static_cast<std::size_t>(len));
  if (len > 0) {
    file.read(reinterpret_cast<char*>(out.data()), len);
    if (!file) return false;
  }
  return true;
}

inline void collect_inputs(const std::filesystem::path& path,
                           std::vector<std::vector<std::uint8_t>>& out) {
  std::error_code ec;
  if (std::filesystem::is_directory(path, ec)) {
    std::vector<std::filesystem::path> entries;
    for (const auto& entry :
         std::filesystem::directory_iterator(path, ec)) {
      if (entry.is_regular_file(ec)) entries.push_back(entry.path());
    }
    std::sort(entries.begin(), entries.end());  // deterministic order
    for (const auto& entry : entries) {
      std::vector<std::uint8_t> bytes;
      if (read_file(entry, bytes)) out.push_back(std::move(bytes));
    }
    return;
  }
  std::vector<std::uint8_t> bytes;
  if (read_file(path, bytes)) out.push_back(std::move(bytes));
}

// One mutation step: bit flip / byte set / truncate / extend / splice a
// corpus chunk. Bounded by max_len.
inline void mutate(std::vector<std::uint8_t>& buf,
                   const std::vector<std::vector<std::uint8_t>>& corpus,
                   Rng& rng, std::size_t max_len) {
  const std::size_t ops = 1 + rng.below(4);
  for (std::size_t i = 0; i < ops; ++i) {
    switch (rng.below(6)) {
      case 0:  // bit flip
        if (!buf.empty()) buf[rng.below(buf.size())] ^= static_cast<std::uint8_t>(1u << rng.below(8));
        break;
      case 1:  // random byte set
        if (!buf.empty()) buf[rng.below(buf.size())] = static_cast<std::uint8_t>(rng.next());
        break;
      case 2:  // truncate
        if (!buf.empty()) buf.resize(rng.below(buf.size() + 1));
        break;
      case 3: {  // append random bytes
        const std::size_t add = rng.below(17);
        for (std::size_t j = 0; j < add && buf.size() < max_len; ++j) {
          buf.push_back(static_cast<std::uint8_t>(rng.next()));
        }
        break;
      }
      case 4: {  // splice in a slice of a corpus entry
        if (corpus.empty()) break;
        const auto& donor = corpus[rng.below(corpus.size())];
        if (donor.empty() || buf.size() >= max_len) break;
        const std::size_t off = rng.below(donor.size());
        const std::size_t len = rng.below(donor.size() - off + 1);
        const std::size_t at = buf.empty() ? 0 : rng.below(buf.size() + 1);
        const std::size_t room = max_len - buf.size();
        const std::size_t take = std::min(len, room);
        buf.insert(buf.begin() + static_cast<std::ptrdiff_t>(at),
                   donor.begin() + static_cast<std::ptrdiff_t>(off),
                   donor.begin() + static_cast<std::ptrdiff_t>(off + take));
        break;
      }
      default: {  // delete a slice
        if (buf.size() < 2) break;
        const std::size_t off = rng.below(buf.size());
        const std::size_t len = rng.below(buf.size() - off + 1);
        buf.erase(buf.begin() + static_cast<std::ptrdiff_t>(off),
                  buf.begin() + static_cast<std::ptrdiff_t>(off + len));
        break;
      }
    }
  }
  if (buf.size() > max_len) buf.resize(max_len);
}

inline int replay_main(int argc, char** argv) {
  std::uint64_t runs = 0;
  std::uint64_t seed = 0x524c4f4f4dull;  // "RLOOM"
  std::size_t max_len = 4096;
  std::vector<std::vector<std::uint8_t>> corpus;
  std::vector<std::string> paths;

  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    const auto flag = [&arg](const char* name) -> bool {
      const std::size_t n = std::strlen(name);
      return arg.size() > n && arg.compare(0, n, name) == 0 && arg[n] == '=';
    };
    if (flag("-runs")) {
      runs = std::strtoull(arg.c_str() + 6, nullptr, 10);
    } else if (flag("-seed")) {
      seed = std::strtoull(arg.c_str() + 6, nullptr, 10);
    } else if (flag("-max_len")) {
      max_len = static_cast<std::size_t>(
          std::strtoull(arg.c_str() + 9, nullptr, 10));
    } else if (flag("-max_total_time") || flag("-timeout") ||
               flag("-rss_limit_mb") || flag("-print_final_stats")) {
      // Accepted and ignored so one ctest command line works for both the
      // libFuzzer binary and this replay driver.
    } else if (!arg.empty() && arg[0] == '-') {
      std::fprintf(stderr, "fuzz replay: ignoring flag %s\n", arg.c_str());
    } else {
      paths.push_back(arg);
    }
  }
  for (const auto& path : paths) {
    collect_inputs(std::filesystem::path(path), corpus);
  }

  std::size_t executed = 0;
  for (const auto& input : corpus) {
    LLVMFuzzerTestOneInput(input.data(), input.size());
    ++executed;
  }

  // Deterministic mutation pass for -runs=N: cheap coverage without a real
  // fuzzer — the corpus is mutated by a fixed-seed xorshift stream, so the
  // same N runs produce the same inputs on every platform.
  if (runs > 0) {
    Rng rng{seed ? seed : 0x9e3779b97f4a7c15ull};
    std::vector<std::uint8_t> scratch;
    for (std::uint64_t i = 0; i < runs; ++i) {
      if (corpus.empty()) {
        scratch.assign(1, static_cast<std::uint8_t>(rng.next()));
        mutate(scratch, corpus, rng, max_len);
      } else {
        scratch = corpus[rng.below(corpus.size())];
        mutate(scratch, corpus, rng, max_len);
      }
      LLVMFuzzerTestOneInput(scratch.data(), scratch.size());
      ++executed;
    }
  }
  std::fprintf(stderr, "fuzz replay: %zu corpus + %llu mutated inputs, all clean\n",
               executed - (runs > 0 ? static_cast<std::size_t>(runs) : 0),
               static_cast<unsigned long long>(runs));
  return 0;
}

}  // namespace routeloom_fuzz

#  define ROUTELOOM_FUZZ_MAIN()                                        \
    int main(int argc, char** argv) {                                  \
      return routeloom_fuzz::replay_main(argc, argv);                  \
    }

#else  // ROUTELOOM_HAS_LIBFUZZER — libFuzzer supplies main().

#  define ROUTELOOM_FUZZ_MAIN()

#endif
