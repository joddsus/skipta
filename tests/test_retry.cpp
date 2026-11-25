// SPDX-License-Identifier: AGPL-3.0-or-later
//
// A transient store error on one block must not abort the download: the block is
// retried with backoff inside its own pipeline slot, so output order and the
// resume checkpoints are unaffected. Permanent errors are not retried.
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <sstream>
#include <string>

#include "doctest/doctest.h"
#include "helpers.hpp"
#include "skipta/error.hpp"
#include "skipta/format.hpp"
#include "skipta/share.hpp"

using namespace skipta;

namespace {

Entry file_entry(std::uint64_t size) {
  Entry entry;
  entry.kind = EntryKind::File;
  entry.name = "payload.bin";
  entry.size = size;
  entry.file_id = skiptest::filled_id(0x21);
  return entry;
}

Bytes block_of(const Bytes& whole, std::uint64_t size, std::uint64_t index) {
  const std::size_t start = static_cast<std::size_t>(index * format::kBlockPlaintextSize);
  const std::size_t len = format::plaintext_block_len(size, index);
  return Bytes(whole.begin() + static_cast<std::ptrdiff_t>(start),
               whole.begin() + static_cast<std::ptrdiff_t>(start + len));
}

}  // namespace

TEST_CASE("a block that fails twice is fetched on the third attempt") {
  constexpr std::uint64_t kSize = 150000;  // 3 blocks: two full and a short tail
  const Entry entry = file_entry(kSize);
  const Bytes whole = skiptest::pattern(kSize, 9);

  // Block fetches run on separate threads, so the counters are atomic: a plain
  // map would be a data race even when only one block misbehaves.
  std::array<std::atomic<int>, 3> attempts{};
  const auto fetch = [&](std::uint64_t index) {
    const int attempt = ++attempts[static_cast<std::size_t>(index)];
    // The middle block fails transiently twice, then succeeds.
    if (index == 1 && attempt <= 2) fail(ErrorCode::StoreIo, "transient store error");
    return block_of(whole, kSize, index);
  };

  FetchOptions options;
  options.backoff = std::chrono::microseconds{0};  // no waiting in this test

  std::ostringstream out;
  const std::uint64_t written = fetch_blocks(entry, 0, kToEndOfFile, fetch, out, options);

  CHECK(written == kSize);
  CHECK(out.str() == to_string(ByteView(whole)));  // still in block order
  CHECK(attempts[0].load() == 1);
  CHECK(attempts[1].load() == 3);  // two failures plus the successful attempt
  CHECK(attempts[2].load() == 1);
}

TEST_CASE("retries are bounded and only transient errors are retried") {
  constexpr std::uint64_t kSize = 100000;  // 2 blocks
  const Entry entry = file_entry(kSize);
  const Bytes whole = skiptest::pattern(kSize, 4);

  SUBCASE("a block that never arrives fails after max_attempts") {
    std::array<std::atomic<int>, 2> attempts{};
    const auto fetch = [&](std::uint64_t index) -> Bytes {
      ++attempts[static_cast<std::size_t>(index)];
      if (index == 0) fail(ErrorCode::NotFound, "block is gone");
      return block_of(whole, kSize, index);
    };
    FetchOptions options;
    options.max_attempts = 2;
    options.backoff = std::chrono::microseconds{0};
    std::ostringstream out;
    CHECK(skiptest::code_of([&] { fetch_blocks(entry, 0, kToEndOfFile, fetch, out, options); }) ==
          ErrorCode::NotFound);
    CHECK(attempts[0].load() == 2);  // bounded, not endless
  }

  SUBCASE("a wrong tag is not retried") {
    std::array<std::atomic<int>, 2> attempts{};
    const auto fetch = [&](std::uint64_t index) -> Bytes {
      ++attempts[static_cast<std::size_t>(index)];
      if (index == 0) fail(ErrorCode::AuthFailed, "block does not authenticate");
      return block_of(whole, kSize, index);
    };
    FetchOptions options;
    options.max_attempts = 5;  // plenty, but this error cannot heal
    options.backoff = std::chrono::microseconds{0};
    std::ostringstream out;
    CHECK(skiptest::code_of([&] { fetch_blocks(entry, 0, kToEndOfFile, fetch, out, options); }) ==
          ErrorCode::AuthFailed);
    CHECK(attempts[0].load() == 1);
  }

  SUBCASE("max_attempts = 1 disables retrying") {
    int calls = 0;
    const auto fetch = [&](std::uint64_t) -> Bytes {
      ++calls;
      fail(ErrorCode::StoreIo, "no retries allowed");
    };
    FetchOptions options;
    options.max_attempts = 1;
    options.backoff = std::chrono::microseconds{0};
    std::ostringstream out;
    CHECK(skiptest::code_of([&] { fetch_blocks(entry, 0, 100, fetch, out, options); }) ==
          ErrorCode::StoreIo);
    CHECK(calls == 1);
  }
}

TEST_CASE("backoff waits between attempts") {
  constexpr std::uint64_t kSize = 100000;
  const Entry entry = file_entry(kSize);
  const Bytes whole = skiptest::pattern(kSize, 2);

  int attempts = 0;
  const auto fetch = [&](std::uint64_t index) {
    if (index == 0) {
      ++attempts;
      if (attempts <= 2) fail(ErrorCode::StoreIo, "flaky store");
    }
    return block_of(whole, kSize, index);
  };

  FetchOptions options;
  options.backoff = std::chrono::microseconds{2000};  // 2 ms, then 4 ms

  std::ostringstream out;
  const auto start = std::chrono::steady_clock::now();
  const std::uint64_t written = fetch_blocks(entry, 0, kToEndOfFile, fetch, out, options);
  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - start)
                           .count();

  CHECK(written == kSize);
  CHECK(attempts == 3);
  CHECK(out.str() == to_string(ByteView(whole)));
  CHECK(elapsed >= 6);  // two waits: 2 ms and 4 ms
}

TEST_CASE("retry options are validated") {
  const Entry entry = file_entry(10);
  const auto fetch = [](std::uint64_t) { return Bytes(10, 0x5a); };
  std::ostringstream out;

  FetchOptions options;
  options.max_attempts = 0;
  CHECK(skiptest::code_of([&] { fetch_blocks(entry, 0, kToEndOfFile, fetch, out, options); }) ==
        ErrorCode::BadOptions);

  options.max_attempts = 11;
  CHECK(skiptest::code_of([&] { fetch_blocks(entry, 0, kToEndOfFile, fetch, out, options); }) ==
        ErrorCode::BadOptions);

  options.max_attempts = 3;
  options.backoff = std::chrono::microseconds{-1};
  CHECK(skiptest::code_of([&] { fetch_blocks(entry, 0, kToEndOfFile, fetch, out, options); }) ==
        ErrorCode::BadOptions);

  options.backoff = std::chrono::seconds{61};
  CHECK(skiptest::code_of([&] { fetch_blocks(entry, 0, kToEndOfFile, fetch, out, options); }) ==
        ErrorCode::BadOptions);

  options.backoff = std::chrono::microseconds{0};
  options.max_attempts = 1;
  CHECK(fetch_blocks(entry, 0, kToEndOfFile, fetch, out, options) == 10);
}
