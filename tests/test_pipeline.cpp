// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The block pipeline may read blocks concurrently, but the output must be in
// ascending block order regardless of completion order, and the number of
// blocks in flight must stay bounded by FetchOptions.
#include <atomic>
#include <chrono>
#include <sstream>
#include <string>
#include <thread>

#include "doctest/doctest.h"
#include "helpers.hpp"
#include "skipta/crypto.hpp"
#include "skipta/error.hpp"
#include "skipta/share.hpp"

using namespace skipta;

namespace {

struct ConcurrencyProbe {
  std::atomic<int> in_flight{0};
  std::atomic<int> peak{0};

  void enter() {
    const int now = ++in_flight;
    int observed = peak.load();
    while (now > observed && !peak.compare_exchange_weak(observed, now)) {
    }
  }
  void leave() { --in_flight; }
};

}  // namespace

TEST_CASE("concurrent block reads keep output in block order") {
  const std::uint64_t blocks = 12;
  const Entry entry = skiptest::synthetic_entry(blocks);
  ConcurrencyProbe probe;

  const BlockFetcher fetch = [&](std::uint64_t index) {
    probe.enter();
    std::this_thread::sleep_for(std::chrono::milliseconds(3));
    probe.leave();
    return skiptest::block_filled_with_index(index);
  };

  FetchOptions options;
  options.max_in_flight = 4;

  std::ostringstream sink;
  CHECK(fetch_blocks(entry, 0, kToEndOfFile, fetch, sink, options) == entry.size);
  CHECK(sink.str() == skiptest::expected_content(blocks));
  CHECK(probe.peak.load() >= 2);  // it really did work in parallel
  CHECK(probe.peak.load() <= 4);  // and never beyond the limit
}

TEST_CASE("blocks that finish in reverse still get written in order") {
  const std::uint64_t blocks = 8;
  const Entry entry = skiptest::synthetic_entry(blocks);

  // Block 0 is the slowest, block 7 the fastest: completion order is reversed.
  const BlockFetcher fetch = [&](std::uint64_t index) {
    std::this_thread::sleep_for(std::chrono::milliseconds(2 * static_cast<int>(blocks - index)));
    return skiptest::block_filled_with_index(index);
  };

  FetchOptions options;
  options.max_in_flight = 4;

  std::ostringstream sink;
  CHECK(fetch_blocks(entry, 0, kToEndOfFile, fetch, sink, options) == entry.size);
  CHECK(sink.str() == skiptest::expected_content(blocks));
}

TEST_CASE("a range across blocks stays ordered under concurrency") {
  const std::uint64_t blocks = 6;
  const Entry entry = skiptest::synthetic_entry(blocks);

  const BlockFetcher fetch = [&](std::uint64_t index) {
    std::this_thread::sleep_for(std::chrono::milliseconds(2 * static_cast<int>(blocks - index)));
    return skiptest::block_filled_with_index(index);
  };

  FetchOptions options;
  options.max_in_flight = 3;

  // Starts mid block 1 and ends mid block 3: three blocks, partial at both ends.
  const std::uint64_t offset = format::kBlockPlaintextSize + 100;
  const std::uint64_t length = 2 * format::kBlockPlaintextSize;
  std::ostringstream sink;
  CHECK(fetch_blocks(entry, offset, length, fetch, sink, options) == length);
  CHECK(sink.str() == skiptest::expected_content(blocks).substr(offset, length));
}

TEST_CASE("a small window bounds how many blocks exist at once") {
  const std::uint64_t blocks = 10;
  const Entry entry = skiptest::synthetic_entry(blocks);
  ConcurrencyProbe probe;

  const BlockFetcher fetch = [&](std::uint64_t index) {
    probe.enter();
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    probe.leave();
    return skiptest::block_filled_with_index(index);
  };

  FetchOptions options;
  options.max_in_flight = 2;
  std::ostringstream sink;
  CHECK(fetch_blocks(entry, 0, kToEndOfFile, fetch, sink, options) == entry.size);
  CHECK(sink.str() == skiptest::expected_content(blocks));
  CHECK(probe.peak.load() <= 2);
}

TEST_CASE("max_in_flight == 1 is strictly serial") {
  const std::uint64_t blocks = 6;
  const Entry entry = skiptest::synthetic_entry(blocks);
  ConcurrencyProbe probe;

  const BlockFetcher fetch = [&](std::uint64_t index) {
    probe.enter();
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    probe.leave();
    return skiptest::block_filled_with_index(index);
  };

  FetchOptions options;
  options.max_in_flight = 1;

  std::ostringstream sink;
  CHECK(fetch_blocks(entry, 0, kToEndOfFile, fetch, sink, options) == entry.size);
  CHECK(sink.str() == skiptest::expected_content(blocks));
  CHECK(probe.peak.load() == 1);
}

TEST_CASE("a failing block aborts the whole fetch with its error code") {
  const Entry entry = skiptest::synthetic_entry(10);

  const BlockFetcher fetch = [](std::uint64_t index) -> Bytes {
    if (index == 5) fail(ErrorCode::NotFound, "block 5 is missing");
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    return skiptest::block_filled_with_index(index);
  };

  FetchOptions options;
  options.max_in_flight = 4;

  std::ostringstream sink;
  CHECK(skiptest::code_of([&] {
          fetch_blocks(entry, 0, kToEndOfFile, fetch, sink, options);
        }) == ErrorCode::NotFound);
}

TEST_CASE("a block of the wrong length is refused rather than silently sliced") {
  const Entry entry = skiptest::synthetic_entry(4);
  const BlockFetcher short_blocks = [](std::uint64_t index) {
    const std::size_t length =
        index == 2 ? 10u : static_cast<std::size_t>(format::kBlockPlaintextSize);
    return Bytes(length, 0x7f);
  };
  FetchOptions options;
  options.max_in_flight = 2;
  std::ostringstream sink;
  CHECK(skiptest::code_of([&] {
          fetch_blocks(entry, 0, kToEndOfFile, short_blocks, sink, options);
        }) == ErrorCode::SizeMismatch);
}

TEST_CASE("nonsensical pipeline options are rejected") {
  const Entry entry = skiptest::synthetic_entry(2);
  const BlockFetcher fetch = [](std::uint64_t) { return Bytes(); };
  std::ostringstream sink;

  FetchOptions zero;
  zero.max_in_flight = 0;
  CHECK(skiptest::code_of([&] {
          fetch_blocks(entry, 0, kToEndOfFile, fetch, sink, zero);
        }) == ErrorCode::BadOptions);

  FetchOptions too_many;
  too_many.max_in_flight = 65;
  CHECK(skiptest::code_of([&] {
          fetch_blocks(entry, 0, kToEndOfFile, fetch, sink, too_many);
        }) == ErrorCode::BadOptions);
}
