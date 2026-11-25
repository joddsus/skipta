// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <sstream>
#include <string>

#include "skipta/bytes.hpp"
#include "skipta/crypto.hpp"
#include "skipta/error.hpp"
#include "skipta/format.hpp"
#include "skipta/manifest.hpp"

namespace skiptest {

/// Runs fn and returns the error code it threw, or -1 if it did not throw.
template <typename Fn>
skipta::ErrorCode code_of(Fn fn) {
  try {
    fn();
  } catch (const skipta::Error& e) {
    return e.code();
  }
  return static_cast<skipta::ErrorCode>(-1);
}

inline skipta::Id128 filled_id(unsigned char value) {
  skipta::Id128 id{};
  id.fill(value);
  return id;
}

inline skipta::Key32 filled_key(unsigned char value) {
  skipta::Key32 key{};
  key.fill(value);
  return key;
}

template <std::size_t N>
std::array<unsigned char, N> filled(unsigned char value) {
  std::array<unsigned char, N> out{};
  out.fill(value);
  return out;
}

inline skipta::Bytes pattern(std::size_t n, unsigned char start = 0) {
  skipta::Bytes out(n);
  for (std::size_t i = 0; i < n; ++i) {
    out[i] = static_cast<unsigned char>((start + i) & 0xff);
  }
  return out;
}

/// A file entry of exactly `blocks` full blocks, for pipeline tests.
inline skipta::Entry synthetic_entry(std::uint64_t blocks) {
  skipta::Entry entry;
  entry.kind = skipta::EntryKind::File;
  entry.name = "synthetic.bin";
  entry.file_id = skipta::crypto::random_id();
  entry.size = blocks * skipta::format::kBlockPlaintextSize;
  return entry;
}

/// Block content encodes the block index, so any reordering corrupts output.
inline skipta::Bytes block_filled_with_index(std::uint64_t index) {
  return skipta::Bytes(skipta::format::kBlockPlaintextSize,
                       static_cast<unsigned char>(0x41 + (index % 26)));
}

/// Scratch directory, removed when it goes out of scope.
class TempDir {
 public:
  explicit TempDir(const std::string& tag) {
    const skipta::Id128 id = skipta::crypto::random_id();
    path_ = std::filesystem::temp_directory_path() /
            ("skipta-" + tag + "-" + skipta::hex_encode(skipta::ByteView(id)).substr(0, 12));
    std::filesystem::create_directories(path_);
  }
  ~TempDir() {
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
  }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;

  const std::filesystem::path& path() const { return path_; }

 private:
  std::filesystem::path path_;
};

inline void write_text(const std::filesystem::path& path, const std::string& text) {
  std::filesystem::create_directories(path.parent_path());
  std::ofstream out(path, std::ios::binary);
  out.write(text.data(), static_cast<std::streamsize>(text.size()));
}

inline void write_pattern(const std::filesystem::path& path, std::size_t size,
                          unsigned char start) {
  std::filesystem::create_directories(path.parent_path());
  const skipta::Bytes data = pattern(size, start);
  std::ofstream out(path, std::ios::binary);
  out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

inline std::string read_all(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  std::ostringstream buffer;
  buffer << in.rdbuf();
  return buffer.str();
}

inline std::string block_name(std::uint64_t index) {
  std::string name = std::to_string(index);
  if (name.size() < 16) name.insert(0, 16 - name.size(), '0');
  return name + ".blk";
}

inline std::string expected_content(std::uint64_t blocks) {
  std::string expected;
  expected.reserve(static_cast<std::size_t>(blocks) * skipta::format::kBlockPlaintextSize);
  for (std::uint64_t i = 0; i < blocks; ++i) {
    expected.append(skipta::format::kBlockPlaintextSize,
                    static_cast<char>(0x41 + (i % 26)));
  }
  return expected;
}

}  // namespace skiptest
