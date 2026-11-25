// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Spike A harness (UNBUILT in the development environment; see README.md).
// Measures magnet -> metadata -> first payload bytes between two in-process
// libtorrent sessions on loopback, and prints one JSON object.
//
// Build: make            (requires libtorrent-rasterbar >= 2.0 and pkg-config)
// Run:   ./spike_a <seed-dir> [payload-MiB]
#include <libtorrent/alert_types.hpp>
#include <libtorrent/create_torrent.hpp>
#include <libtorrent/magnet_uri.hpp>
#include <libtorrent/session.hpp>
#include <libtorrent/torrent_info.hpp>
#include <libtorrent/version.hpp>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace lt = libtorrent;
namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;

namespace {

double ms_since(const Clock::time_point& start) {
  return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}

/// Deterministic filler so both runs hash the same payload.
void write_payload(const fs::path& path, std::size_t bytes) {
  std::ofstream out(path, std::ios::binary);
  std::vector<char> chunk(64 * 1024);
  for (std::size_t i = 0; i < chunk.size(); ++i) {
    chunk[i] = static_cast<char>((i * 31 + 7) & 0xff);
  }
  std::size_t written = 0;
  while (written < bytes) {
    const std::size_t n = std::min(chunk.size(), bytes - written);
    out.write(chunk.data(), static_cast<std::streamsize>(n));
    written += n;
  }
}

bool wait_for(const std::function<bool()>& condition, double timeout_ms) {
  const auto start = Clock::now();
  while (ms_since(start) < timeout_ms) {
    if (condition()) return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  return condition();
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::cerr << "usage: " << argv[0] << " <seed-dir> [payload-MiB]\n";
    return 2;
  }
  const fs::path seed_dir = argv[1];
  const std::size_t payload_mib = argc > 2 ? static_cast<std::size_t>(std::stoul(argv[2])) : 256;

  const auto process_start = Clock::now();
  std::error_code ec;
  fs::create_directories(seed_dir / "manifest", ec);
  fs::create_directories(seed_dir / "payload", ec);
  // 100-entry listing stand-in, ~4 KiB, like a medium directory manifest.
  {
    std::ofstream out(seed_dir / "manifest" / "root.bin", std::ios::binary);
    std::string line;
    for (int i = 0; i < 100; ++i) {
      line += "entry-" + std::to_string(i) + "-00000000000000000000000000000000\n";
    }
    out << line;
  }
  write_payload(seed_dir / "payload" / "large.bin", payload_mib * 1024 * 1024);

  try {
    // ---- create and seed -------------------------------------------------
    lt::file_storage files;
    if (!lt::add_files(files, seed_dir.string())) {
      std::cerr << "cannot add files from " << seed_dir << "\n";
      return 1;
    }
    lt::create_torrent creator(files);
    lt::set_piece_hashes(creator, seed_dir.string());
    creator.set_priv(true);  // G6: private torrent, no DHT, tracker-only
    creator.set_creator("skipta-spike-a");

    const fs::path torrent_path = seed_dir / "spike.torrent";
    {
      const std::vector<char> buffer = creator.generate_buf();
      std::ofstream out(torrent_path, std::ios::binary);
      out.write(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    }

    lt::session_params params;
    params.settings.set_int(lt::settings_pack::alert_mask,
                            lt::alert_category::status | lt::alert_category::error);
    lt::session seeder(params);

    lt::add_torrent_params seed_atp;
    seed_atp.ti = std::make_shared<lt::torrent_info>(torrent_path.string());
    seed_atp.save_path = seed_dir.string();
    seed_atp.seed_mode = true;
    lt::torrent_handle seed_handle = seeder.add_torrent(seed_atp);
    wait_for([&] { return seed_handle.status().is_seeding; }, 5000.0);

    const double session_start_ms = ms_since(process_start);
    const std::string magnet = lt::make_magnet_uri(*seed_atp.ti);

    // ---- reader session --------------------------------------------------
    lt::session leecher(params);
    lt::add_torrent_params read_atp = lt::parse_magnet_uri(magnet);
    read_atp.save_path = (seed_dir / "download").string();
    fs::create_directories(read_atp.save_path, ec);

    const auto magnet_time = Clock::now();
    lt::torrent_handle read_handle = leecher.add_torrent(read_atp);

    const bool got_metadata =
        wait_for([&] { return read_handle.status().has_metadata; }, 20000.0);
    const double metadata_ms = got_metadata ? ms_since(magnet_time) : -1.0;

    const bool got_bytes =
        wait_for([&] { return read_handle.status().total_done > 0; }, 20000.0);
    const double first_bytes_ms = got_bytes ? ms_since(magnet_time) : -1.0;

    // Short throughput window after the first block.
    const auto window_start = Clock::now();
    const std::int64_t before = read_handle.status().total_done;
    std::this_thread::sleep_for(std::chrono::seconds(5));
    const std::int64_t after = read_handle.status().total_done;
    const double seconds =
        std::chrono::duration<double>(Clock::now() - window_start).count();
    const double kib_per_s = seconds > 0 ? (after - before) / 1024.0 / seconds : 0.0;

    const double progress =
        read_atp.ti ? 100.0 * static_cast<double>(after) /
                          static_cast<double>(read_atp.ti->total_size())
                    : 0.0;

    std::printf(
        "{\"libtorrent\":\"%s\",\"payload_mib\":%zu,\"session_start_ms\":%.1f,"
        "\"metadata_ms\":%.1f,\"first_bytes_ms\":%.1f,\"throughput_kib_s\":%.1f,"
        "\"percent_done\":%.1f,\"private_torrent\":true,\"loopback\":true}\n",
        lt::version(), payload_mib, session_start_ms, metadata_ms, first_bytes_ms,
        kib_per_s, progress);
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "spike failed: " << e.what() << "\n";
    return 1;
  }
}
