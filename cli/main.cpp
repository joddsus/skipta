// SPDX-License-Identifier: AGPL-3.0-or-later
//
// skipta - publish a folder as one encrypted drive and browse it from a link.
// Phase 3: blobs live in a local store that stands in for the swarm.
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#if !defined(_WIN32)
#include <termios.h>
#include <unistd.h>
#endif

#include "skipta/bytes.hpp"
#include "skipta/crypto.hpp"
#include "skipta/download.hpp"
#include "skipta/error.hpp"
#include "skipta/gc.hpp"
#include "skipta/http.hpp"
#include "skipta/identity.hpp"
#include "skipta/link.hpp"
#include "skipta/share.hpp"

namespace fs = std::filesystem;
using namespace skipta;

namespace {

struct UsageError : std::runtime_error {
  using std::runtime_error::runtime_error;
};

const char* kUsage =
    "skipta - share a folder, encrypted\n"
    "\n"
    "usage:\n"
    "  skipta publish <dir> [--store <dir>]\n"
    "  skipta passwd <dir> [--store <dir>]\n"
    "  skipta list <link> [path] [--store <dir>]\n"
    "  skipta get <link> <path> [--out <file|->|--out <dir>] [--range START:END]\n"
    "             [--in-flight N] [--resume] [--force] [--store <dir>]\n"
    "  skipta verify <link> [path] [--in-flight N] [--store <dir>]\n"
    "  skipta gc [--delete] [--store <dir>]\n"
    "  skipta serve [--store <dir>] [--listen <host:port>]\n"
    "\n"
    "  <path> may be a file, a directory, or \".\" for the whole share. A directory\n"
    "  is downloaded recursively, file by file, in published order; --resume\n"
    "  continues each interrupted file. A whole-share download needs --out.\n"
    "\n"
    "  --range START:END   half-open byte range; END may be omitted (to end of file).\n"
    "                      Only the blocks overlapping the range are read. A range\n"
    "                      needs a file, not a directory.\n"
    "  --in-flight N       blocks fetched at the same time (default 4; 1 = serial).\n"
    "  --resume            continue a partial download using <out>.skipta-resume,\n"
    "                      after verifying the bytes already on disk; a complete\n"
    "                      file is left untouched.\n"
    "  --force             overwrite an existing file and discard its resume state\n"
    "                      (cannot be combined with --resume).\n"
    "\n"
    "  Use -- after the options to pass a <dir> or <path> that begins with '-':\n"
    "  skipta get <link> --store <dir> --out <file> -- -name\n"
    "\n"
    "  publish needs a passphrase for the local drive identity. It reads\n"
    "  $SKIPTA_PASSPHRASE when set, otherwise asks on a terminal with echo off\n"
    "  (twice when setting one up). The identity file is encrypted with it, so a\n"
    "  stolen store cannot reveal the drive key or the signing seed. list, get and\n"
    "  verify need only the link. Losing the passphrase means the drive can never\n"
    "  be updated again, by anyone.\n"
    "\n"
    "  passwd re-encrypts that identity under a new passphrase. The current one\n"
    "  comes from $SKIPTA_PASSPHRASE or a prompt; the new one from\n"
    "  $SKIPTA_NEW_PASSPHRASE or two prompts. Only the identity file is rewritten:\n"
    "  the drive key, signing seed, seq, link and published files stay exactly as\n"
    "  they are. The old passphrase stops working and cannot be recovered. A\n"
    "  missing identity is an error; a legacy plaintext one must be migrated by\n"
    "  publishing once first.\n"
    "\n"
    "  exit codes: 0 ok, 1 error, 2 usage, 3 wrong passphrase,\n"
    "              4 missing passphrase without a terminal, 5 unusable identity file\n"
    "\n"
    "  gc removes store objects that no current root pointer reaches: superseded\n"
    "  versions and the ciphertext of files removed from a folder, which is still\n"
    "  decryptable with the link. It reports first and deletes only with --delete.\n"
    "  It needs one passphrase that opens every identity in the store, and refuses\n"
    "  without deleting if any drive has no identity or no pointer: what it cannot\n"
    "  account for it keeps. Run it when nothing is downloading. publish and gc\n"
    "  lock the store, so a second one fails with StoreBusy instead of racing.\n"
    "\n"
    "  verify decrypts and authenticates every manifest and every block below the\n"
    "  path (the whole share by default) and checks every file against its\n"
    "  published size. It writes nothing and reports ok or the first failure; use\n"
    "  it on a store you copied from somewhere else.\n"
    "\n"
    "  A read store may be an http:// origin instead of a directory: list, get\n"
    "  and verify fetch missing objects from it and cache them locally (--cache,\n"
    "  $SKIPTA_CACHE, else ./skipta-cache). serve publishes a store read-only over\n"
    "  HTTP; it serves only sealed pointers, manifests and blocks, never keys or\n"
    "  plaintext. Plain HTTP is not confidential: object names, sizes and timing\n"
    "  are visible on the network. Use it on a trusted LAN, over a VPN, or behind\n"
    "  a TLS tunnel; --listen defaults to 127.0.0.1.\n"
    "\n"
    "The store is a local blob directory standing in for the swarm; publish and\n"
    "read use the same one. Default: $SKIPTA_STORE, else ./skipta-store.\n"
    "Each published folder gets a drive identity under <store>/identities, so\n"
    "publishing the same folder again keeps the link and advances the pointer's\n"
    "seq; readers remember that seq and refuse an older pointer.\n"
    "\n"
    "A link is a key: anyone who receives it can read the share.\n";

std::uint64_t parse_u64(const std::string& text, const char* what);

struct Args {
  std::string command;
  std::vector<std::string> positional;
  std::string store;
  std::string out;
  std::string range;
  std::size_t in_flight = FetchOptions{}.max_in_flight;
  std::string listen;
  std::string cache;
  bool has_range = false;
  bool resume = false;
  bool force = false;
  bool gc_delete = false;
};

Args parse_args(int argc, char** argv) {
  Args args;
  bool end_of_options = false;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (end_of_options) {
      if (args.command.empty()) {
        args.command = arg;
      } else {
        args.positional.push_back(arg);
      }
      continue;
    }
    if (arg == "--") {
      end_of_options = true;
      continue;
    }
    if (arg == "--help" || arg == "-h") {
      std::cout << kUsage;
      std::exit(0);
    }
    if (arg == "--store") {
      if (++i >= argc) throw UsageError("--store needs a directory");
      args.store = argv[i];
    } else if (arg == "--out" || arg == "-o") {
      if (++i >= argc) throw UsageError("--out needs a file name");
      args.out = argv[i];
    } else if (arg == "--range") {
      if (++i >= argc) throw UsageError("--range needs START:END");
      args.range = argv[i];
      args.has_range = true;
    } else if (arg == "--listen") {
      if (++i >= argc) throw UsageError("--listen needs [host:]port");
      args.listen = argv[i];
    } else if (arg == "--cache") {
      if (++i >= argc) throw UsageError("--cache needs a directory");
      args.cache = argv[i];
    } else if (arg == "--in-flight") {
      if (++i >= argc) throw UsageError("--in-flight needs a number");
      args.in_flight = static_cast<std::size_t>(parse_u64(argv[i], "--in-flight"));
    } else if (arg == "--resume") {
      args.resume = true;
    } else if (arg == "--force") {
      args.force = true;
    } else if (arg == "--delete") {
      args.gc_delete = true;
    } else if (!arg.empty() && arg.front() == '-') {
      throw UsageError("unknown option: " + arg);
    } else if (args.command.empty()) {
      args.command = arg;
    } else {
      args.positional.push_back(arg);
    }
  }
  return args;
}

std::string store_arg(const Args& args) {
  if (!args.store.empty()) return args.store;
  if (const char* env = std::getenv("SKIPTA_STORE"); env != nullptr && *env != '\0') {
    return env;
  }
  return "skipta-store";
}

/// A store this command writes to must be a local directory. Publishing to a
/// remote origin would mean trusting it with new ciphertext and granting it
/// write access to the drive; that is not part of this transport.
FileStore local_store(const Args& args) {
  const std::string text = store_arg(args);
  if (!args.cache.empty()) throw UsageError("--cache only applies to an http:// store");
  if (looks_like_store_url(text) || text.find("://") != std::string::npos) {
    fail(ErrorCode::BadOptions,
         "this command needs a local store directory, not " + text);
  }
  return FileStore(fs::path(text));
}

/// A read store is either a local directory or an http:// origin with a local
/// cache for fetched objects and the accepted-seq rollback guard.
FileStore read_store(const Args& args) {
  const std::string text = store_arg(args);
  if (!looks_like_store_url(text)) {
    if (text.find("://") != std::string::npos) {
      fail(ErrorCode::BadOptions, "only http:// stores are supported: " + text);
    }
    if (!args.cache.empty()) throw UsageError("--cache only applies to an http:// store");
    return FileStore(fs::path(text));
  }
  std::string cache = args.cache;
  if (cache.empty()) {
    if (const char* env = std::getenv("SKIPTA_CACHE"); env != nullptr && *env != '\0') {
      cache = env;
    } else {
      cache = "skipta-cache";
    }
  }
  if (looks_like_store_url(cache)) throw UsageError("--cache must be a local directory");
  return FileStore(fs::path(cache), text);
}

/// Opens a share, refusing a pointer older than the one this store accepted
/// last time, and records the seq it accepted now.
ShareSession open_session(const FileStore& store, const std::string& link_text) {
  const ShareLink link = decode_link(link_text);
  const ShareSession session =
      open_share(store, link_text, accepted_pointer_seq(store, link.drive));
  remember_pointer_seq(store, session.link.drive, session.pointer.seq);
  return session;
}

std::uint64_t parse_u64(const std::string& text, const char* what) {
  if (text.empty()) throw UsageError(std::string(what) + " is empty");
  for (char c : text) {
    if (c < '0' || c > '9') throw UsageError(std::string(what) + " is not a number: " + text);
  }
  try {
    return std::stoull(text);
  } catch (const std::exception&) {
    throw UsageError(std::string(what) + " is out of range: " + text);
  }
}

/// Parses "START:END" (END exclusive, may be empty) into offset and length.
void parse_range(const std::string& spec, std::uint64_t* offset, std::uint64_t* length) {
  const std::size_t colon = spec.find(':');
  if (colon == std::string::npos) {
    throw UsageError("--range must be START:END (END exclusive, may be omitted)");
  }
  *offset = parse_u64(spec.substr(0, colon), "--range start");
  *length = kToEndOfFile;
  const std::string end_text = spec.substr(colon + 1);
  if (!end_text.empty()) {
    const std::uint64_t end = parse_u64(end_text, "--range end");
    if (end <= *offset) throw UsageError("--range end must be greater than start");
    *length = end - *offset;
  }
}

/// Parses "[v6addr]:port", "host:port" or just "port". A bare port binds to
/// loopback; sharing on a LAN needs an explicit wildcard address.
void parse_listen(const std::string& text, std::string* host, std::uint16_t* port) {
  std::string host_text = "127.0.0.1";
  std::string port_text = text;
  if (!text.empty() && text.front() == '[') {
    const std::size_t close = text.find(']');
    if (close == std::string::npos || close + 1 >= text.size() || text[close + 1] != ':') {
      throw UsageError("--listen must be [IPv6]:PORT");
    }
    host_text = text.substr(1, close - 1);
    port_text = text.substr(close + 2);
  } else {
    const std::size_t colon = text.rfind(':');
    if (colon != std::string::npos) {
      if (text.find(':') != colon) throw UsageError("bracket an IPv6 --listen address");
      host_text = text.substr(0, colon);
      port_text = text.substr(colon + 1);
    }
  }
  if (host_text.empty()) throw UsageError("--listen has an empty host");
  const std::uint64_t value = parse_u64(port_text, "--listen port");
  if (value == 0 || value > 65535) throw UsageError("--listen port must be 1..65535");
  *host = host_text;
  *port = static_cast<std::uint16_t>(value);
}

std::string short_hex(ByteView bytes, std::size_t count) {
  const std::string full = hex_encode(bytes);
  return full.substr(0, std::min(full.size(), count * 2));
}

/// Holds a passphrase for one publish and wipes it on the way out. Copies are
/// deleted on purpose: there is exactly one owner of the bytes.
class Passphrase {
 public:
  Passphrase() = default;
  Passphrase(const Passphrase&) = delete;
  Passphrase& operator=(const Passphrase&) = delete;
  Passphrase(Passphrase&&) = default;
  Passphrase& operator=(Passphrase&&) = delete;
  ~Passphrase() { wipe(); }

  std::string& value() noexcept { return value_; }
  std::string_view view() const noexcept { return value_; }

 private:
  void wipe() noexcept {
    if (!value_.empty()) crypto::wipe(value_.data(), value_.size());
    value_.clear();
  }

  std::string value_;
};

bool stdin_is_terminal() {
#if !defined(_WIN32)
  return ::isatty(STDIN_FILENO) != 0;
#else
  return false;
#endif
}

/// Reads one line with terminal echo disabled. The echo setting is restored
/// before returning, including when reading fails.
std::string read_hidden_line(const char* prompt) {
  std::cerr << prompt << std::flush;
  std::string line;
#if !defined(_WIN32)
  struct termios original {};
  bool hidden = false;
  if (::tcgetattr(STDIN_FILENO, &original) == 0) {
    struct termios changed = original;
    changed.c_lflag &= ~static_cast<tcflag_t>(ECHO);
    // TCSANOW, not TCSAFLUSH: typed-ahead input must not be discarded.
    hidden = ::tcsetattr(STDIN_FILENO, TCSANOW, &changed) == 0;
  }
  const bool got = static_cast<bool>(std::getline(std::cin, line));
  if (hidden) ::tcsetattr(STDIN_FILENO, TCSANOW, &original);
  std::cerr << "\n";
#else
  // No echo control here; selling a terminal prompt on Windows is future work.
  const bool got = static_cast<bool>(std::getline(std::cin, line));
#endif
  if (!got) {
    fail(ErrorCode::MissingPassphrase, "no passphrase was read from the terminal");
  }
  return line;
}

/// A passphrase comes from `env_name` or, only on a terminal, from a prompt.
/// With neither available the command refuses instead of guessing: an empty or
/// default passphrase would silently protect nothing.
Passphrase acquire_passphrase_from(const char* env_name, const std::string& label, bool confirm) {
  Passphrase passphrase;
  if (const char* env = std::getenv(env_name); env != nullptr && *env != '\0') {
    passphrase.value() = env;
    return passphrase;
  }
  if (!stdin_is_terminal()) {
    fail(ErrorCode::MissingPassphrase, std::string("no ") + label + ": set " + env_name +
                                           " or run this command from a terminal");
  }
  passphrase.value() = read_hidden_line((label + ": ").c_str());
  if (passphrase.view().empty()) {
    fail(ErrorCode::BadPassphrase, "passphrase must not be empty");
  }
  if (confirm) {
    Passphrase repeated;
    repeated.value() = read_hidden_line(("repeat " + label + ": ").c_str());
    if (!constant_time_equal(ByteView(passphrase.view()), ByteView(repeated.view()))) {
      throw UsageError("passphrases do not match; nothing was written");
    }
  }
  return passphrase;
}

/// The identity's current passphrase: $SKIPTA_PASSPHRASE or one prompt.
Passphrase acquire_passphrase(bool confirm) {
  return acquire_passphrase_from("SKIPTA_PASSPHRASE", "passphrase", confirm);
}

/// The replacement passphrase: $SKIPTA_NEW_PASSPHRASE or two prompts. It is a
/// separate variable so a script can supply both without an argument that would
/// show in the process list; arguments never carry a passphrase.
Passphrase acquire_new_passphrase() {
  return acquire_passphrase_from("SKIPTA_NEW_PASSPHRASE", "new passphrase", true);
}

int do_publish(const Args& args) {
  if (args.positional.size() != 1) throw UsageError("publish needs exactly one directory");
  if (!args.listen.empty()) throw UsageError("--listen only applies to serve");
  FileStore store = local_store(args);
  const fs::path source = args.positional[0];

  // One drive per published folder: the second run updates the same link.
  const IdentityStore identities(store.root() / "identities");
  const IdentityFormat format = identities.format(source);
  // A wrapped identity only has to be unlocked. A new drive and a legacy
  // plaintext identity are setting a passphrase for the first time, so an
  // interactive prompt asks twice: a typo there would leave a drive nobody can
  // ever update again.
  Passphrase passphrase = acquire_passphrase(format != IdentityFormat::Wrapped);
  std::optional<DriveIdentity> stored;
  if (format != IdentityFormat::Missing) stored = identities.load(source, passphrase.view());
  const bool is_new = !stored.has_value();
  if (is_new) stored = DriveIdentity::create();

  const Drive drive(stored->drive_key, stored->signing);
  PublishOptions options;
  options.identity = &drive;
  options.seq = stored->seq + 1;
  const PublishResult result = publish_directory(source, store, options);

  stored->seq = result.seq;
  const fs::path identity_path = identities.path_for(source);
  identities.save(source, *stored, passphrase.view());

  std::cout << result.link << "\n";
  std::cerr << "published " << result.files << " files, " << result.directories
            << " directories, " << result.bytes << " bytes\n"
            << "drive  " << short_hex(ByteView(result.drive), 8) << "...\n"
            << (is_new ? "new drive, seq " : "updated drive, seq ") << result.seq << "\n";
  if (!is_new) {
    std::cerr << "the link is unchanged; older pointers are now stale\n";
  }
  std::cerr << "store  " << fs::absolute(store.root()).string() << "\n"
            << "identity " << fs::absolute(identity_path).string()
            << " (passphrase-wrapped; keep the store private)\n";
  if (format == IdentityFormat::Plaintext) {
    std::cerr << "migrated the plaintext identity to a passphrase-wrapped file; "
                 "the old plaintext seed is gone\n";
  }
  std::cerr << "note: the passphrase cannot be recovered; without it this drive can "
               "never be updated again\n";
  for (const std::string& skipped : result.skipped) {
    std::cerr << "skipped " << skipped << "\n";
  }
  std::cerr << "note: the link below is a bearer secret - anyone with it can read the share\n";
  return 0;
}

int do_passwd(const Args& args) {
  if (args.positional.size() != 1) throw UsageError("passwd needs exactly one directory");
  if (args.has_range || args.resume || args.force || !args.out.empty()) {
    throw UsageError("passwd takes no --out, --range, --resume or --force");
  }
  if (!args.listen.empty()) throw UsageError("--listen only applies to serve");
  const FileStore store = local_store(args);
  const fs::path source = args.positional[0];
  const IdentityStore identities(store.root() / "identities");

  // Decide what is on disk before asking for anything: there is nothing to
  // change without a wrapped identity, and a legacy file belongs to publish.
  const IdentityFormat format = identities.format(source);
  if (format == IdentityFormat::Missing) {
    fail(ErrorCode::NotFound, "no drive identity for " + source.string() + " in " +
                                  fs::absolute(identities.dir()).string() +
                                  "; publish the folder first");
  }
  if (format == IdentityFormat::Plaintext) {
    fail(ErrorCode::UnsupportedIdentity,
         "the identity for " + source.string() +
             " is a legacy plaintext file; publish the folder once to migrate it, then passwd");
  }

  Passphrase current = acquire_passphrase(false);
  Passphrase replacement = acquire_new_passphrase();
  // This unwraps with the current passphrase and only then writes; a wrong one
  // stops here with exit 3 and leaves the file byte-for-byte as it was.
  identities.rewrap(source, current.view(), replacement.view());

  std::cerr << "identity " << fs::absolute(identities.path_for(source)).string()
            << " re-wrapped with the new passphrase\n"
            << "the drive key, signing seed, seq, link and published files are unchanged\n"
            << "note: the old passphrase no longer opens this identity and cannot be "
               "recovered\n";
  return 0;
}

int do_gc(const Args& args) {
  if (!args.positional.empty()) throw UsageError("gc takes no path; it covers the whole store");
  if (args.has_range || args.resume || args.force || !args.out.empty()) {
    throw UsageError("gc takes no --out, --range, --resume or --force");
  }
  if (!args.listen.empty()) throw UsageError("--listen only applies to serve");
  const FileStore store = local_store(args);
  const IdentityStore identities(store.root() / "identities");
  const std::vector<fs::path> files = identities.files();
  if (files.empty() && store.pointer_drives().empty()) {
    std::cerr << "gc: nothing is published in " << fs::absolute(store.root()).string()
              << "; nothing to collect\n";
    return 0;
  }

  // Every drive has to be walkable, so a store whose identities use different
  // passphrases cannot be collected with this command. It refuses instead of
  // guessing which objects belong to the drives it could not open.
  std::vector<DriveIdentity> drives;
  drives.reserve(files.size());
  if (!files.empty()) {
    Passphrase passphrase = acquire_passphrase(false);
    for (const fs::path& file : files) {
      try {
        drives.push_back(identities.load_file(file, passphrase.view()));
      } catch (const Error& e) {
        if (e.code() == ErrorCode::BadPassphrase) {
          fail(ErrorCode::BadPassphrase,
               "identity " + file.string() + " does not open with this passphrase: gc needs " +
                   "one passphrase that opens every identity in the store (" + e.what() + ")");
        }
        throw;
      }
    }
  }

  const GcResult result = collect_garbage(store, drives, args.gc_delete);
  std::cerr << "gc: " << result.drives << " drive" << (result.drives == 1 ? "" : "s") << ", "
            << result.reachable_manifests << " manifests and " << result.reachable_files
            << " file block sets reachable\n"
            << "    " << result.removable_manifests << " manifests and "
            << result.removable_blocks << " blocks (" << result.removable_bytes
            << " bytes) unreachable\n";
  if (args.gc_delete) {
    std::cerr << "    removed " << result.removed_manifests << " manifests and "
              << result.removed_blocks << " blocks (" << result.removed_bytes << " bytes)\n";
  } else {
    std::cerr << "    nothing deleted; pass --delete to remove them\n";
  }
  if (result.ignored != 0) {
    std::cerr << "    kept " << result.ignored
              << " entries that are not store objects (links, temp files, unknown names)\n";
  }
  return 0;
}

int do_list(const Args& args) {
  if (args.positional.empty() || args.positional.size() > 2) {
    throw UsageError("list needs a link and an optional path");
  }
  if (!args.listen.empty()) throw UsageError("--listen only applies to serve");
  const FileStore store = read_store(args);
  const ShareSession session = open_session(store, args.positional[0]);
  // "." names the share root, as it does for get and verify.
  const std::string path = args.positional.size() == 2 && args.positional[1] != "."
                               ? args.positional[1]
                               : std::string();
  const std::vector<Entry> entries = list_path(store, session, path);

  std::printf("drive %s... seq %llu\n", short_hex(ByteView(session.pointer.drive), 8).c_str(),
              static_cast<unsigned long long>(session.pointer.seq));
  for (const Entry& entry : entries) {
    if (entry.kind == EntryKind::File) {
      std::printf("file  %10llu  %s\n", static_cast<unsigned long long>(entry.size),
                  entry.name.c_str());
    } else {
      std::printf("dir   %10s  %s/\n", "-", entry.name.c_str());
    }
  }
  std::printf("%zu entr%s\n", entries.size(), entries.size() == 1 ? "y" : "ies");
  return 0;
}

int do_get_directory(const FileStore& store, const ShareSession& session, const Args& args,
                     const std::string& share_path) {
  if (args.has_range) throw UsageError("--range needs a file, not a directory");
  const std::string out = args.out.empty() && !share_path.empty()
                              ? fs::path(share_path).filename().string()
                              : args.out;
  if (out.empty()) throw UsageError("downloading the whole share needs --out <dir>");
  if (out == "-") throw UsageError("a directory cannot be written to stdout");
  std::error_code ec;
  if (fs::exists(out, ec) && !fs::is_directory(out, ec)) {
    throw UsageError(out + " is not a directory");
  }

  FetchOptions fetch;
  fetch.max_in_flight = args.in_flight;

  DirectoryOptions options;
  options.file.resume = args.resume;
  options.file.overwrite = args.force;
  options.file.fetch = fetch;
  options.on_file = [](const DirectoryProgress& file) {
    if (file.skipped) {
      std::cerr << "kept     " << file.path << " (" << file.size << " bytes, complete)\n";
    } else if (file.reused > 0) {
      std::cerr << "resumed  " << file.path << " after " << file.reused << " of " << file.size
                << " bytes\n";
    } else {
      std::cerr << "wrote    " << file.path << " (" << file.written << " bytes)\n";
    }
  };
  const DirectoryOutcome outcome = download_directory(store, session, share_path, out, options);
  std::cerr << "downloaded " << outcome.files << " files and " << outcome.directories
            << " directories into " << out << ": " << outcome.written_now << " bytes written, "
            << outcome.reused << " kept, " << outcome.skipped << " already complete\n";
  return 0;
}

int do_verify(const Args& args) {
  if (args.positional.empty() || args.positional.size() > 2) {
    throw UsageError("verify needs a link and an optional path");
  }
  if (args.has_range || args.resume || args.force || !args.out.empty()) {
    throw UsageError("verify takes no --out, --range, --resume or --force");
  }

  if (!args.listen.empty()) throw UsageError("--listen only applies to serve");
  const FileStore store = read_store(args);
  const ShareSession session = open_session(store, args.positional[0]);
  const std::string path = args.positional.size() == 2 && args.positional[1] != "."
                               ? args.positional[1]
                               : std::string();

  FetchOptions fetch;
  fetch.max_in_flight = args.in_flight;
  const VerifyResult result = verify_path(store, session, path, fetch);
  std::cerr << "verified " << result.files << " files, " << result.directories
            << " directories, " << result.blocks << " blocks, " << result.bytes
            << " bytes (every manifest and block authenticated)\n";
  return 0;
}

int do_get(const Args& args) {
  if (args.positional.size() != 2) throw UsageError("get needs a link and a path");
  if (!args.listen.empty()) throw UsageError("--listen only applies to serve");
  const FileStore store = read_store(args);
  const ShareSession session = open_session(store, args.positional[0]);

  // "." (or "") means the share root, which has no name of its own.
  const std::string share_path = args.positional[1] == "." ? std::string() : args.positional[1];
  if (share_path.empty()) return do_get_directory(store, session, args, share_path);

  const std::optional<Entry> entry = resolve_path(store, session, share_path);
  if (!entry) fail(ErrorCode::NotFound, "'" + args.positional[1] + "' is not in the share");
  if (entry->kind == EntryKind::Directory) {
    return do_get_directory(store, session, args, share_path);
  }

  std::uint64_t offset = 0;
  std::uint64_t length = kToEndOfFile;
  if (args.has_range) parse_range(args.range, &offset, &length);
  if (offset > entry->size) {
    fail(ErrorCode::BadRange,
         "offset " + std::to_string(offset) + " is past the end of '" + entry->name +
             "' (" + std::to_string(entry->size) + " bytes)");
  }

  const std::string out =
      args.out.empty() ? fs::path(args.positional[1]).filename().string() : args.out;
  if (args.resume && args.has_range) {
    throw UsageError("--resume cannot be combined with --range");
  }
  if (args.resume && out == "-") {
    throw UsageError("--resume needs a real file, not stdout");
  }

  FetchOptions options;
  options.max_in_flight = args.in_flight;

  if (out == "-") {
    const std::uint64_t written =
        fetch_file_range(store, session, *entry, offset, length, std::cout, options);
    if (args.has_range) {
      std::cerr << "wrote " << written << " bytes (range " << offset << ".." << offset + written
                << " of " << entry->size << ") to stdout\n";
    } else {
      std::cerr << "wrote " << written << " bytes to stdout\n";
    }
    return 0;
  }
  if (args.has_range) {
    const std::uint64_t written = download_file_range(store, session, *entry, offset, length, out,
                                                      args.force, options);
    std::cerr << "wrote " << written << " bytes (range " << offset << ".." << offset + written
              << " of " << entry->size << ") to " << out << "\n";
    return 0;
  }
  if (!args.resume && !args.force && fs::exists(out)) {
    throw UsageError(out + " already exists; pass --resume to continue it or --force to "
                            "overwrite");
  }

  DownloadOptions download;
  download.resume = args.resume;
  download.overwrite = args.force;
  download.fetch = options;
  const DownloadOutcome outcome = download_file(store, session, *entry, out, download);
  if (outcome.skipped) {
    std::cerr << out << " is already complete (" << outcome.file_size
              << " bytes); nothing fetched\n";
    return 0;
  }
  if (outcome.reused > 0) {
    std::cerr << "resumed after " << outcome.reused << " of " << outcome.file_size
              << " bytes\n";
  }
  std::cerr << "wrote " << outcome.written_now << " bytes to " << out << " ("
            << outcome.file_size << " bytes total)\n";
  return 0;
}

int do_serve(const Args& args) {
  if (!args.positional.empty()) {
    throw UsageError("serve takes no path; name the store with --store");
  }
  if (args.has_range || args.resume || args.force || args.gc_delete || !args.out.empty()) {
    throw UsageError("serve takes no --out, --range, --resume, --force or --delete");
  }
  const FileStore store = local_store(args);
  std::string host = "127.0.0.1";
  std::uint16_t port = 8787;
  if (!args.listen.empty()) parse_listen(args.listen, &host, &port);

  HttpServer server({store.root(), host, port});
  std::cerr << "serving " << fs::absolute(store.root()).string() << " read-only at "
            << server.origin() << "\n"
            << "only sealed pointers, manifests and blocks are served: no keys, no plaintext\n";
  if (host == "0.0.0.0" || host == "::") {
    std::cerr << "warning: listening on every interface. Plain HTTP reveals object names, sizes\n"
                 "         and timing to the network; use a trusted LAN, a VPN or a TLS tunnel.\n";
  } else {
    std::cerr << "reachable from this machine only; pass --listen 0.0.0.0:" << port
              << " to share on a LAN\n";
  }
  if (host == "0.0.0.0" || host == "::") {
    std::cerr << "readers: skipta list \"<link>\" --store http://<this-machine>:" << port
              << " --cache ./skipta-cache\n";
  } else {
    std::cerr << "readers: skipta list \"<link>\" --store " << server.origin()
              << " --cache ./skipta-cache\n";
  }
  server.run();
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    const Args args = parse_args(argc, argv);
    if (args.command.empty()) {
      std::cout << kUsage;
      return 2;
    }
    if (args.gc_delete && args.command != "gc") {
      throw UsageError("--delete only applies to gc");
    }
    if (args.resume && args.force) {
      throw UsageError("--resume and --force contradict each other: pick one");
    }
    if (args.command == "publish") return do_publish(args);
    if (args.command == "passwd") return do_passwd(args);
    if (args.command == "gc") return do_gc(args);
    if (args.command == "list") return do_list(args);
    if (args.command == "get") return do_get(args);
    if (args.command == "verify") return do_verify(args);
    if (args.command == "serve") return do_serve(args);
    throw UsageError("unknown command: " + args.command);
  } catch (const UsageError& e) {
    std::cerr << "skipta: " << e.what() << "\n\n" << kUsage;
    return 2;
  } catch (const Error& e) {
    std::cerr << "skipta: " << e.what() << " [" << error_code_name(e.code()) << "]\n";
    switch (e.code()) {
      case ErrorCode::BadPassphrase: return 3;
      case ErrorCode::MissingPassphrase: return 4;
      case ErrorCode::UnsupportedIdentity: return 5;
      default: return 1;
    }
  } catch (const std::exception& e) {
    std::cerr << "skipta: " << e.what() << "\n";
    return 1;
  }
}
