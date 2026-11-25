# Platform support and real-hardware validation

This page records exactly what was built and run in this VM, and what remains
for physical hardware. A platform is **verified** only when the full native test
suite ran there. A cross-build proves compile/link/header/ABI work, not runtime
behavior.

All builds were from clean source copies on 2026-11-24, with zig 0.13.0,
FreeBSD 14.5 `base.txz`, Ubuntu LLD 18.1.3, and Ubuntu Wine 10 for the Windows
runtime attempt.

## Executed build matrix

| Target | Literal project build command | Build result | Was a binary run? |
|---|---|---|---|
| Linux x86_64 glibc | `make clean && make` | **succeeded**, 0 warnings; ELF x86-64 | **yes, native:** `make test` = 128/2274; `make vectors` stable |
| Linux aarch64 glibc | `make -j"$(nproc)" CXX='/tmp/zig/zig c++ -target aarch64-linux-gnu' AR='/tmp/zig/zig ar' DEPS=/tmp/deps-arm64 all` | **succeeded**; ELF aarch64 | **not run** (no native aarch64 loader in this VM) |
| Linux aarch64 musl static | `make -j"$(nproc)" CXX='/tmp/zig/zig c++ -target aarch64-linux-musl -static' AR='/tmp/zig/zig ar' DEPS=/tmp/deps-arm64-musl3 all` | **succeeded**, 0 warnings; static ELF aarch64 | **yes, QEMU 8.2.2:** 128/2274; vector SHA-256 identical |
| Linux armv7 musl static | `make -j"$(nproc)" CXX='/tmp/zig/zig c++ -target arm-linux-musleabihf -static' AR='/tmp/zig/zig ar' DEPS=/tmp/deps-armv7 all` | **succeeded after the test fix below**, 0 warnings; static ELF ARM EABI5 | **yes, QEMU 8.2.2:** 128/2274; vector SHA-256 identical |
| macOS 13+ x86_64 | `make -j"$(nproc)" CXX='/tmp/zig/zig c++ -target x86_64-macos' AR='/tmp/zig/zig ar --format=darwin' DEPS=/tmp/deps-mac all` | **succeeded**, 0 warnings; Mach-O x86-64 | **not run** (no macOS host) |
| macOS 13+ arm64 | `make -j"$(nproc)" CXX='/tmp/zig/zig c++ -target aarch64-macos' AR='/tmp/zig/zig ar --format=darwin' DEPS=/tmp/deps-macarm all` | **succeeded**, 0 warnings; Mach-O arm64 | **not run** (no macOS host) |
| FreeBSD 14.5 | `FBSD_SYSROOT=/tmp/freebsd-base FBSD_LLD=/tmp/llvm/usr/lib/llvm-18/bin/ld.lld FBSD_LLD_LIBDIR=/tmp/llvm/usr/lib/x86_64-linux-gnu:/tmp/llvm/usr/lib/llvm-18/lib make -j"$(nproc)" CXX='/tmp/zig/zig c++ -target x86_64-freebsd -nostdinc++ -I/tmp/freebsd-base/usr/include/c++/v1 -I/tmp/freebsd-base/usr/include' AR='/tmp/zig/zig ar' LINKER=./scripts/freebsd-link.sh DEPS=/tmp/deps-fbsd THREAD_FLAGS=-pthread all` | **succeeded**; ELF FreeBSD 14.5 | **not run** (no FreeBSD host) |
| Windows 10/11 x86_64 MinGW-w64 (zig GNU ABI) | `make -j"$(nproc)" CXX='/tmp/zig/zig c++ -target x86_64-windows-gnu' AR='/tmp/zig/zig ar' DEPS=/tmp/deps-win THREAD_FLAGS= EXTRA_LIBS=-lbcrypt all` | **succeeded**, 0 warnings; PE32+ x86-64 | **not run:** Wine prefix creation exited 139 before the test binary could run |
| OpenBSD | `printf '#include <assert.h>\n#include <inttypes.h>\nint main(void){return 0;}\n' \| /tmp/zig/zig c++ -target x86_64-openbsd -x c++ -c - -o /tmp/openbsd.o` | **failed:** `fatal error: 'assert.h' file not found` | **not run** (no binary) |
| NetBSD | `printf '#include <assert.h>\n#include <inttypes.h>\nint main(void){return 0;}\n' \| /tmp/zig/zig c++ -target x86_64-netbsd -x c++ -c - -o /tmp/netbsd.o` | **failed:** `fatal error: 'assert.h' file not found` | **not run** (no binary) |
| Haiku R1 | `printf '#include <assert.h>\n#include <inttypes.h>\nint main(void){return 0;}\n' \| /tmp/zig/zig c++ -target x86_64-haiku -x c++ -c - -o /tmp/haiku.o` | **failed:** `fatal error: 'assert.h' file not found` | **not run** (no binary) |

`make vectors` ran on the host and under both QEMU targets. All three generated
the same SHA-256:

```text
3d2eb50cece2e177698238a478abc0c49da52c8a35a450ab96cae08e7a375030
```

The Windows build is local-store only: `serve` and `http://` URLs are rejected
with a clear runtime error, the terminal passphrase prompt is not implemented
(use `SKIPTA_PASSPHRASE`), and concurrent `publish`/`gc` are not protected
because `StoreLock` is a no-op. It has not been run natively or under Wine.

MSVC is not an intended target: there is no Visual Studio project, and the
build/dependency scripts are POSIX shell plus GNU make.

## Working directories and exact run commands

### Host / Linux x86_64

```sh
./scripts/fetch-deps.sh
make clean && make
make test
make vectors
```

Result: 0 warnings; 128 test cases / 2274 assertions passed; vector file
byte-identical. The same tree also passed ASan/UBSan (128/2274) and TSan
(128/2274) after the ARMv7 test fix.

### Linux ARMv7

The final ARMv7 build and run were replayed from the clean copy at
`/tmp/final-armv7`:

```sh
make -j"$(nproc)" CXX='/tmp/zig/zig c++ -target arm-linux-musleabihf -static' \
     AR='/tmp/zig/zig ar' DEPS=/tmp/deps-armv7 all

/tmp/qemu/usr/bin/qemu-arm-static ./build/run_tests
/tmp/qemu/usr/bin/qemu-arm-static ./build/gen_vectors /tmp/armv7-vectors.json
sha256sum /tmp/armv7-vectors.json testvectors/format-v1.json
```

Result:

```text
[doctest] test cases:  128 |  128 passed | 0 failed | 0 skipped
[doctest] assertions: 2274 | 2274 passed | 0 failed |
3d2eb50cece2e177698238a478abc0c49da52c8a35a450ab96cae08e7a375030  /tmp/armv7-vectors.json
3d2eb50cece2e177698238a478abc0c49da52c8a35a450ab96cae08e7a375030  testvectors/format-v1.json
```

The first ARMv7 compile exposed the 32-bit `size_t` test bug described below;
after fixing it, the rebuild had zero warnings and the QEMU run passed.

### Linux ARM64

The glibc artifact was built but cannot run without an ARM64 loader. The static
musl artifact was built and executed under QEMU 8.2.2 from the clean copy at
`/tmp/final-arm64-musl3`:

```sh
make -j"$(nproc)" CXX='/tmp/zig/zig c++ -target aarch64-linux-musl -static' \
     AR='/tmp/zig/zig ar' DEPS=/tmp/deps-arm64-musl3 all

/tmp/qemu/usr/bin/qemu-aarch64-static ./build/run_tests
/tmp/qemu/usr/bin/qemu-aarch64-static ./build/gen_vectors /tmp/arm64-vectors.json
sha256sum /tmp/arm64-vectors.json testvectors/format-v1.json
```

Both QEMU tests reported 128/2274 and the vector hash above. This is
emulation, not ARM hardware.

### macOS

libsodium was built for each architecture, then its archive was rewritten in
Darwin format because GNU `ar` output is not accepted by Apple's linker:

```sh
find . -name '*.o' -exec sh -c \
  'file "$1" | grep -q "Mach-O" && printf "%s\0" "$1"' sh {} + \
  | xargs -0 zig ar --format=darwin rcs deps/lib/libsodium.a

make -j"$(nproc)" CXX='zig c++ -target x86_64-macos' \
     AR='zig ar --format=darwin' DEPS="$PWD/deps-mac" all

make -j"$(nproc)" CXX='zig c++ -target aarch64-macos' \
     AR='zig ar --format=darwin' DEPS="$PWD/deps-macarm" all
```

Both builds produced Mach-O CLI, test and vector binaries with 0 project
warnings. Neither binary was run.

### FreeBSD 14.5

FreeBSD has no bundled libc in zig 0.13. libsodium was compiled directly with
the FreeBSD headers:

```sh
find src/libsodium -name '*.c' -print0 | while IFS= read -r -d '' f; do
  o="obj/$(echo "$f" | tr / _).o"
  zig cc -target x86_64-freebsd \
    -D__FreeBSD_version=1405000 -DHAVE_SYS_RANDOM_H=1 \
    -I"$FBSD_SYSROOT/usr/include" \
    -Isrc/libsodium/include -Isrc/libsodium/include/sodium \
    -O2 -fPIC -c "$f" -o "$o"
done
zig ar rcs deps-fbsd/lib/libsodium.a obj/*.o
cp -a src/libsodium/include/. deps-fbsd/include/
```

The project was then compiled with FreeBSD's libc++ headers and linked through
the Makefile hook and `scripts/freebsd-link.sh`:

```sh
FBSD_SYSROOT=/tmp/freebsd-base \
FBSD_LLD=/tmp/llvm/usr/lib/llvm-18/bin/ld.lld \
FBSD_LLD_LIBDIR=/tmp/llvm/usr/lib/x86_64-linux-gnu:/tmp/llvm/usr/lib/llvm-18/lib \
make -j"$(nproc)" CXX='/tmp/zig/zig c++ -target x86_64-freebsd -nostdinc++ \
  -I/tmp/freebsd-base/usr/include/c++/v1 \
  -I/tmp/freebsd-base/usr/include' \
  AR='/tmp/zig/zig ar' LINKER=./scripts/freebsd-link.sh \
  DEPS="$PWD/deps-fbsd" THREAD_FLAGS=-pthread all
```

Result: FreeBSD 14.5 ELF CLI, test and vector binaries. They were not run.
FreeBSD system headers emit `-Wnullability-extension` warnings under zig's
Clang; those are not project-code warnings.

### Windows

```sh
make -j"$(nproc)" CXX='/tmp/zig/zig c++ -target x86_64-windows-gnu' \
     AR='/tmp/zig/zig ar' DEPS="$PWD/deps-win" \
     THREAD_FLAGS= EXTRA_LIBS=-lbcrypt all
```

Result: `PE32+ executable (console) x86-64` for `skipta`, `run_tests` and
`gen_vectors`; 0 project warnings.

Execution was attempted with the extracted Ubuntu Wine 10:

```sh
WINEPREFIX=/tmp/skipta-wine \
/tmp/wine/usr/lib/x86_64-linux-gnu/wine/wine wineboot -u
```

Wine exited with status **139** after printing
`wine: created the configuration directory ...` followed by
`Segmentation fault`. Supplying `l_intl.nls` from the Wine source did not
change the prefix crash. No Windows test result exists.

### OpenBSD, NetBSD, Haiku

These targets fail before any project source is compiled because zig 0.13 has
no matching libc/sysroot. The literal probe used for each was:

```sh
printf '#include <assert.h>\n#include <inttypes.h>\nint main(void){return 0;}\n' \
  | zig c++ -target x86_64-openbsd -x c++ -c - -o /tmp/openbsd.o
```

with the same command for `x86_64-netbsd` and `x86_64-haiku`. Each exits 1
with:

```text
fatal error: 'assert.h' file not found
```

No compiler/sysroot for these systems is installed in this VM.

## Bugs fixed during this pass

- **32-bit portability bug in `tests/test_keywrap.cpp`:** on ARMv7,
  `std::size_t` is 32-bit, so
  `absurd.memlimit = 4ull * 1024 * 1024 * 1024` truncated to 0 and no longer
  tested an over-limit value. It now uses
  `std::numeric_limits<std::size_t>::max()`. ARMv7 then built with 0 warnings
  and passed all tests.
- **Sanitizer link regression in the Makefile:** routing CLI/vector links
  through `LINKER` initially dropped `CXXFLAGS`, so sanitizer builds linked
  without `-fsanitize`. `CXXFLAGS` is now passed to every link.
- `Makefile` hard-coded GNU `ar` and had no linker/extra-library hooks. It now
  honors `AR`, `LINKER`, `LDFLAGS` and `EXTRA_LIBS`; FreeBSD uses those hooks.
- musl defines `makedev` as a macro, so `::makedev` in the attack test was not
  valid C++ (glibc/FreeBSD accepted it because it is a function). The test now
  uses the portable unqualified form.
- The POSIX-only permission helpers in `tests/test_attacks.cpp` are now behind
  `!_WIN32`, removing Windows unused-function warnings.
- macOS/BSD `SIGPIPE`: sockets set `SO_NOSIGPIPE` where available, and a zero
  byte `send` is an error.
- The dependency script had GNU-only `sha256sum`; it now supports `shasum`,
  FreeBSD `sha256` and `openssl`. Attack tests no longer include the Linux-only
  `<sys/sysmacros.h>`.
- Windows-only HTTP wrappers had called parsers that were compiled only on
  POSIX. The pure parsers compile everywhere; only the socket transport is
  POSIX-only.
- A hostile store could redirect writes through symlinked `blocks/`,
  `manifests/`, `pointers/`, `identities/`, `accepted/` or a symlink/FIFO
  `.lock`. Writes and the lock now refuse symlinks/non-regular files.

## Real-hardware test list

These cannot be proven in this Linux VM. Run them on each platform before
calling it supported.

### Every platform

1. Fresh `fetch-deps.sh`, `make clean && make`, `make test` and `make vectors`;
   record compiler and libsodium versions; confirm zero project warnings.
2. `make fuzz-build` and a 100k-input run; confirm no artifacts or timeouts.
3. Publish a tree with empty directories, zero-byte files, 64 KiB ± 1 files,
   a >4 GiB file if the filesystem allows it, and Unicode/space/quote/dash
   names; extract and `diff -r`.
4. Wrong passphrase, damaged identity, truncated pointer/manifest/block, missing
   object: non-zero exit, clear error, no crash.
5. `passwd` under the platform’s file permissions; restart and re-open.
6. HTTP serve/get over loopback and LAN; disconnect a client mid-response and
   confirm `serve` survives the SIGPIPE path.
7. Kill publish/download/gc (`SIGKILL`) at several points, then republish,
   resume and verify; confirm no torn pointer and no stale temp key.
8. Disk full, read-only store, and a store on a removable volume.

### macOS

- Run the actual binaries on Intel and Apple Silicon with Apple clang/Xcode
  tools, not only the zig cross-build.
- APFS: rename-replace semantics, 0700/0600 modes, extended attributes, sparse
  files, case-insensitive vs case-sensitive volumes.
- Unicode names in NFD and NFC (Finder-created names), and `--` paths.
- Sleep/wake during an HTTP transfer; firewall prompt and local-network privacy
  permission; IPv6 loopback/LAN.
- Terminal passphrase prompt with echo off, Ctrl-C, and EOF.

### FreeBSD

- Run the produced FreeBSD 14.5 binaries natively; also build with the system
  compiler and GNU make, not only zig.
- `flock` contention (two publishes, publish vs gc), `openat`/`O_NOFOLLOW`
  behavior on symlinks, and `poll` wakeup on `shutdown`.
- ZFS and UFS: atomic rename, permissions, sparse/large files.
- Jails restrictions on file and socket access.

### OpenBSD / NetBSD

- First get a native/sysroot build; neither has been built or run here.
- Then repeat the common checklist, especially `flock`/`openat` behavior and
  pledge/unveil restrictions if supported.

### Haiku

- First establish that libsodium 1.0.20 configures and builds, C++17 filesystem
  is complete, and `flock`, `openat`, `O_DIRECTORY`, `O_NOFOLLOW`, `poll` and
  `SO_NOSIGPIPE`/`MSG_NOSIGNAL` exist or have replacements. No Haiku build has
  been performed.

### Windows (local-only)

- Run `build/skipta.exe` and `build/run_tests.exe` natively with the MinGW UCRT
  runtime; confirm `serve` and `http://` fail with the documented message.
- NTFS ACLs instead of 0700/0600, reparse points/junctions in the store,
  `MAX_PATH`/long paths, reserved device names, trailing dots/spaces, CRLF.
- Concurrent `publish` and `gc` (currently unprotected), antivirus
  interference, locked files, and Unicode names.
- Port or explicitly skip POSIX test cases (symlinks, FIFOs, mknod, permissions)
  before claiming `make test` passes there.

### Linux variants

- aarch64 and armv7 on real hardware: vectors, Ed25519/XChaCha/Argon2, block
  pipeline, file sizes beyond 2/4 GiB, and `size_t` truncation paths. QEMU is
  useful but not a substitute for the hardware memory/filesystem behavior.
- The QEMU-tested armv7 and aarch64 builds are static musl. Also test glibc and
  a 32-bit userland on suitable distributions.
- NFS/SMB stores: `flock` reliability and rename atomicity; case-insensitive
  filesystems; FAT/exFAT without Unix permissions.

### Security review that is not a hardware test

- External cryptographic review of the format, AAD/nonce construction and
  identity wrapping.
- `mlock`/swap protection for keys and passphrases (currently not implemented).
- Memory-forensics and crash-dump exposure of plaintext; OS keychain integration
  is not implemented.
