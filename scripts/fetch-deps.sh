#!/usr/bin/env bash
# Fetch and build Skipta's pinned third-party dependencies.
#
# Layout (all ignored by git except third_party/*.h):
#   .deps/include/sodium.h         libsodium headers
#   .deps/lib/libsodium.a          static libsodium (no shared library, no root needed)
#   third_party/nlohmann/json.hpp  nlohmann/json single header  (checked in)
#   third_party/doctest/doctest.h  doctest single header        (checked in)
#
# No root, no apt, no cmake required. Re-run to rebuild.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
deps="$root/.deps"
dl="$deps/src"
mkdir -p "$deps" "$dl" "$root/third_party/doctest"

SODIUM_VERSION="1.0.20"
JSON_VERSION="3.11.3"
DOCTEST_VERSION="2.4.11"

fetch() { # url dest
  if [ ! -s "$2" ]; then
    echo "fetching $1"
    curl -fsSL --retry 3 -o "$2.part" "$1"
    mv "$2.part" "$2"
  fi
}

sha() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  elif command -v sha256 >/dev/null 2>&1; then
    sha256 -q "$1"
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$1" | sed 's/^.*= //'
  else
    echo "no SHA-256 tool found (need sha256sum, shasum or openssl)" >&2
    return 1
  fi
}

# ---- libsodium: the only dependency in the trusted computing base -------------
if [ ! -f "$deps/lib/libsodium.a" ]; then
  fetch "https://download.libsodium.org/libsodium/releases/libsodium-$SODIUM_VERSION.tar.gz" \
        "$dl/libsodium-$SODIUM_VERSION.tar.gz"
  echo "libsodium sha256: $(sha "$dl/libsodium-$SODIUM_VERSION.tar.gz")"
  rm -rf "$dl/libsodium-$SODIUM_VERSION"
  tar -xzf "$dl/libsodium-$SODIUM_VERSION.tar.gz" -C "$dl"
  (
    cd "$dl/libsodium-$SODIUM_VERSION"
    ./configure --prefix="$deps" --disable-shared --enable-static >/dev/null
    make -j"$(nproc 2>/dev/null || echo 2)" >/dev/null
    make install >/dev/null
  )
  echo "libsodium $SODIUM_VERSION installed in $deps"
fi

# ---- header-only libraries (vendored, checked in) ----------------------------
if [ ! -s "$root/third_party/nlohmann/json.hpp" ]; then
  mkdir -p "$root/third_party/nlohmann"
  fetch "https://github.com/nlohmann/json/releases/download/v$JSON_VERSION/json.hpp" \
        "$root/third_party/nlohmann/json.hpp"
  echo "nlohmann/json sha256: $(sha "$root/third_party/nlohmann/json.hpp")"
fi

if [ ! -s "$root/third_party/doctest/doctest.h" ]; then
  fetch "https://raw.githubusercontent.com/doctest/doctest/v$DOCTEST_VERSION/doctest/doctest.h" \
        "$root/third_party/doctest/doctest.h"
  echo "doctest sha256: $(sha "$root/third_party/doctest/doctest.h")"
fi

echo "dependencies ready"
