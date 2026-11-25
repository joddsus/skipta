#!/bin/sh
# Link FreeBSD binaries with LLVM's lld against a real FreeBSD base.txz sysroot.
# Used from the Makefile as:
#   make LINKER=./scripts/freebsd-link.sh CXX="zig c++ -target x86_64-freebsd ..." ...
# Required: FBSD_SYSROOT (extracted base.txz). Optional: FBSD_LLD,
# FBSD_LLD_LIBDIR (for a distro lld package whose libLLVM is outside ld.lld's
# runpath). The compiler has already produced FreeBSD objects; this only links.
set -eu

: "${FBSD_SYSROOT:?set FBSD_SYSROOT to an extracted FreeBSD base.txz}"
LLD=${FBSD_LLD:-ld.lld}
out=
inputs=
libs=
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o)
            [ "$#" -ge 2 ] || { echo "freebsd-link: -o needs an argument" >&2; exit 2; }
            out=$2
            shift 2
            ;;
        -pthread)
            shift
            ;;
        -std=*|-O*|-g|-W*|-f*|-D*|-I*)
            shift
            ;;
        -L*|-l*)
            libs="$libs $1"
            shift
            ;;
        -*)
            shift
            ;;
        *)
            inputs="$inputs $1"
            shift
            ;;
    esac
done

[ -n "$out" ] || { echo "freebsd-link: missing -o" >&2; exit 2; }
if [ -n "${FBSD_LLD_LIBDIR:-}" ]; then
    LD_LIBRARY_PATH="${FBSD_LLD_LIBDIR}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    export LD_LIBRARY_PATH
fi

# libthr provides pthread; libc++.so is a linker script for libc++.so.1.
# shellcheck disable=SC2086
exec "$LLD" --sysroot="$FBSD_SYSROOT" \
    -dynamic-linker /libexec/ld-elf.so.1 \
    -o "$out" \
    "$FBSD_SYSROOT/usr/lib/crt1.o" \
    "$FBSD_SYSROOT/usr/lib/crti.o" \
    "$FBSD_SYSROOT/usr/lib/crtbegin.o" \
    $inputs \
    -L"$FBSD_SYSROOT/usr/lib" -L"$FBSD_SYSROOT/lib" \
    -lc++ -lcxxrt -lpthread -lc -lgcc -lgcc_s -lm \
    "$FBSD_SYSROOT/usr/lib/crtend.o" \
    "$FBSD_SYSROOT/usr/lib/crtn.o"
