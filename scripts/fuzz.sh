#!/bin/sh
# Build and run the sanitizer mutation fuzzer.
#
#   ./scripts/fuzz.sh --iterations 3000000 --seed 1
#   ./scripts/fuzz.sh --iterations 500000 --only http-response
#
# Artifacts (a timeout, sanitizer finding or unexpected exception) are written
# to /tmp/skipta-fuzz-artifacts by default; pass --artifacts DIR to change it.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

make fuzz-build

: "${ASAN_OPTIONS:=detect_leaks=1:abort_on_error=1:strict_string_checks=1:check_initialization_order=1:malloc_context_size=25}"
: "${UBSAN_OPTIONS:=print_stacktrace=1:halt_on_error=1}"
export ASAN_OPTIONS UBSAN_OPTIONS

exec ./build-fuzz/fuzz "$@"
