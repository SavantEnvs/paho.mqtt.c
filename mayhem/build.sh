#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

LIBS="-lpthread -ldl"

# 1) The library, sanitized, with upstream's CMake. Static libs only, no SSL (the harnesses drive
#    plain tcp://). -DNO_HEAP_TRACKING=1 turns off paho's own malloc wrapper (Heap.c) so ASan sees
#    the real allocation sizes (Heap.c pads every block with an eyecatcher that would hide small
#    overflows); tracing (Log.c) stays on, unlike PAHO_HIGH_PERFORMANCE which drops both.
#    -fsanitize=fuzzer-no-link gives the library SanitizerCoverage, so the fuzzer sees its edges.
FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -DNO_HEAP_TRACKING=1 -fsanitize=fuzzer-no-link"
cmake -S . -B mayhem/build-fuzz \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="$FUZZ_CFLAGS" \
  -DPAHO_BUILD_STATIC=ON -DPAHO_BUILD_SHARED=OFF \
  -DPAHO_ENABLE_TESTING=OFF -DPAHO_ENABLE_CPACK=OFF \
  -DPAHO_BUILD_SAMPLES=OFF -DPAHO_WITH_SSL=OFF
cmake --build mayhem/build-fuzz -j"$MAYHEM_JOBS"
LIBC=mayhem/build-fuzz/src/libpaho-mqtt3c.a
LIBA=mayhem/build-fuzz/src/libpaho-mqtt3a.a

# 2) Harnesses: each linked twice, with libFuzzer and with the standalone run-once driver.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.c -o mayhem/build-fuzz/lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o mayhem/build-fuzz/standalone_main.o
INC="-Isrc -Imayhem/build-fuzz/src -Imayhem/harnesses"
build_harness() { # <name> <lib> <source> [extra cflags...]
  local name="$1" lib="$2" srcf="$3"; shift 3
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE $INC "$@" "$srcf" \
    mayhem/build-fuzz/lsan_off.o "$lib" $LIBS -o "/mayhem/$name"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $INC "$@" "$srcf" mayhem/build-fuzz/standalone_main.o \
    mayhem/build-fuzz/lsan_off.o "$lib" $LIBS -o "/mayhem/$name-standalone"
}
build_harness fuzz_client_sync_v5     "$LIBC" mayhem/harnesses/fuzz_client_sync.c -DFUZZ_MQTT_VERSION=5
build_harness fuzz_client_sync_v3     "$LIBC" mayhem/harnesses/fuzz_client_sync.c -DFUZZ_MQTT_VERSION=4
build_harness fuzz_client_ws          "$LIBC" mayhem/harnesses/fuzz_client_sync.c -DFUZZ_MQTT_VERSION=4 -DFUZZ_TRANSPORT=1
build_harness fuzz_client_async       "$LIBA" mayhem/harnesses/fuzz_client_async.c
build_harness fuzz_persistence_sync   "$LIBC" mayhem/harnesses/fuzz_persistence.c
build_harness fuzz_persistence_async  "$LIBA" mayhem/harnesses/fuzz_persistence.c -DFUZZ_ASYNC=1

# 3) Upstream's own test programs (test/*.c), NORMAL flags, separate tree. mayhem/test.sh runs a
#    subset of them against a local mosquitto broker.
cmake -S . -B mayhem/build-tests \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_EXE_LINKER_FLAGS="$COVERAGE_FLAGS" \
  -DPAHO_BUILD_STATIC=ON -DPAHO_BUILD_SHARED=OFF \
  -DPAHO_ENABLE_TESTING=ON -DPAHO_ENABLE_CPACK=OFF \
  -DPAHO_BUILD_SAMPLES=OFF -DPAHO_WITH_SSL=OFF
cmake --build mayhem/build-tests -j"$MAYHEM_JOBS"
