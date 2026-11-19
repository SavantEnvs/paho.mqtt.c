#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Upstream's own test programs (test/*.c, built by build.sh into mayhem/build-tests) against a
# local mosquitto broker on 127.0.0.1:1883 — the setup upstream's CI uses. Each program logs a
# summary "... <N> tests run, 0 failures." and "verdict pass" per test case; a case counts as passed
# only when both are present with N>0 and no failure, so a binary that exits early fails.
# test45 cases 1 and 4 are left out: they assert UNSUBACK properties, which mosquitto never sends.
BIN="$SRC/mayhem/build-tests/test"
BROKER="tcp://127.0.0.1:1883"
command -v mosquitto >/dev/null || { echo "mosquitto missing (installed by mayhem/Dockerfile)" >&2; emit_ctrf paho-test 0 1; exit 1; }
[ -x "$BIN/test1-static" ] || { echo "test binaries missing: run mayhem/build.sh" >&2; emit_ctrf paho-test 0 1; exit 1; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/paho-test.XXXXXX")
printf 'listener 1883 127.0.0.1\nallow_anonymous true\npersistence false\n' > "$WORK/mosquitto.conf"
mosquitto -c "$WORK/mosquitto.conf" > "$WORK/mosquitto.log" 2>&1 &
MPID=$!
trap 'kill $MPID 2>/dev/null; wait $MPID 2>/dev/null; rm -rf "$WORK"' EXIT
for _ in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/1883) 2>/dev/null && break; sleep 0.1; done

passed=0; failed=0
run_case() { # <program> <test_no>
  local prog="$1" no="$2" out
  out=$(cd "$WORK" && timeout 120 "$BIN/$prog" --test_no "$no" --connection "$BROKER" 2>&1)
  if grep -Eq '(test passed\.|passed: test [^.]*\.) [1-9][0-9]* tests run, 0 failures' <<<"$out" \
     && grep -q 'verdict pass' <<<"$out" && ! grep -Eq 'test failed|verdict fail' <<<"$out"; then
    passed=$((passed+1)); echo "PASS $prog #$no"
  else
    failed=$((failed+1)); echo "FAIL $prog #$no"; tail -n 20 <<<"$out"
  fi
}
for n in 1 2 3 4 5; do run_case test1-static "$n"; done
for n in 1 2 3 4 5; do run_case test4-static "$n"; done
for n in 1 2 3 4 5; do run_case test15-static "$n"; done
for n in 2 3 5; do run_case test45-static "$n"; done

emit_ctrf paho-test "$passed" "$failed" 0
