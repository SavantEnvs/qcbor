#!/usr/bin/env bash
#
# qcbor/mayhem/test.sh -- RUN QCBOR's own upstream KAT test suite (built by
# mayhem/build.sh via the project's plain Makefile, normal flags) and emit a
# CTRF summary. exit 0 iff nothing failed.
#
# BEHAVIORAL oracle (SPEC 6.3 anti-reward-hacking). `$SRC/qcbortest` is
# QCBOR's own upstream test aggregator (test/run_tests.c, run via
# cmd_line_main.c): it runs ~100 known-answer tests over the encoder,
# decoder, spiffy-decode typed accessors, float/half-float conversion, and
# UsefulBuf, each asserting exact decoded/encoded VALUES (not just "did not
# crash"), and prints a summary line:
#
#   SUMMARY: <N> tests run; <F> tests failed
#
# and returns <F> as its process exit code. A no-op/exit(0) patch to the
# library would make individual KATs fail their internal comparisons (wrong
# decoded value, wrong error code, ...), which run_tests.c counts and
# reports -- NOT a stub that survives.
#
# qcbortest is a plain, dynamically-linked clang/cc executable (asserted by
# build.sh) -- unlike a statically-linked `go test`/`cargo test` binary, the
# verify-repo LD_PRELOAD sabotage shim CAN neuter it (constructor _exit(0)s
# it before main() runs), which makes it produce NO output at all -- the
# SUMMARY-line parse below then fails outright, so this oracle is caught by
# the mechanical sabotage check without needing a separate cgo-style probe.
#
# This script does NOT compile -- mayhem/build.sh already built qcbortest.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
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

BIN="$SRC/qcbortest"
if [ ! -x "$BIN" ]; then
  echo "missing $BIN -- run mayhem/build.sh first" >&2
  emit_ctrf "qcbor-run_tests" 0 1 0
  exit 2
fi

echo "=== running: $BIN ==="
OUT="$("$BIN" 2>&1)"; rc=$?
printf '%s\n' "$OUT"

# UNCONDITIONAL: a missing/garbled SUMMARY line is a FAILURE, never a skip -- this is exactly
# what a neutered (exit(0)'d before printing) or crashed binary produces.
SUMMARY_LINE="$(printf '%s\n' "$OUT" | grep -m1 '^SUMMARY:')"
if [ -z "$SUMMARY_LINE" ]; then
  echo "FAIL: no 'SUMMARY:' line in qcbortest output (neutered, crashed, or missing binary) -- rc=$rc" >&2
  emit_ctrf "qcbor-run_tests" 0 1 0
  exit 1
fi

RUN="$(printf '%s' "$SUMMARY_LINE" | sed -nE 's/^SUMMARY:[[:space:]]*([0-9]+) tests run;.*/\1/p')"
FAILED="$(printf '%s' "$SUMMARY_LINE" | sed -nE 's/.*;[[:space:]]*([0-9]+) tests failed.*/\1/p')"
: "${RUN:=0}" "${FAILED:=0}"

if [ "$RUN" -eq 0 ]; then
  echo "FAIL: SUMMARY reports 0 tests run -- the suite did not execute" >&2
  emit_ctrf "qcbor-run_tests" 0 1 0
  exit 1
fi

PASSED=$(( RUN - FAILED ))
# A nonzero exit with a clean-looking SUMMARY (e.g. a crash on a test AFTER printing SUMMARY, or a
# signal) is inconsistent -- stay honest rather than silently reporting green.
if [ "$rc" -ne 0 ] && [ "$FAILED" -eq 0 ]; then
  echo "FAIL: qcbortest exited $rc despite SUMMARY reporting 0 failures -- treating as a failure" >&2
  FAILED=1
  PASSED=$(( PASSED > 0 ? PASSED - 1 : 0 ))
fi

echo "=== results: $RUN run, $PASSED passed, $FAILED failed ==="
emit_ctrf "qcbor-run_tests" "$PASSED" "$FAILED"
