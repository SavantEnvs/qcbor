#!/usr/bin/env bash
#
# qcbor/mayhem/build.sh -- build two libFuzzer harnesses over QCBOR's DECODER
# (+ standalone reproducers), AND QCBOR's own upstream KAT test runner
# (`qcbortest`, built via the project's plain Makefile with NORMAL flags) for
# mayhem/test.sh.
#
# QCBOR ships NO fuzz harness of its own and is not an OSS-Fuzz project --
# both harnesses under mayhem/harnesses/ are new, hand-written here:
#   fuzz_decode        -- raw traversal: QCBORDecode_Init + QCBORDecode_GetNext
#                          loop until error/end (the core decoder: every major
#                          type, arbitrary nesting, definite/indefinite length,
#                          tags, floats/half-floats, big numbers).
#   fuzz_decode_encode -- decode via the same GetNext loop, then re-encode
#                          each decoded item with QCBOREncode_* (indefinite-
#                          length containers), exercising the ENCODER
#                          (qcbor_encode.c) on decoder-derived, attacker-
#                          influenced values. Asserts nothing -- see the
#                          harness's own header comment.
#
# The QCBOR library itself is compiled here (not just the harness) so the
# fuzzed decoder/encoder code is instrumented -- and with -fsanitize=fuzzer-no-link
# UNCONDITIONALLY (independent of $SANITIZER_FLAGS) so SanitizerCoverage is
# always present in the library object files even under an explicit empty
# --build-arg SANITIZER_FLAGS= (no-sanitizer) build; without it Mayhem would
# see 0 edges from the library despite the harness TU itself being
# instrumented via $LIB_FUZZING_ENGINE at the final link.
#
# Zero external dependencies (this is why QCBOR was picked as the first C
# repo in this cohort) -- nothing here ever touches the network, so the
# air-gapped re-run (SPEC 6.5) is trivial; no vendoring/caching needed.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) -- must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# Always ensure the LIBRARY gets SanitizerCoverage instrumentation, regardless of the base image's
# default or an empty override (see header comment).
case "$SANITIZER_FLAGS" in
  *fuzzer-no-link*) ;;  # already present
  *) SANITIZER_FLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link" ;;
esac
# DWARF <= 3 (SPEC 6.2 item 10): clang-19's plain -g emits DWARF-5; be explicit.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE STANDALONE_FUZZ_MAIN MAYHEM_JOBS
: "${SRC:=/mayhem}"
cd "$SRC"

INC="-I$SRC/inc"
LIBSRCS="src/UsefulBuf.c src/qcbor_encode.c src/qcbor_decode.c src/ieee754.c src/qcbor_err_to_str.c"
HARNESS_DIR="$SRC/mayhem/harnesses"
BUILD="$SRC/mayhem-build"
mkdir -p "$BUILD"

# ── 1) Build the QCBOR library WITH sanitizers + SanCov (the fuzzed decoder/encoder is instrumented) ──
OBJS=()
for s in $LIBSRCS; do
  obj="$BUILD/$(basename "${s%.c}").o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $INC -c "$s" -o "$obj"
  OBJS+=("$obj")
done
LIBQCBOR_FUZZ="$BUILD/libqcbor_fuzz.a"
rm -f "$LIBQCBOR_FUZZ"; ar rcs "$LIBQCBOR_FUZZ" "${OBJS[@]}"

# Standalone driver object, built once, linked into every harness's -standalone binary.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c -x c "$STANDALONE_FUZZ_MAIN" -o "$BUILD/standalone_main.o"

# ── 2) Build each harness TWICE: libFuzzer target -> /mayhem/<name>, standalone -> /mayhem/<name>-standalone ──
for h in fuzz_decode fuzz_decode_encode; do
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $INC \
      "$HARNESS_DIR/$h.c" $LIB_FUZZING_ENGINE "$LIBQCBOR_FUZZ" -lm \
      -o "/mayhem/$h"

  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $INC \
      "$HARNESS_DIR/$h.c" "$BUILD/standalone_main.o" "$LIBQCBOR_FUZZ" -lm \
      -o "/mayhem/$h-standalone"

  echo "built $h (+ standalone)"
done

# ── 3) Build QCBOR's OWN KAT test runner (`qcbortest`) via its plain Makefile, NORMAL flags ───────
# `make qcbortest` builds a SEPARATE, non-sanitized libqcbor.a + test/*.o + cmd_line_main.o straight
# into the source tree (its own object-naming scheme, distinct from mayhem-build/ above -- no
# collision with step 1). This is a clean, independent build so mayhem/test.sh stays an honest
# functional oracle (no sanitizer/UB noise). `make` is naturally idempotent (mtime-based), so
# re-running this on an already-built tree is a near-no-op -- satisfies the air-gapped re-run gate.
make CC="$CC" -j"$MAYHEM_JOBS" qcbortest
[ -x "$SRC/qcbortest" ] || { echo "FATAL: $SRC/qcbortest was not produced by 'make qcbortest'" >&2; exit 1; }
# qcbortest MUST be dynamically linked so verify-repo's LD_PRELOAD sabotage shim can neuter it --
# a statically-linked test binary would survive sabotage and make mayhem/test.sh reward-hackable
# (SPEC 6.3). Plain clang/cc links dynamically by default; assert it so a toolchain change can't
# silently flip this and weaken the oracle.
if ! file "$SRC/qcbortest" | grep -q 'dynamically linked'; then
  echo "FATAL: $SRC/qcbortest is not dynamically linked -- the sabotage check could not neuter it," >&2
  echo "       which would make mayhem/test.sh a reward-hackable oracle." >&2
  file "$SRC/qcbortest" >&2
  exit 1
fi
echo "built qcbortest (dynamically linked KAT runner)"

echo "build.sh complete:"
ls -la /mayhem/fuzz_decode /mayhem/fuzz_decode_encode \
       /mayhem/fuzz_decode-standalone /mayhem/fuzz_decode_encode-standalone \
       "$SRC/qcbortest" 2>&1 || true
