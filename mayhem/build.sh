#!/usr/bin/env bash
# mayhem/build.sh — gerbera: upstream unit-test suite (normal flags) + sanitized libFuzzer harnesses.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS SRC
cd "$SRC"

# Feature set shared by both builds. Off: systemd/curl/zip/icu/exiv2/magic (optional extras; libzippp
# is not packaged). On: every media-metadata parser that reads untrusted files, plus JS import scripts.
GRB_OPTS=(-DWITH_SYSTEMD=OFF -DWITH_CURL=OFF -DWITH_ZIP=OFF -DWITH_ICU=OFF -DWITH_EXIV2=OFF
          -DWITH_MAGIC=OFF -DWITH_WAVPACK=ON -DWITH_TAGLIB=ON -DWITH_MATROSKA=ON -DWITH_EXIF=ON
          -DWITH_JS=ON -DWITH_INOTIFY=ON -DWITH_DEBUG=ON)

# 1) Upstream gtest suite, NORMAL flags (the functional oracle run by mayhem/test.sh).
#    mayhem/build/ is gitignored by upstream's `build` pattern (git clean -ffdX removes it).
cmake -S . -B mayhem/build/tests -DCMAKE_BUILD_TYPE=Release -DWITH_TESTS=ON "${GRB_OPTS[@]}" \
      -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS"
cmake --build mayhem/build/tests -j"$MAYHEM_JOBS"

# 2) Sanitized + SanCov-instrumented libgerbera and harnesses (mayhem/fuzz/fuzz_*.cc), fuzzer and
#    -standalone each. -fsanitize=fuzzer-no-link is unconditional so the library carries coverage
#    edges even with an empty SANITIZER_FLAGS; only the harness targets are built (not the server).
FUZZ_CFLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS"
# LeakSanitizer off at build time (mayhem/lsan_off.cc, linked into every fuzz + -standalone binary).
mkdir -p mayhem/build
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o mayhem/build/lsan_off.o
cmake -S . -B mayhem/build/fuzz -DCMAKE_PROJECT_INCLUDE="$SRC/mayhem/fuzz/project-include.cmake" -DFUZZ_LSAN_OFF_OBJ="$SRC/mayhem/build/lsan_off.o" -DCMAKE_BUILD_TYPE=Debug -DWITH_TESTS=OFF "${GRB_OPTS[@]}" \
      -DCMAKE_C_FLAGS="$FUZZ_CFLAGS" -DCMAKE_CXX_FLAGS="$FUZZ_CFLAGS" \
      -DCMAKE_C_FLAGS_DEBUG="-O1" -DCMAKE_CXX_FLAGS_DEBUG="-O1"
FUZZERS=()
for f in mayhem/fuzz/fuzz_*.cc; do n=$(basename "$f" .cc); FUZZERS+=("$n" "$n-standalone"); done
cmake --build mayhem/build/fuzz -j"$MAYHEM_JOBS" --target "${FUZZERS[@]}"

for f in mayhem/fuzz/fuzz_*.cc; do
  n=$(basename "$f" .cc)
  install -m 755 "mayhem/build/fuzz/$n" "/mayhem/$n"
  install -m 755 "mayhem/build/fuzz/$n-standalone" "/mayhem/$n-standalone"
done
