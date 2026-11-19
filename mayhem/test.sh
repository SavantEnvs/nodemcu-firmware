#!/usr/bin/env bash
#
# mayhem/test.sh — RUN NodeMCU's own host test suites against the luac.cross binaries mayhem/build.sh
# built with normal flags (mayhem/out/test53/luac.cross = Lua 5.3, mayhem/out/test51/luac.cross =
# Lua 5.1), as upstream CI (.github/workflows/build.yml, job NTest) does:
#   - NTest selfcheck   (tests/NTest/NTest_NTest.lua): "failed: F  passed: P"
#   - NTest host tests  (tests/NTest_lua.lua): one "  pass ..." / " ==>  fail ..." line per check
#   - mayhem/test/kat.lua known answers for struct/sjson/bit/load, diffed per line against
#     mayhem/test/kat_<53|51>.expected
# A neutered luac.cross prints nothing, so every count drops to failures.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"
: "${SRC:=/mayhem}"
cd "$SRC"

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

passed=0 failed=0
work=$(mktemp -d "${TMPDIR:-/tmp}/nodemcu-test.XXXXXX")
trap 'rm -rf "$work"' EXIT

for v in 53 51; do
  luac="$SRC/mayhem/out/test$v/luac.cross"
  if [ ! -x "$luac" ]; then
    echo "test.sh: $luac missing — mayhem/build.sh did not build it" >&2
    failed=$((failed + 1)); continue
  fi

  # 1) NTest selfcheck
  log=$(cd "$SRC/tests/NTest" && "$luac" -e ../NTest/NTest_NTest.lua 2>&1)
  line=$(grep -E '^failed: [0-9]+[[:space:]]+passed: [0-9]+' <<<"$log" | tail -1)
  if [ -n "$line" ]; then
    f=$(sed -E 's/^failed: ([0-9]+).*/\1/' <<<"$line"); p=$(sed -E 's/.*passed: ([0-9]+).*/\1/' <<<"$line")
    echo "lua$v NTest selfcheck: passed=$p failed=$f"
    passed=$((passed + p)); failed=$((failed + f))
  else
    echo "lua$v NTest selfcheck: no summary line"; failed=$((failed + 1))
  fi

  # 2) NTest host tests (upstream copies NTest.lua next to the test; done in a scratch dir here)
  d="$work/host$v"; mkdir -p "$d"
  cp "$SRC/tests/NTest/NTest.lua" "$SRC/tests/NTest_lua.lua" "$d/"
  log=$(cd "$d" && "$luac" -e NTest_lua.lua 2>&1)
  p=$(grep -c '^  pass ' <<<"$log"); f=$(grep -c '^ ==>  ' <<<"$log")
  grep -q '^######## finished' <<<"$log" || f=$((f + 1))
  echo "lua$v NTest host tests: passed=$p failed=$f"
  passed=$((passed + p)); failed=$((failed + f))

  # 3) known answers
  exp="$SRC/mayhem/test/kat_$v.expected"
  got=$(cd "$work" && "$luac" -e "$SRC/mayhem/test/kat.lua" 2>&1)
  n=$(wc -l < "$exp"); p=0; f=0
  for ((i = 1; i <= n; i++)); do
    e=$(sed -n "${i}p" "$exp"); g=$(sed -n "${i}p" <<<"$got")
    if [ "$e" == "$g" ]; then p=$((p + 1)); else f=$((f + 1)); echo "  KAT lua$v line $i: expected [$e] got [$g]"; fi
  done
  echo "lua$v known answers: passed=$p failed=$f"
  passed=$((passed + p)); failed=$((failed + f))
done

emit_ctrf "nodemcu-ntest" "$passed" "$failed" 0
