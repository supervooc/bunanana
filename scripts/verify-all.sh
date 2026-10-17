#!/bin/bash
# Final acceptance run - one command that replays the whole verification matrix.
#
#   bash scripts/verify-all.sh              # real run against the attached device
#   bash scripts/verify-all.sh --selftest   # prove the assertions reject bad logs
#
# Every assertion here is strict on purpose. An earlier version grepped for
# substrings, which a review showed was defeated by real logs:
#   * "0 failure(s)" matches inside "10 failure(s)"   -> 10 failures passed
#   * "deep-skipped ... need uid 0" matched the deep-check assertion -> a non-root
#     run passed although no deep check ever executed
#   * "abi-consistency|abi-consistency-mismatch" let a CRITICAL ABI divergence pass
#   * `--selftest > file` never looked at $?, so the regex was the only gate
# So: parse the summary lines, compare exit codes, and add negative assertions for
# the states that must NOT appear. --selftest feeds the exact counter-examples from
# that review through these primitives and fails if any of them is accepted.
set -u
PROJ=/mnt/c/Users/86134/Documents/deepseek-harness/default-workspace/android-rootdetect
ADB=/opt/rx-android/platform-tools/adb
RESULTS=/tmp/verify-all
mkdir -p "$RESULTS"

pass=0; fail=0; skip=0
SELFTEST=0
if [ "${1:-}" = "--selftest" ]; then
  SELFTEST=1
  RESULTS=/tmp/verify-all-selftest
  rm -rf "$RESULTS"
  mkdir -p "$RESULTS"
fi

hr()       { echo; echo "================ $* ================"; }
ok()       { echo "  PASS  $1"; pass=$((pass + 1)); }
bad()      { echo "  FAIL  $1    ($2)"; fail=$((fail + 1)); }
skipnote() { echo "  SKIP  $1    ($2)"; skip=$((skip + 1)); }

# --------------------------------------------------------- strict primitives ---
# Whole-line literal match: no substring surprises.
expect_line() { # name file literal
  if grep -qxF "$3" "$2" 2>/dev/null; then ok "$1"; else bad "$1" "no whole line '$3' in ${2##*/}"; fi
}
expect_regex() { # name file regex
  if grep -qE "$3" "$2" 2>/dev/null; then ok "$1"; else bad "$1" "no match for /$3/ in ${2##*/}"; fi
}
expect_no_regex() { # name file regex
  if grep -qE "$3" "$2" 2>/dev/null; then bad "$1" "forbidden match /$3/ in ${2##*/}"; else ok "$1"; fi
}
expect_rc() { # name wanted actual
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "exit $3, wanted $2"; fi
}

# "N checks, N failure(s), N skipped" - parsed, not grepped.
selftest_counts() { # file -> "checks failures skips"
  local line c f s
  line=$(tr -d '\r' < "$1" 2>/dev/null | grep -E '^[0-9]+ checks, [0-9]+ failure\(s\), [0-9]+ skipped$' | tail -1)
  [ -z "$line" ] && return 1
  c=$(echo "$line" | sed -E 's/^([0-9]+) checks.*/\1/')
  f=$(echo "$line" | sed -E 's/.* ([0-9]+) failure\(s\).*/\1/')
  s=$(echo "$line" | sed -E 's/.* ([0-9]+) skipped$/\1/')
  echo "$c $f $s"
}
expect_selftest() { # name file min_checks
  local counts c f s
  counts=$(selftest_counts "$2") || { bad "$1" "no 'N checks, N failure(s), N skipped' line"; return; }
  c=${counts%% *}
  f=$(echo "$counts" | cut -d' ' -f2)
  s=${counts##* }
  if [ "$f" -ne 0 ]; then bad "$1" "$c checks, $f failure(s) - failures must be 0"; return; fi
  if [ "$c" -lt "${3:-1}" ]; then bad "$1" "only $c checks, expected >= ${3:-1}"; return; fi
  ok "$1  [$c checks, 0 failure(s), $s skipped]"
}

# "summary: N critical, N high, ..." - parsed, not grepped.
summary_line() { # file -> "critical high medium low info"
  local line
  line=$(tr -d '\r' < "$1" 2>/dev/null | grep -E '^summary: [0-9]+ critical' | tail -1)
  [ -z "$line" ] && return 1
  echo "$line" | sed -E 's/^summary: ([0-9]+) critical, ([0-9]+) high, ([0-9]+) medium, ([0-9]+) low, ([0-9]+) info.*/\1 \2 \3 \4 \5/'
}
expect_summary() { # name file max_critical max_high
  local v c h
  v=$(summary_line "$2") || { bad "$1" "no 'summary: N critical' line"; return; }
  c=${v%% *}
  h=$(echo "$v" | cut -d' ' -f2)
  if [ "$c" -gt "$3" ] || [ "$h" -gt "$4" ]; then
    bad "$1" "summary: $c critical, $h high (allowed <= $3 critical, <= $4 high)"; return
  fi
  ok "$1  [$c critical, $h high]"
}
expect_summary_min_critical() { # name file min
  local v c
  v=$(summary_line "$2") || { bad "$1" "no 'summary: N critical' line"; return; }
  c=${v%% *}
  if [ "$c" -lt "$3" ]; then bad "$1" "$c critical, expected >= $3"; return; fi
  ok "$1  [$c critical]"
}

# Deep checks only exist under uid 0. This assertion used to accept the
# "deep-skipped ... need uid 0" INFO line, which is the opposite of a deep run.
expect_deep_ran() { # name file uid
  if [ "$3" != "0" ]; then bad "$1" "device uid is $3, deep checks need uid 0"; return; fi
  if grep -qE 'deep-skipped.*uid 0' "$2" 2>/dev/null; then
    bad "$1" "log says 'deep-skipped ... need uid 0' - the deep checks did not run"; return
  fi
  if ! grep -qE '^\[INFO *\].*(kernel-taint|kernel-kcore|kernel-module|deep-dmesg)' "$2" 2>/dev/null; then
    bad "$1" "no deep-check line (kernel-taint/kernel-kcore/kernel-module/deep-dmesg) in log"; return
  fi
  ok "$1  [uid 0, deep checks present]"
}

# -v must print each INFO row exactly once (the renderer used to print them twice).
expect_no_duplicate_info() { # name file
  local dups
  dups=$(tr -d '\r' < "$2" 2>/dev/null | grep -E '^\[INFO *\]' | sed -E 's/^\[INFO *\] ([a-z0-9-]+).*/\1/' | sort | uniq -d | head -5)
  if [ -n "$dups" ]; then bad "$1" "duplicated INFO ids: $(echo $dups | tr '\n' ' ')"; else ok "$1"; fi
}

# A mismatch must never count as success.
expect_abi_agree() { # name file rc
  if [ "$3" != "0" ]; then bad "$1" "abi-diff script exited $3"; return; fi
  if grep -qE 'abi-consistency-mismatch' "$2" 2>/dev/null; then
    bad "$1" "log contains abi-consistency-mismatch (the two ABIs disagree)"; return
  fi
  if ! grep -qE 'abi-consistency .*both ABIs agree' "$2" 2>/dev/null; then
    bad "$1" "no 'abi-consistency ... both ABIs agree' line"; return
  fi
  ok "$1"
}

# ------------------------------------------------------------------ selftest ---
if [ "$SELFTEST" = "1" ]; then
  hr "self-test: the assertions must reject bad logs"
  ST="$RESULTS/fixtures"
  mkdir -p "$ST"

  printf '77 checks, 0 failure(s), 2 skipped\n' > "$ST/selftest-good.txt"
  printf '36 checks, 10 failure(s), 2 skipped\n' > "$ST/selftest-bad.txt"
  printf 'selftest_exit=9\nno summary here\n' > "$ST/selftest-noline.txt"

  printf '[INFO    ] kernel-taint             no taint bits set\n[INFO    ] deep-dmesg              no root framework named in the kernel log\n' > "$ST/deep-good.txt"
  printf '[INFO    ] deep-skipped           deep kernel checks need uid 0\n' > "$ST/deep-skipped.txt"

  printf '[INFO    ] abi-consistency        both ABIs agree on every probed path\n' > "$ST/abi-good.txt"
  printf '[CRITICAL] abi-consistency-mismatch  the two ABIs disagree on /system/bin/su\n' > "$ST/abi-bad.txt"

  printf 'summary: 0 critical, 0 high, 1 medium, 2 low, 20 info\nverdict: CLEAN\n' > "$ST/summary-good.txt"
  printf 'summary: 1 critical, 3 high, 1 medium, 2 low, 20 info\nverdict: HIDING_DETECTED\n' > "$ST/summary-bad.txt"

  # want=1: the primitive must accept; want=0: it must reject (the review's cases).
  st_case() { # want description func args...
    local want="$1" desc="$2"
    shift 2
    local out p f got=0
    out=$( ( pass=0; fail=0; "$@" >/dev/null 2>&1; echo "$pass:$fail" ) )
    p=${out%%:*}
    f=${out##*:}
    [ "$p" -gt 0 ] && [ "$f" -eq 0 ] && got=1
    if [ "$got" = "$want" ]; then
      echo "  PASS  $desc"
      pass=$((pass + 1))
    else
      echo "  FAIL  $desc (wanted pass=$want, got pass=$p fail=$f)"
      fail=$((fail + 1))
    fi
  }

  st_case 1 "clean self-test log is accepted"              expect_selftest "st" "$ST/selftest-good.txt" 40
  st_case 0 "10 failure(s) is rejected (substring trap)"   expect_selftest "st" "$ST/selftest-bad.txt" 40
  st_case 0 "log without a summary line is rejected"       expect_selftest "st" "$ST/selftest-noline.txt" 40
  st_case 1 "real deep-check log is accepted"              expect_deep_ran "st" "$ST/deep-good.txt" 0
  st_case 0 "deep-skipped log is rejected"                 expect_deep_ran "st" "$ST/deep-skipped.txt" 0
  st_case 0 "non-root run is rejected"                     expect_deep_ran "st" "$ST/deep-good.txt" 2000
  st_case 1 "agreeing ABI log is accepted"                 expect_abi_agree "st" "$ST/abi-good.txt" 0
  st_case 0 "abi-consistency-mismatch is rejected"         expect_abi_agree "st" "$ST/abi-bad.txt" 0
  st_case 0 "abi script failure is rejected"               expect_abi_agree "st" "$ST/abi-good.txt" 3
  st_case 1 "clean summary is accepted"                    expect_summary "st" "$ST/summary-good.txt" 0 0
  st_case 0 "CRITICAL in summary is rejected"              expect_summary "st" "$ST/summary-bad.txt" 0 3
  st_case 1 "fixture CRITICAL satisfies min_critical"      expect_summary_min_critical "st" "$ST/summary-bad.txt" 1
  st_case 0 "clean summary fails min_critical"             expect_summary_min_critical "st" "$ST/summary-good.txt" 1
  st_case 0 "forbidden pattern is caught"                  expect_no_regex "st" "$ST/abi-bad.txt" 'abi-consistency-mismatch'

  hr "selftest summary"
  echo "  PASS=$pass  FAIL=$fail"
  [ "$fail" -eq 0 ]
  exit $?
fi

# ------------------------------------------------------------------- real run ---
RX=/tmp/rootdetect-verify/rx
mkdir -p /tmp/rootdetect-verify

hr "0. artifacts"
ls -l "$PROJ/out" 2>/dev/null | sed 's/^/  /'
if [ -f "$PROJ/out/rootdetect-x86_64" ]; then
  cp -f "$PROJ/out/rootdetect-x86_64" "$RX"
  chmod 755 "$RX"
else
  bad "x86_64 CLI binary present" "$PROJ/out/rootdetect-x86_64 is missing"
fi

if [ -x "$RX" ]; then
  hr "1. real Linux kernel (WSL): self-test and clean baseline"
  "$RX" --selftest > "$RESULTS/linux-selftest.txt" 2>&1
  expect_rc "linux self-test exited 0" 0 $?
  expect_selftest "linux self-test: 0 failures, >= 40 checks" "$RESULTS/linux-selftest.txt" 40

  "$RX" > "$RESULTS/linux-baseline.txt" 2>&1
  expect_rc "linux baseline exited 0" 0 $?
  expect_summary "linux baseline: no CRITICAL/HIGH" "$RESULTS/linux-baseline.txt" 0 0
  expect_line "linux baseline: verdict CLEAN" "$RESULTS/linux-baseline.txt" "verdict: CLEAN"
else
  skipnote "linux self-test" "no scanner binary"
fi

hr "2. Android emulator (KVM inside WSL)"
if $ADB devices 2>/dev/null | grep -q "emulator-.*device"; then
  $ADB wait-for-device
  # Deploy to a root-only directory when adbd is root: a root process executing a
  # file from a group/other-writable directory (/data/local/tmp is drwxrwx--x
  # shell shell) could have had its binary replaced by any adb shell user.
  RXDEV=/data/local/tmp/rx
  if [ "$($ADB shell id -u 2>/dev/null | tr -d '\r')" = "0" ]; then
    $ADB shell "mkdir -p /data/local/rx && chmod 700 /data/local/rx" > /dev/null 2>&1
    RXDEV=/data/local/rx/rx
  fi
  $ADB push "$RX" "$RXDEV" > /dev/null 2>&1
  $ADB shell chmod 755 "$RXDEV" > /dev/null 2>&1

  # Shell-domain view first (the JSON needs no uid 0), then take root and assert
  # the self-test there: the shell domain legitimately skips three checks
  # (/proc/kallsyms and the two /proc/sys/kernel sources), so "0 skipped" is only
  # deterministic under uid 0.
  $ADB shell $RXDEV --json 2>&1 | tr -d '\r' > "$RESULTS/android-shell.json"
  expect_regex "android (shell): no CRITICAL crafted from SELinux denials" "$RESULTS/android-shell.json" '"critical": 0'

  $ADB root > /dev/null 2>&1
  sleep 4
  UID_DEV=$($ADB shell id -u 2>/dev/null | tr -d '\r')

  $ADB shell $RXDEV --selftest 2>&1 | tr -d '\r' > "$RESULTS/android-selftest.txt"
  expect_rc "android self-test exited 0" 0 ${PIPESTATUS[0]:-$?}
  expect_selftest "android self-test (uid 0): 0 failures, >= 40 checks" "$RESULTS/android-selftest.txt" 40
  expect_regex "android self-test (uid 0): no skipped checks" "$RESULTS/android-selftest.txt" \
    '^[0-9]+ checks, 0 failure\(s\), 0 skipped$'
  $ADB shell $RXDEV -v 2>&1 | tr -d '\r' > "$RESULTS/android-root.txt"
  expect_deep_ran "android (uid 0): deep checks really ran" "$RESULTS/android-root.txt" "$UID_DEV"
  expect_no_duplicate_info "android (uid 0): every INFO row printed once" "$RESULTS/android-root.txt"
  expect_no_regex "android (uid 0): no self-executable warning from the root-only path" \
    "$RESULTS/android-root.txt" 'self-executable-in-writable-dir'

  hr "2b. injected root artefacts must be detected"
  $ADB shell mkdir -p /data/adb/magisk /data/data/com.topjohnwu.magisk > /dev/null 2>&1
  $ADB shell "printf 'MAGISK\n' > /data/adb/magisk/util_functions.sh" > /dev/null 2>&1
  $ADB shell cp /system/bin/toybox /data/local/tmp/su > /dev/null 2>&1
  $ADB shell chmod 755 /data/local/tmp/su > /dev/null 2>&1
  $ADB shell $RXDEV -v 2>&1 | tr -d '\r' > "$RESULTS/android-fixtures.txt"
  expect_regex "fixtures: package-hidden reported" "$RESULTS/android-fixtures.txt" 'package-hidden'
  expect_regex "fixtures: artefact-present reported" "$RESULTS/android-fixtures.txt" 'artefact-present'
  expect_summary_min_critical "fixtures: at least one CRITICAL" "$RESULTS/android-fixtures.txt" 1
  $ADB shell rm -rf /data/adb /data/data/com.topjohnwu.magisk /data/local/tmp/su > /dev/null 2>&1
else
  skipnote "android emulator checks" "no emulator in 'device' state - run scripts/wsl-emulator.sh boot"
fi

hr "3. cross-ABI differential (needs out/rootdetect-x86)"
if [ -f "$PROJ/out/rootdetect-x86" ] && [ -f "$PROJ/scripts/wsl-abi-diff.sh" ]; then
  bash "$PROJ/scripts/wsl-abi-diff.sh" > "$RESULTS/abi-diff.txt" 2>&1
  rc=$?
  expect_abi_agree "abi differential ran and the ABIs agree" "$RESULTS/abi-diff.txt" "$rc"
else
  skipnote "abi differential" "build it with: powershell -ExecutionPolicy Bypass -File build/build.ps1 -Abi x86"
fi

hr "4. APK structure and embedded scanner hashes"
if [ -f "$PROJ/out/bunanana.apk" ]; then
  python3 "$PROJ/apk/check_apk.py" "$PROJ/out/bunanana.apk" > "$RESULTS/apk.txt" 2>&1
  expect_rc "apk: check_apk.py succeeded" 0 $?
  expect_regex "apk: dex declares MainActivity" "$RESULTS/apk.txt" 'MainActivity'
  python3 "$PROJ/apk/list_apk.py" "$PROJ/out/bunanana.apk" \
    "lib/arm64-v8a/librootdetect.so=$PROJ/out/rootdetect-arm64" \
    "lib/armeabi-v7a/librootdetect.so=$PROJ/out/rootdetect-arm" \
    "lib/x86_64/librootdetect.so=$PROJ/out/rootdetect-x86_64" > "$RESULTS/apk-hash.txt" 2>&1
  expect_rc "apk: list_apk.py succeeded" 0 $?
  expect_line "apk: embedded binaries match out/" "$RESULTS/apk-hash.txt" "embedded binaries verified: yes"
else
  bad "bunanana.apk present" "$PROJ/out/bunanana.apk is missing"
fi

hr "summary"
echo "  PASS=$pass  FAIL=$fail  SKIP=$skip"
echo "  raw outputs in $RESULTS"
[ "$fail" -eq 0 ]
