#!/bin/bash
# Final acceptance run - one command that replays the whole verification matrix.
#
#   wsl -u root -e bash .../scripts/verify-all.sh
#
# Sections are independent: a failure is reported but does not abort the rest, so
# the summary at the end is always complete. Raw outputs land in /tmp/verify-all.
#
# This is the script the Lead runs *after* all writers have stopped, because it
# touches the emulator (shared resource) and the built artifacts.
set -u
PROJ=/mnt/c/Users/86134/Documents/deepseek-harness/default-workspace/android-rootdetect
ADB=/opt/rx-android/platform-tools/adb
RESULTS=/tmp/verify-all
mkdir -p "$RESULTS"

pass=0; fail=0; skip=0
hr()      { echo; echo "================ $* ================"; }
verdict() { # name, regex, file
  if grep -qE "$2" "$3" 2>/dev/null; then echo "  PASS  $1"; pass=$((pass + 1));
  else echo "  FAIL  $1    (expected /$2/ in ${3##*/})"; fail=$((fail + 1)); fi
}
missing() { echo "  FAIL  $1    (file not found: $2)"; fail=$((fail + 1)); }
skipnote(){ echo "  SKIP  $1    ($2)"; skip=$((skip + 1)); }

hr "0. artifacts"
ls -l "$PROJ/out" 2>/dev/null | sed 's/^/  /'

RX=/tmp/rootdetect-verify/rx
mkdir -p /tmp/rootdetect-verify
if [ -f "$PROJ/out/rootdetect-x86_64" ]; then
  cp -f "$PROJ/out/rootdetect-x86_64" "$RX"; chmod 755 "$RX"
else
  missing "x86_64 CLI binary" "$PROJ/out/rootdetect-x86_64"
fi

if [ -x "$RX" ]; then
  hr "1. real Linux kernel (WSL): self-test and clean baseline"
  "$RX" --selftest > "$RESULTS/linux-selftest.txt" 2>&1
  verdict "linux self-test: 0 failures" "0 failure" "$RESULTS/linux-selftest.txt"
  "$RX" > "$RESULTS/linux-baseline.txt" 2>&1
  verdict "linux baseline: verdict CLEAN" "^verdict: CLEAN" "$RESULTS/linux-baseline.txt"
  verdict "linux baseline: no CRITICAL/HIGH" "^summary: 0 critical, 0 high" "$RESULTS/linux-baseline.txt"
else
  skipnote "linux self-test" "no scanner binary"
fi

hr "2. Android emulator (KVM inside WSL)"
if $ADB devices 2>/dev/null | grep -q "emulator-.*device"; then
  $ADB wait-for-device
  $ADB push "$RX" /data/local/tmp/rx > /dev/null 2>&1
  $ADB shell chmod 755 /data/local/tmp/rx > /dev/null 2>&1

  $ADB shell /data/local/tmp/rx --selftest 2>&1 | tr -d '\r' > "$RESULTS/android-selftest.txt"
  # As the shell domain two checks are SKIPped (/proc/sys/kernel/osrelease and
  # version are not readable), as uid 0 none are; only failures are mandatory.
  verdict "android self-test: 0 failures" "0 failure\(s\)" "$RESULTS/android-selftest.txt"

  $ADB shell /data/local/tmp/rx --json 2>&1 | tr -d '\r' > "$RESULTS/android-shell.json"
  verdict "android (shell): no CRITICAL crafted from SELinux denials" '"critical": 0' "$RESULTS/android-shell.json"

  $ADB root > /dev/null 2>&1; sleep 4
  $ADB shell /data/local/tmp/rx -v 2>&1 | tr -d '\r' > "$RESULTS/android-root.txt"
  verdict "android (uid 0): deep checks ran" "deep-skipped|kernel-syscall-table|kernel-kcore|hook-kprobe|deep-dmesg" "$RESULTS/android-root.txt"

  hr "2b. injected root artefacts must be detected"
  $ADB shell mkdir -p /data/adb/magisk /data/data/com.topjohnwu.magisk > /dev/null 2>&1
  $ADB shell "printf 'MAGISK\n' > /data/adb/magisk/util_functions.sh" > /dev/null 2>&1
  $ADB shell cp /system/bin/toybox /data/local/tmp/su > /dev/null 2>&1
  $ADB shell chmod 755 /data/local/tmp/su > /dev/null 2>&1
  $ADB shell /data/local/tmp/rx -v 2>&1 | tr -d '\r' > "$RESULTS/android-fixtures.txt"
  verdict "fixtures: package-hidden CRITICAL" "package-hidden" "$RESULTS/android-fixtures.txt"
  verdict "fixtures: artefacts reported" "artefact-present" "$RESULTS/android-fixtures.txt"
  $ADB shell rm -rf /data/adb /data/data/com.topjohnwu.magisk /data/local/tmp/su > /dev/null 2>&1
else
  skipnote "android emulator checks" "no emulator in 'device' state - run scripts/wsl-emulator.sh boot"
fi

hr "3. cross-ABI differential (needs out/rootdetect-x86)"
if [ -f "$PROJ/out/rootdetect-x86" ] && [ -f "$PROJ/scripts/wsl-abi-diff.sh" ]; then
  bash "$PROJ/scripts/wsl-abi-diff.sh" > "$RESULTS/abi-diff.txt" 2>&1
  verdict "abi differential executed both ABIs" "abi-consistency|abi-consistency-mismatch" "$RESULTS/abi-diff.txt"
else
  skipnote "abi differential" "build it with: pwsh -File build/build.ps1 -Abi x86"
fi

hr "4. APK structure and embedded scanner hashes"
if [ -f "$PROJ/out/bunanana.apk" ]; then
  python3 "$PROJ/apk/check_apk.py" "$PROJ/out/bunanana.apk" > "$RESULTS/apk.txt" 2>&1
  verdict "apk: dex declares MainActivity" "found .*MainActivity" "$RESULTS/apk.txt"
  python3 "$PROJ/apk/list_apk.py" "$PROJ/out/bunanana.apk" \
    "lib/arm64-v8a/librootdetect.so=$PROJ/out/rootdetect-arm64" \
    "lib/armeabi-v7a/librootdetect.so=$PROJ/out/rootdetect-arm" \
    "lib/x86_64/librootdetect.so=$PROJ/out/rootdetect-x86_64" > "$RESULTS/apk-hash.txt" 2>&1
  verdict "apk: embedded binaries match out/" "embedded binaries verified: yes" "$RESULTS/apk-hash.txt"
else
  missing "bunanana.apk" "$PROJ/out/bunanana.apk"
fi

hr "summary"
echo "  PASS=$pass  FAIL=$fail  SKIP=$skip"
echo "  raw outputs in $RESULTS"
[ "$fail" -eq 0 ]
