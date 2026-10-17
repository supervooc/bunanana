#!/bin/bash
# Install and actually exercise the APK on the emulator running inside WSL.
#
#   wsl -u root -e bash .../scripts/wsl-apk-test.sh
#
# This closes the last unverified gap: does the packaged app really manage to
# execute its bundled static scanner on Android?
set -u
SRC=/mnt/c/Users/86134/Documents/deepseek-harness/default-workspace/android-rootdetect
ADB=/opt/rx-android/platform-tools/adb
APK=$SRC/out/bunanana.apk
hr() { echo; echo "================ $* ================"; }

hr "device"
$ADB devices -l
$ADB wait-for-device
echo "boot_completed=$($ADB shell getprop sys.boot_completed | tr -d '\r')"
echo "abi=$($ADB shell getprop ro.product.cpu.abi | tr -d '\r')"

hr "install"
install_out=$($ADB install -r -t "$APK" 2>&1)
echo "$install_out" | tail -2
case "$install_out" in
  *Success*) ;;
  *)
    echo "  update rejected (signing key changed?) - uninstalling and retrying"
    $ADB uninstall com.rootdetect.app >/dev/null 2>&1
    $ADB install -t "$APK" 2>&1 | tail -2
    ;;
esac

hr "package layout"
$ADB shell pm path com.rootdetect.app
$ADB shell dumpsys package com.rootdetect.app 2>/dev/null |
  grep -E 'primaryCpuAbi|nativeLibraryDir|targetSdk|versionName' | head -6
echo "-- extracted native libs --"
$ADB shell 'd=$(pm path com.rootdetect.app | head -1 | sed "s/package://;s#/base.apk##"); ls -l $d/lib/*/ 2>/dev/null' | head -6

hr "launch the activity"
$ADB logcat -c 2>/dev/null
$ADB shell am start -n com.rootdetect.app/.MainActivity 2>&1 | tail -3
sleep 15

hr "logcat: app messages, crashes and SELinux denials"
$ADB logcat -d -v brief 2>&1 | grep -iE 'rootdetect|AndroidRuntime|avc: *denied' | head -25

hr "process"
$ADB shell "ps -A | grep rootdetect" || echo "  (no matching process)"

hr "screenshot of the app"
if $ADB shell screencap -p /sdcard/rx.png && $ADB pull /sdcard/rx.png /tmp/rx.png >/dev/null 2>&1; then
  cp /tmp/rx.png "$SRC/out/apk-screenshot.png"
  echo "saved: out/apk-screenshot.png ($(stat -c%s /tmp/rx.png) bytes)"
else
  echo "screencap failed"
fi

hr "can the app's native dir be executed at all? (selinux + permissions)"
$ADB shell 'd=$(pm path com.rootdetect.app | head -1 | sed "s/package://;s#/base.apk##"); ls -lZ $d/lib/x86_64/librootdetect.so 2>/dev/null; echo "--- try running it as shell:"; $d/lib/x86_64/librootdetect.so --selftest 2>&1 | head -5'
