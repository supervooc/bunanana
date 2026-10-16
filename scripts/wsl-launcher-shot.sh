#!/bin/bash
# Get a screenshot of the launcher showing the new icon + label, trying the
# several ways an AOSP launcher can be coaxed into showing the app drawer.
ADB=/opt/rx-android/platform-tools/adb
SRC=/mnt/c/Users/86134/Documents/deepseek-harness/default-workspace/android-rootdetect

check() {
  $ADB shell uiautomator dump /sdcard/l.xml >/dev/null 2>&1
  $ADB pull /sdcard/l.xml /tmp/l.xml >/dev/null 2>&1
  if grep -q 'bunanana' /tmp/l.xml; then
    echo "  drawer open, label found (via $1)"
    $ADB shell screencap -p /sdcard/d.png >/dev/null 2>&1
    $ADB pull /sdcard/d.png /tmp/d.png >/dev/null 2>&1
    cp /tmp/d.png "$SRC/out/launcher-apps.png"
    grep -o 'text="[^"]*bunanana[^"]*"' /tmp/l.xml | sort -u | head -3
    return 0
  fi
  return 1
}

$ADB shell input keyevent KEYCODE_HOME >/dev/null 2>&1
sleep 2
$ADB shell input swipe 540 1800 540 200 600 >/dev/null 2>&1
sleep 3
check "slow swipe" && exit 0
$ADB shell input keyevent 82 >/dev/null 2>&1
sleep 3
check "menu key" && exit 0
$ADB shell input swipe 540 1500 540 300 120 >/dev/null 2>&1
sleep 3
check "fast swipe" && exit 0
echo "  app drawer did not open on this launcher - icon wiring is verified by aapt2 badging instead"
