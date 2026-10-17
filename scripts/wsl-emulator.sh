#!/bin/bash
# Set up / boot the Android emulator inside WSL2, where /dev/kvm is available.
#
#   sudo wsl -u root -e bash .../wsl-emulator.sh setup
#   wsl -u root -e bash .../wsl-emulator.sh avd
#   wsl -u root -e bash .../wsl-emulator.sh boot
#   wsl -u root -e bash .../wsl-emulator.sh status
set -u
SRC=/mnt/c/Users/86134/Documents/deepseek-harness/default-workspace/android-rootdetect
DEST=/opt/rx-android
export ANDROID_SDK_ROOT=$DEST
export ANDROID_HOME=$DEST
export ANDROID_AVD_HOME=$DEST/avd
export ANDROID_USER_HOME=$DEST/userhome
export ANDROID_EMULATOR_HOME=$DEST/userhome
AVD=rx

unzip_py() { python3 -c "import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" "$1" "$2"; }

setup() {
  mkdir -p "$DEST" "$ANDROID_AVD_HOME" "$ANDROID_USER_HOME"
  local emu_zip pt_zip
  emu_zip=$(ls "$SRC"/vendor/sdk/dl/emulator-linux_x64-*.zip | head -1)
  pt_zip=$(ls "$SRC"/vendor/sdk/dl/platform-tools_r*-linux.zip | head -1)

  if [ ! -x "$DEST/emulator/emulator" ]; then
    echo "== extracting $(basename "$emu_zip")"
    unzip_py "$emu_zip" "$DEST"
  fi
  chmod +x "$DEST"/emulator/emulator "$DEST"/emulator/qemu/linux-x86_64/* 2>/dev/null

  if [ ! -x "$DEST/platform-tools/adb" ]; then
    echo "== extracting $(basename "$pt_zip")"
    unzip_py "$pt_zip" "$DEST"
  fi
  chmod +x "$DEST"/platform-tools/adb

  if [ ! -f "$DEST/system-images/android-30/default/x86_64/system.img" ]; then
    echo "== copying the system image (already downloaded for Windows)"
    mkdir -p "$DEST/system-images/android-30/default"
    cp -r "$SRC/vendor/sdk/system-images/android-30/default/x86_64" "$DEST/system-images/android-30/default/"
  fi

  echo "== emulator"
  "$DEST/emulator/emulator" -version 2>&1 | head -4
  echo "== missing shared libraries"
  for b in "$DEST/emulator/emulator" "$DEST/emulator/qemu/linux-x86_64/qemu-system-x86_64-headless"; do
    [ -e "$b" ] || continue
    miss=$(ldd "$b" 2>/dev/null | grep "not found" | awk '{print $1}' | sort -u | tr '\n' ' ')
    echo "   $(basename "$b"): ${miss:-none}"
  done
  echo "== kvm"
  ls -l /dev/kvm 2>&1
}

make_avd() {
  mkdir -p "$ANDROID_AVD_HOME/$AVD.avd"
  cat > "$ANDROID_AVD_HOME/$AVD.avd/config.ini" <<EOF
AvdId=$AVD
avd.ini.displayname=$AVD (AOSP API 30 x86_64, KVM)
avd.ini.encoding=UTF-8
abi.type=x86_64
hw.cpu.arch=x86_64
hw.cpu.ncore=4
hw.ramSize=2048
vm.heapSize=256
disk.dataPartition.size=2048M
disk.cachePartition.size=256M
image.sysdir.1=system-images/android-30/default/x86_64/
tag.id=default
tag.display=AOSP
target=android-30
PlayStore.enabled=false
hw.gpu.enabled=no
hw.gpu.mode=off
hw.keyboard=yes
hw.mainKeys=no
hw.lcd.density=420
hw.lcd.width=1080
hw.lcd.height=1920
hw.audioInput=no
hw.audioOutput=no
hw.camera.back=none
hw.camera.front=none
hw.sdCard=no
fastboot.forceColdBoot=yes
EOF
  cat > "$ANDROID_AVD_HOME/$AVD.ini" <<EOF
avd.ini.encoding=UTF-8
path=$ANDROID_AVD_HOME/$AVD.avd
path.rel=$AVD.avd
target=android-30
EOF
  "$DEST/emulator/emulator" -list-avds
}

boot() {
  # Log inside WSL: a Windows-side ">" redirection cannot address /tmp.
  exec "$DEST/emulator/emulator" -avd "$AVD" -accel on -no-window \
    -gpu off -no-audio -no-boot-anim -no-snapshot -no-metrics -verbose \
    > /tmp/emulator.log 2>&1
}

status() {
  export PATH="$DEST/platform-tools:$PATH"
  adb devices -l
  adb shell getprop sys.boot_completed 2>&1
}

case "${1:-}" in
  setup) setup ;;
  avd) make_avd ;;
  boot) boot ;;
  status) status ;;
  *) echo "usage: $0 setup|avd|boot|status"; exit 2 ;;
esac
