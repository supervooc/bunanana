# Create an AVD without Android Studio / avdmanager (no JDK needed).
# Everything stays inside the workspace: vendor/sdk (SDK), vendor/avd (AVDs),
# vendor/android-home (.android user dir).
#
#   pwsh -File scripts/setup-emulator.ps1                          # x86_64, API 30
#   pwsh -File scripts/setup-emulator.ps1 -Arch arm64-v8a -Name rootdetect-arm
param(
  [string]$Name = "rootdetect",
  [string]$Arch = "x86_64",     # x86_64 | arm64-v8a
  [int]$Api = 30,
  [int]$RamMb = 2048,
  [int]$Cores = 4
)
$ErrorActionPreference = "Stop"
$root    = Split-Path -Parent $PSScriptRoot
$sdk     = Join-Path $root "vendor\sdk"
$avdHome = Join-Path $root "vendor\avd"
$userHome= Join-Path $root "vendor\android-home"

# The emulator resolves AVDs/SDK through these; without them it looks in
# %USERPROFILE%\.android and reports "no AVDs".
$env:ANDROID_SDK_ROOT      = $sdk
$env:ANDROID_HOME          = $sdk
$env:ANDROID_AVD_HOME      = $avdHome
$env:ANDROID_USER_HOME     = $userHome
$env:ANDROID_EMULATOR_HOME = $userHome
$env:TEMP                  = Join-Path $root "vendor\tmp"
$env:TMP                   = $env:TEMP

if (-not (Test-Path (Join-Path $sdk "emulator\emulator.exe"))) { throw "emulator missing - run: node vendor/sdkpkg.mjs getall emulator" }

$imgBase = Join-Path $sdk "system-images\android-$Api\default"
$imgArch = Join-Path $imgBase $Arch
$cpuArch = if ($Arch -eq "x86_64") { "x86_64" } else { "arm64" }

# --- 1. system image -------------------------------------------------------
if (-not (Test-Path (Join-Path $imgArch "system.img"))) {
  $zip = Get-ChildItem (Join-Path $sdk "dl") -Filter "$Arch-$($Api)_r*.zip" | Select-Object -First 1
  if (-not $zip) { throw "system image zip for $Arch API $Api not found in vendor/sdk/dl" }
  Write-Host "extracting $($zip.Name) -> $imgBase"
  New-Item -ItemType Directory -Force -Path $imgBase | Out-Null
  tar -xf $zip.FullName -C $imgBase
  if (-not (Test-Path (Join-Path $imgArch "system.img"))) { throw "unexpected image layout" }
} else {
  Write-Host "system image already present: $imgArch"
}

# --- 2. AVD ----------------------------------------------------------------
New-Item -ItemType Directory -Force -Path $avdHome, $userHome, (Join-Path $avdHome "$Name.avd") | Out-Null

$config = @"
AvdId=$Name
avd.ini.displayname=$Name API $Api (AOSP $Arch)
avd.ini.encoding=UTF-8
abi.type=$Arch
hw.cpu.arch=$cpuArch
hw.cpu.ncore=$Cores
hw.ramSize=$RamMb
vm.heapSize=256
disk.dataPartition.size=6144M
disk.cachePartition.size=256M
image.sysdir.1=system-images/android-$Api/default/$Arch/
tag.id=default
tag.display=AOSP
target=android-$Api
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
hw.arc=false
hw.sdCard=no
fastboot.forceColdBoot=yes
"@
Set-Content -Path (Join-Path $avdHome "$Name.avd\config.ini") -Value $config -Encoding ASCII

$ini = @"
avd.ini.encoding=UTF-8
path=$avdHome\$Name.avd
path.rel=$Name.avd
target=android-$Api
"@
Set-Content -Path (Join-Path $avdHome "$Name.ini") -Value $ini -Encoding ASCII

Write-Host "AVD '$Name' created at $avdHome\$Name.avd ($Arch, API $Api)"
& (Join-Path $sdk "emulator\emulator.exe") -list-avds
