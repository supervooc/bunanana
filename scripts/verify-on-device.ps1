# One-command verification of rootdetect on a connected device.
#
#   pwsh -File scripts/verify-on-device.ps1                 # first device
#   pwsh -File scripts/verify-on-device.ps1 -Serial <sn>
#
# What it does
#   1. picks the right build for the device ABI and pushes it (plus the other-ABI
#      build, so the cross-ABI differential check can run)
#   2. runs --selftest            (logic + false-positive guards)
#   3. runs the detector as the `shell` user  -> out/report-shell.json
#   4. tries `adb root` and runs it again     -> out/report-root.json
#   5. prints a side-by-side summary of the findings
param([string]$Serial = "")
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
$adb  = Join-Path $root "vendor\sdk\platform-tools\adb.exe"
$env:TEMP = Join-Path $root "vendor\tmp"
$env:TMP  = $env:TEMP
New-Item -ItemType Directory -Force -Path $env:TEMP, (Join-Path $root "out") | Out-Null

$target = @()
if ($Serial) { $target = @("-s", $Serial) }
function A { param([Parameter(ValueFromRemainingArguments = $true)]$a) & $adb @target @a 2>&1 }

$devices = (& $adb devices) -split "`n" | Where-Object { $_ -match "\tdevice$" }
if (-not $devices) { Write-Error "no device in 'device' state. `adb devices` says:`n$(& $adb devices)"; exit 1 }
Write-Host "device: $($devices[0].Trim())"

$abi = (A shell getprop ro.product.cpu.abi | Out-String).Trim()
$abi2 = (A shell getprop ro.product.cpu.abi2 | Out-String).Trim()
Write-Host "abi=$abi abi2=$abi2"

$binMap = @{ "arm64-v8a" = "rootdetect-arm64"; "armeabi-v7a" = "rootdetect-arm"; "armeabi" = "rootdetect-arm"; "x86_64" = "rootdetect-x86_64"; "x86" = "rootdetect-x86" }
$primary = $binMap[$abi]
if (-not $primary) { Write-Error "unsupported ABI '$abi'"; exit 1 }
$others = $binMap.Values | Where-Object { $_ -ne $primary } | Select-Object -Unique

$remote = "/data/local/tmp/rx"
Write-Host "pushing $primary -> $remote"
A push (Join-Path $root "out\$primary") $remote | Out-Null
A shell chmod 755 $remote | Out-Null
foreach ($o in $others) {
  $p = Join-Path $root "out\$o"
  if (Test-Path $p) {
    Write-Host "pushing $o -> /data/local/tmp/$o (for the cross-ABI check)"
    A push $p "/data/local/tmp/$o" | Out-Null
    A shell chmod 755 "/data/local/tmp/$o" | Out-Null
  }
}

Write-Host "`n=== 1. self-test ==="
A shell "$remote --selftest" | ForEach-Object { Write-Host $_ }

function Report($label, $file) {
  Write-Host "`n=== $label ==="
  $json = A shell "$remote --json"
  ($json -join "`n") | Set-Content -Path (Join-Path $root "out\$file") -Encoding UTF8
  $text = A shell "$remote -v"
  ($text -join "`n") | ForEach-Object { Write-Host $_ }
  Write-Host "(saved: out\$file)"
}

Report "2. as the shell user (app-equivalent view)" "report-shell.json"

Write-Host "`n=== 3. adb root, then again with uid 0 (deep kernel checks) ==="
$rootOut = (A root | Out-String)
Write-Host $rootOut.Trim()
Start-Sleep -Seconds 3
$id = (A shell id | Out-String).Trim()
Write-Host "now: $id"
if ($id -match "uid=0") {
  Report "3. as uid 0" "report-root.json"
} else {
  Write-Host "`nadb root unavailable (production build or adbd not rootable): the deep-* checks"
  Write-Host "will have reported themselves as skipped. Run through 'su' instead if the device"
  Write-Host "is actually rooted:   su -c '$remote -v'"
}

Write-Host "`n=== 4. what the two runs disagree about ==="
$a1 = Join-Path $root "out\report-shell.json"
$a2 = Join-Path $root "out\report-root.json"
if ((Test-Path $a1) -and (Test-Path $a2)) {
  try {
    $j1 = Get-Content $a1 -Raw | ConvertFrom-Json
    $j2 = Get-Content $a2 -Raw | ConvertFrom-Json
    Write-Host ("shell verdict : {0}  ({1} critical / {2} high)" -f $j1.verdict, $j1.summary.critical, $j1.summary.high)
    Write-Host ("root  verdict : {0}  ({1} critical / {2} high)" -f $j2.verdict, $j2.summary.critical, $j2.summary.high)
    $ids1 = $j1.findings | ForEach-Object { $_.id }
    $onlyRoot = $j2.findings | Where-Object { $ids1 -notcontains $_.id }
    if ($onlyRoot) {
      Write-Host "`nfindings only visible with uid 0:"
      $onlyRoot | ForEach-Object { Write-Host ("  [{0}] {1}" -f $_.severity, $_.id) }
    } else {
      Write-Host "`n(no additional findings with uid 0)"
    }
  } catch { Write-Warning "could not compare reports: $($_.Exception.Message)" }
}
Write-Host "`ndone."
