# Build rootdetect with the Android NDK, statically linked.
#
#   pwsh -File build/build.ps1                # x86_64 + arm64
#   pwsh -File build/build.ps1 -Abi x86_64    # emulator only
#
# Static linking is deliberate: the binary carries its own libc, so LD_PRELOAD,
# GOT patching and a hijacked linker cannot influence it - important for a tool
# whose job is to notice that userspace has been tampered with.
param(
  [string[]]$Abi = @("x86_64", "arm64"),
  [int]$Api = 24,
  [switch]$DebugBuild
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$ndk  = $env:ANDROID_NDK_HOME
if (-not $ndk) {
  $cand = Get-ChildItem (Join-Path $root "vendor\sdk") -Directory -Filter "android-ndk-*" -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($cand) { $ndk = $cand.FullName }
}
if (-not $ndk -or -not (Test-Path $ndk)) { throw "NDK not found; set ANDROID_NDK_HOME" }

$sysroot = Join-Path $ndk "toolchains\llvm\prebuilt\windows-x86_64"
$src     = Join-Path $root "src"
$out     = Join-Path $root "out"
New-Item -ItemType Directory -Force -Path $out | Out-Null
# clang writes its temp files into %TEMP%; under DSH's file sandbox that shared
# directory can end up unwritable ("unable to make temporary file"), so use a
# private one inside the workspace.
$env:TMP = Join-Path $root "vendor\tmp"
$env:TEMP = $env:TMP
New-Item -ItemType Directory -Force -Path $env:TMP | Out-Null

$sources = Get-ChildItem $src -Filter "*.c" | ForEach-Object { $_.FullName }

$triples = @{ "x86_64" = "x86_64-linux-android$Api"; "arm64" = "aarch64-linux-android$Api"; "arm" = "armv7a-linux-androideabi$Api"; "x86" = "i686-linux-android$Api" }

$opt = if ($DebugBuild) { @("-O0", "-g", "-DDEBUG") } else { @("-O2", "-DNDEBUG") }

foreach ($a in $Abi) {
  $t = $triples[$a]
  if (-not $t) { throw "unsupported abi: $a (use x86_64|arm64|arm|x86)" }
  $cc = Join-Path $sysroot "bin\$t-clang.cmd"
  if (-not (Test-Path $cc)) { throw "compiler wrapper missing: $cc" }
  $exe = Join-Path $out "rootdetect-$a"
  Write-Host "==> $a ($t)"
  $flags = @(
    "-std=gnu11", "-Wall", "-Wextra", "-Wno-unused-parameter",
    "-static", "-fno-ident", "-fvisibility=hidden",
    "-ffunction-sections", "-fdata-sections",
    "-Wl,--gc-sections", "-Wl,-z,noexecstack",
    "-o", $exe
  ) + $opt
  $cmd = "`"$cc`" $($flags -join ' ') $($sources -join ' ')"
  # Native compilers write warnings to stderr; with ErrorActionPreference=Stop
  # PowerShell would abort on the first warning, so relax it for this call and
  # judge success by the exit code instead.
  $prevEap = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  cmd /c "$cmd 2>&1" | ForEach-Object { Write-Host "$_" }
  $rc = $LASTEXITCODE
  $ErrorActionPreference = $prevEap
  if ($rc -ne 0) { throw "build failed for $a (exit $rc)" }
  $len = (Get-Item $exe).Length
  Write-Host ("    -> {0} ({1:N0} bytes)" -f $exe, $len)
}
Write-Host "done."
