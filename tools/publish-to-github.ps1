# Publish bunanana to GitHub using the already-authenticated gh CLI as the
# transport: no git, no token handling in this script, and no TLS bypass -
# gh uses the credential in the user's keyring.
#
#   powershell -ExecutionPolicy Bypass -File tools/publish-to-github.ps1 -DryRun
#   powershell -ExecutionPolicy Bypass -File tools/publish-to-github.ps1 -Visibility public
#
# Uploads sources, scripts, docs, the APK and the evidence images/reports through
# the Git Data API (blob -> tree -> commit -> ref) so the whole thing lands as one
# commit. vendor/ (multi-GB toolchains) and out/rootdetect-* (reproducible build
# output) are excluded; see .gitignore.
param(
  [string]$Repo = "bunanana",
  [ValidateSet("public", "private")][string]$Visibility = "public",
  [string]$Description = "bunanana - Android root / root-hiding detector (static native scanner + APK)",
  [switch]$DryRun
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$rootFull = (Resolve-Path $root).Path

$gh = @(
  "$env:LOCALAPPDATA\Microsoft\WinGet\Links\gh.exe",
  (Join-Path $env:ProgramFiles "GitHub CLI\gh.exe")
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $gh) { $c = Get-Command gh -ErrorAction SilentlyContinue; if ($c) { $gh = $c.Source } }
if (-not $gh) { throw "gh CLI not found - install it or download the repo manually" }

# Shared %TEMP% is not reliably writable here; request bodies go next to the build.
$env:TMP = Join-Path $root "vendor\tmp"
$env:TEMP = $env:TMP
New-Item -ItemType Directory -Force -Path $env:TMP | Out-Null
$work = Join-Path $env:TMP "gh-publish"
Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $work | Out-Null
$utf8 = New-Object System.Text.UTF8Encoding($false)

function Gh([string[]]$a) {
  # Native commands write warnings/errors to stderr, and with
  # ErrorActionPreference=Stop PowerShell would turn "repository does not exist
  # yet" into a terminating error before we can look at the exit code.
  $prev = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  $out = & $gh @a 2>&1
  $code = $LASTEXITCODE
  $ErrorActionPreference = $prev
  if ($code -ne 0) { throw ("gh " + ($a -join ' ') + "`n" + ($out -join "`n")) }
  return $out
}

function GhOk([string[]]$a) {
  $prev = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  & $gh @a *> $null
  $code = $LASTEXITCODE
  $ErrorActionPreference = $prev
  return ($code -eq 0)
}

$login = (Gh @("api", "user", "--jq", ".login")) | Select-Object -Last 1
Write-Host "account : $login"
Write-Host "target  : $login/$Repo ($Visibility)"

# ---------------------------------------------------------------- file list ---
$files = New-Object System.Collections.Generic.List[object]
function AddFile([string]$p) {
  $full = (Resolve-Path $p).Path
  if (-not $full.StartsWith($rootFull + '\')) { return }
  $rel = $full.Substring($rootFull.Length + 1) -replace '\\', '/'
  if ($script:files.rel -contains $rel) { return }
  $script:files.Add([pscustomobject]@{ abs = $full; rel = $rel; size = (Get-Item $full).Length })
}

foreach ($f in @('README.md', 'README.zh-CN.md', '.gitignore')) {
  $p = Join-Path $root $f
  if (Test-Path $p) { AddFile $p }
}
foreach ($d in @('src', 'apk', 'scripts', 'review', 'tools')) {
  $p = Join-Path $root $d
  if (Test-Path $p) { Get-ChildItem $p -Recurse -File | ForEach-Object { AddFile $_.FullName } }
}
Get-ChildItem (Join-Path $root 'build') -File -Filter *.ps1 -ErrorAction SilentlyContinue |
  ForEach-Object { AddFile $_.FullName }
Get-ChildItem (Join-Path $root 'out') -File -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match '\.(apk|png|txt)$' } |
  ForEach-Object { AddFile $_.FullName }

$files = @($files | Sort-Object rel)
$total = ($files | Measure-Object -Property size -Sum).Sum
Write-Host ("`nfiles   : {0}  ({1:N1} MB)" -f $files.Count, ($total / 1MB))
foreach ($f in $files) { Write-Host ("  {0,9:N0} B  {1}" -f $f.size, $f.rel) }
if ($DryRun) { Write-Host "`n(dry run - nothing uploaded)"; exit 0 }

# ------------------------------------------------------------- create repo ----
if (-not (GhOk @("repo", "view", "$login/$Repo", "--json", "name"))) {
  Gh @("repo", "create", "$login/$Repo", "--$Visibility", "--description", $Description) | Out-Null
  Write-Host "`nrepository created"
} else {
  Write-Host "`nrepository exists - adding a commit to it"
}

# ------------------------------------------------------------------- upload ---
Write-Host "`nuploading blobs through the Git Data API..."

# A brand-new repository has no commits and the Git Data API refuses to create
# blobs in it ("409 Git Repository is empty"), so seed one commit through the
# Contents API first. The real commit below is created with no parent and force
# points main at it, which leaves a single clean commit and drops the seed file.
if (-not (GhOk @("api", "/repos/$login/$Repo/contents/"))) {
  $bootstrap = Join-Path $work "bootstrap.json"
  $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("# seed`n"))
  [IO.File]::WriteAllText($bootstrap, (@{ message = "seed"; content = $b64; branch = "main" } |
    ConvertTo-Json -Compress), $utf8)
  Gh @("api", "--method", "PUT", "/repos/$login/$Repo/contents/.seed", "--input", $bootstrap) | Out-Null
  Write-Host "seed commit created (the Git Data API needs a non-empty repository)"
}

$tree = New-Object System.Collections.Generic.List[object]
$n = 0
foreach ($f in $files) {
  $n++
  $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($f.abs))
  $body = Join-Path $work "blob.json"
  [IO.File]::WriteAllText($body, (@{ content = $b64; encoding = "base64" } | ConvertTo-Json -Compress), $utf8)
  $sha = (Gh @("api", "--method", "POST", "/repos/$login/$Repo/git/blobs", "--input", $body, "--jq", ".sha")) |
    Select-Object -Last 1
  $tree.Add(@{ path = $f.rel; mode = "100644"; type = "blob"; sha = $sha })
  Write-Host ("  [{0,2}/{1}] {2}" -f $n, $files.Count, $f.rel)
}

$treeBody = Join-Path $work "tree.json"
[IO.File]::WriteAllText($treeBody, (@{ tree = $tree } | ConvertTo-Json -Depth 6 -Compress), $utf8)
$treeSha = (Gh @("api", "--method", "POST", "/repos/$login/$Repo/git/trees", "--input", $treeBody, "--jq", ".sha")) |
  Select-Object -Last 1
Write-Host "tree    : $treeSha"

$message = @"
bunanana: Android root / root-hiding detector (native scanner + APK)

Engine rootdetect, C11, statically linked, no third-party dependencies.

* conventional checks: su binaries, Magisk/KernelSU/APatch layout, root manager
  packages, build/AVB state, mounts, injected libraries
* cross-view detection: 7 syscalls per path (stat/statx/fstatat/access/open/
  openat/getdents) plus four mount views must agree - a hide module hooks a
  subset of the interfaces and its blind spots are the evidence
* kernel checks (uid 0): taint flags, module lists cross-checked against
  kallsyms tags, kprobe/tracefs, sys_call_table through /proc/kcore, dmesg
* SuSFS-specific: uname vs /proc/version, open-redirect via dev/ino, cmdline vs
  ro.boot.* (cmdline + bootconfig), /proc/susfs_* nodes, cross-ABI differential

Verified on WSL (real kernel) and on an API 30 x86_64 emulator with KVM:
77 self-test checks on device, injected fixtures detected, 11/11 acceptance
checks green. 16 red-team findings fixed (see README section 11.6).
"@
$commitBody = Join-Path $work "commit.json"
[IO.File]::WriteAllText($commitBody, (@{ message = $message; tree = $treeSha; parents = @() } |
  ConvertTo-Json -Depth 5 -Compress), $utf8)
$commitSha = (Gh @("api", "--method", "POST", "/repos/$login/$Repo/git/commits", "--input", $commitBody, "--jq", ".sha")) |
  Select-Object -Last 1
Write-Host "commit  : $commitSha"

if (GhOk @("api", "/repos/$login/$Repo/git/ref/heads/main", "--jq", ".object.sha")) {
  Gh @("api", "--method", "PATCH", "/repos/$login/$Repo/git/refs/heads/main", "-f", "sha=$commitSha", "-F", "force=true") | Out-Null
  Write-Host "ref     : refs/heads/main updated"
} else {
  Gh @("api", "--method", "POST", "/repos/$login/$Repo/git/refs", "-f", "ref=refs/heads/main", "-f", "sha=$commitSha") | Out-Null
  Write-Host "ref     : refs/heads/main created"
}
Gh @("api", "--method", "PATCH", "/repos/$login/$Repo", "-f", "description=$Description", "-f", "default_branch=main") | Out-Null
if (GhOk @("repo", "edit", "$login/$Repo", "--add-topic", "android", "--add-topic", "root-detection",
           "--add-topic", "security-tools", "--add-topic", "reverse-engineering")) {
  Write-Host "topics  : android, root-detection, security-tools, reverse-engineering"
}

Write-Host "`ndone: https://github.com/$login/$Repo"
