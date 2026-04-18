$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$hookDir = (& git -C $repoRoot rev-parse --git-path hooks).Trim()

if (-not $hookDir) {
  throw "Could not resolve the Git hooks directory for $repoRoot"
}

if (-not (Test-Path $hookDir)) {
  New-Item -ItemType Directory -Path $hookDir -Force | Out-Null
}

$preCommit = @'
#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"
exec bash ./precommit.sh --fast
'@

$prePush = @'
#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"
exec bash ./precommit.sh
'@

$utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText((Join-Path $hookDir "pre-commit"), $preCommit, $utf8NoBom)
[System.IO.File]::WriteAllText((Join-Path $hookDir "pre-push"), $prePush, $utf8NoBom)

Write-Host "Installed pre-commit and pre-push hooks for sdk-rust."