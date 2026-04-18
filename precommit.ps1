param(
  [switch]$Fast
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

Write-Host "sdk-rust local quality gate"

function Get-Tool {
  param([string]$Name)

  $command = Get-Command $Name -ErrorAction SilentlyContinue
  if ($command) {
    return $command.Source
  }

  $command = Get-Command "$Name.exe" -ErrorAction SilentlyContinue
  if ($command) {
    return $command.Source
  }

  return $null
}

function Invoke-OptionalTool {
  param(
    [string]$Name,
    [string]$Description,
    [string[]]$Arguments
  )

  $tool = Get-Tool $Name
  if (-not $tool) {
    Write-Host " - Skipping $Description (missing $Name)"
    return
  }

  Write-Host " - $Description"
  & $tool @Arguments
  if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
  }
}

$cargo = Get-Tool cargo
if (-not $cargo) {
  throw "cargo is required for sdk-rust quality checks."
}

$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
$env:CARGO_INCREMENTAL = "0"

try {
  Write-Host "1) Apply automated fixes"
  & $cargo fix --all-targets --all-features --allow-dirty --allow-staged
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  & $cargo fmt --all
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

  Write-Host "2) Lint and correctness"
  & $cargo fmt --all --check
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  & $cargo clippy --all-targets --all-features -- -D warnings
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

  Write-Host "3) Security scans"
  Invoke-OptionalTool -Name semgrep -Description "SAST via Semgrep" -Arguments @("--config=auto", "--exclude", ".git", "--exclude", "target", "--exclude", "dist", "--exclude", ".venv", ".")
  Invoke-OptionalTool -Name gitleaks -Description "Secret scanning via Gitleaks" -Arguments @("detect", "--source", ".", "--no-git", "--redact")
  if (-not $Fast) {
    Invoke-OptionalTool -Name cargo-audit -Description "Dependency audit via cargo-audit" -Arguments @("audit")
    Invoke-OptionalTool -Name trivy -Description "Filesystem security scan via Trivy" -Arguments @("fs", "--scanners", "vuln,misconfig,secret", "--severity", "HIGH,CRITICAL", "--exit-code", "1", ".")
  } else {
    Write-Host " - Fast mode: skipping cargo-audit and Trivy"
  }

  Write-Host "4) Tests"
  & $cargo test --all-targets --all-features
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

  Write-Host "5) Build"
  & $cargo build --release
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

  Write-Host "All checks passed."
}
finally {
  Write-Host "6) Cleanup"
  & $cargo clean *> $null
}