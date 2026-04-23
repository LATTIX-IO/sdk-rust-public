#!/usr/bin/env bash
set -euo pipefail

FAST=false

for arg in "$@"; do
  case "$arg" in
    --fast)
      FAST=true
      ;;
    -h|--help)
      cat <<'EOF'
Usage: ./precommit.sh [--fast]

  --fast   Skip heavier security scans and release-build packaging steps.
EOF
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      exit 1
      ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

echo "sdk-rust local quality gate"

find_cmd() {
  local cmd="$1"
  if command -v "$cmd" >/dev/null 2>&1; then
    command -v "$cmd"
    return 0
  fi
  if command -v "${cmd}.exe" >/dev/null 2>&1; then
    command -v "${cmd}.exe"
    return 0
  fi
  return 1
}

trivy_version_for() {
  local trivy_bin="$1"
  local version_output

  version_output="$("$trivy_bin" --version 2>/dev/null || "$trivy_bin" version 2>/dev/null || true)"
  if [[ "$version_output" =~ ([0-9]+\.[0-9]+\.[0-9]+) ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
  fi
}

ensure_safe_trivy_version() {
  local trivy_bin="$1"
  local version

  version="$(trivy_version_for "$trivy_bin")"
  if [[ -z "$version" ]]; then
    echo " - Refusing to run Trivy because its version could not be determined." >&2
    echo "   Install a known-safe Trivy release such as v0.69.3 or v0.69.2." >&2
    return 1
  fi

  case "$version" in
    0.69.4|0.69.5|0.69.6)
      echo " - Refusing to run compromised Trivy $version (GHSA-69fq-xp46-6x23 / CVE-2026-33634)." >&2
      echo "   Install Trivy v0.69.3 or v0.69.2 before re-running precommit." >&2
      return 1
      ;;
  esac
}

run_if_available() {
  local cmd="$1"
  local desc="$2"
  shift 2
  local cmd_bin
  if cmd_bin="$(find_cmd "$cmd")"; then
    if [[ "$cmd" == "trivy" ]]; then
      ensure_safe_trivy_version "$cmd_bin"
    fi
    echo " - $desc"
    "$cmd_bin" "$@"
  else
    echo " - Skipping $desc (missing $cmd)"
  fi
}

cleanup() {
  if CARGO_BIN="$(find_cmd cargo)"; then
    echo "6) Cleanup"
    "$CARGO_BIN" clean >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT

if ! CARGO_BIN="$(find_cmd cargo)"; then
  echo "cargo is required for sdk-rust quality checks." >&2
  exit 1
fi

export PYTHONUTF8=1
export PYTHONIOENCODING=UTF-8
export CARGO_INCREMENTAL=0

echo "1) Apply automated fixes"
"$CARGO_BIN" fix --all-targets --all-features --allow-dirty --allow-staged
"$CARGO_BIN" fmt --all

echo "2) Lint and correctness"
"$CARGO_BIN" fmt --all --check
"$CARGO_BIN" clippy --all-targets --all-features -- -D warnings

echo "3) Security scans"
run_if_available semgrep "SAST via Semgrep" --config=auto --exclude .git --exclude target --exclude dist --exclude .venv .
run_if_available gitleaks "Secret scanning via Gitleaks" detect --source . --no-git --redact
if [[ "$FAST" == false ]]; then
  run_if_available cargo-audit "Dependency audit via cargo-audit" audit
  run_if_available trivy "Filesystem security scan via Trivy" fs --scanners vuln,misconfig,secret --severity HIGH,CRITICAL --exit-code 1 .
else
  echo " - Fast mode: skipping cargo-audit and Trivy"
fi

echo "4) Tests"
"$CARGO_BIN" test --all-targets --all-features

echo "5) Build"
"$CARGO_BIN" build --release

echo "All checks passed."