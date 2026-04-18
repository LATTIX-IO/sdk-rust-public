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

run_if_available() {
  local cmd="$1"
  local desc="$2"
  shift 2
  local cmd_bin
  if cmd_bin="$(find_cmd "$cmd")"; then
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