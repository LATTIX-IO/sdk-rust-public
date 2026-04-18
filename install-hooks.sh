#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK_DIR="$(git -C "$REPO_ROOT" rev-parse --git-path hooks)"

if [[ -z "$HOOK_DIR" ]]; then
  echo "Could not resolve the Git hooks directory for $REPO_ROOT" >&2
  exit 1
fi

mkdir -p "$HOOK_DIR"

cat >"$HOOK_DIR/pre-commit" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"
exec bash ./precommit.sh --fast
EOF

cat >"$HOOK_DIR/pre-push" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"
exec bash ./precommit.sh
EOF

chmod +x "$HOOK_DIR/pre-commit" "$HOOK_DIR/pre-push"
echo "Installed pre-commit and pre-push hooks for sdk-rust."