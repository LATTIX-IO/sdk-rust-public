---
tracker:
  kind: linear
  endpoint: https://api.linear.app/graphql
  api_key: $LINEAR_API_KEY
  project_slug: "289d946064d4"
  active_states:
    - Todo
    - In Progress
  exclude_labels:
    - epic
  terminal_states:
    - Closed
    - Cancelled
    - Canceled
    - Duplicate
    - Done
polling:
  interval_ms: 30000
workspace:
  root: "D:/lattix/.symphony/workspaces/sdk-rust-public"
hooks:
  timeout_ms: 120000
  after_create: |
    set -euo pipefail
    git clone --recurse-submodules --branch "main" "https://github.com/LATTIX-IO/sdk-rust-public.git" .
  before_run: |
    set -euo pipefail
    if [ -d .git ] && [ -z "$(git status --porcelain)" ]; then
      git fetch --all --prune
      git pull --ff-only || true
    fi
  after_run: |
    set -euo pipefail
    git status --short || true
agent:
  max_concurrent_agents: 2
  max_turns: 12
  max_retry_backoff_ms: 300000
  max_concurrent_agents_by_state:
    todo: 1
    in progress: 2
codex:
  command: codex app-server -c model="gpt-5.5" -c model_reasoning_effort="low"
  turn_timeout_ms: 3600000
  read_timeout_ms: 5000
  stall_timeout_ms: 300000
  approval_policy: never
symphony:
  repo: "sdk-rust-public"
  path: "sdk-rust-public"
  remote: "https://github.com/LATTIX-IO/sdk-rust-public.git"
  default_branch: "main"
  linear_project_name: "Testing, Quality & Documentation"
  technologies:
    - rust
    - docs
---

# Symphony Workflow — sdk-rust-public

You are the coding agent for **sdk-rust-public** (sdk-rust-public) running under Symphony. Symphony has selected this Linear issue and created an isolated per-issue workspace for you. Treat the workspace as the only place where commands and file edits may run.

## Issue context

- Issue: {{ issue.identifier }} — {{ issue.title }}
- State: {{ issue.state }}
- URL: {{ issue.url }}
- Attempt: {{ attempt }}

Use the issue description, labels, blockers, linked assets, and repository context to determine the smallest safe change. If required information is missing, leave a concise Linear comment or implementation note and stop only when genuinely blocked.

## Repository profile

- Linear project: Testing, Quality & Documentation (289d946064d4)
- Repository path: sdk-rust-public
- Default branch: main
- Detected technology profile: rust, docs

### Technology-specific execution spec

- `rust`: preserve ownership/borrowing clarity, typed errors, feature gates, deterministic tests, and workspace-level formatting/clippy discipline.
- `docs`: keep documentation factual, repo-specific, and free of fake contacts, secrets, or unverified operational claims.

## Executable SDLC contract

`WORKFLOW.md` is not the engineering handbook or a generic SDLC manual. It is the executable, agent-facing slice of the SDLC for one unattended issue run. Follow only process rules that can be acted on in this workspace, and refer to repository docs/runbooks for deeper background when needed.

### Linear state map

- `Backlog`: out of scope for autonomous execution; do not start implementation unless the issue is moved to an active state.
- `Todo`: queued and eligible. Before editing code, move or request movement to `In Progress` when tracker tooling is available.
- `In Progress`: active implementation state. Keep work scoped, validated, and ready for PR handoff.
- `Human Review`: handoff state. Move here only after branch/PR, validation evidence, and final notes are complete.
- `Rework`: reviewer feedback requires another implementation pass; re-read feedback, update the plan, and revalidate before returning to `Human Review`.
- `Done`, `Closed`, `Cancelled`, `Canceled`, `Duplicate`: terminal states. Do not make changes for terminal issues.

### Blockers, follow-ups, and scope control

- Stop only for true blockers: missing required auth, missing required permissions, unavailable required tooling, or ambiguous requirements that would make execution unsafe.
- If blocked, leave a concise tracker note with what is missing, why it blocks validation or delivery, and the exact unblock action needed.
- Do not expand the issue to include opportunistic cleanup. Create or recommend a separate follow-up issue for meaningful out-of-scope improvements, especially security, reliability, or tech-debt findings.
- For production, security, IaC, GitOps, data, or migration changes, include rollback notes and any threat assumptions in the final handoff.

## Required execution flow

1. Re-read the issue and inspect the current repository state before editing.
2. Confirm the issue is in an executable state. If it is `Todo`, transition it to `In Progress` when tracker tooling is available; if it is terminal, stop without changing files.
3. Create or reuse a branch named from the issue identifier and short title. Do not commit directly to `main` unless the workflow owner explicitly requires it.
4. Keep changes scoped to the issue. In this monorepo, if you change a submodule, commit in the child repository first and update the superproject gitlink only when the parent should consume that child commit.
5. Prefer tests first for behavior changes. Preserve existing public APIs unless the issue asks for an intentional contract change.
6. Never print, commit, or log secrets. `LINEAR_API_KEY` is available to Symphony through environment indirection only; do not read or echo it from `.env`.
7. Use the repo's existing tools and dependency managers. Add dependencies only when justified by purpose, license, risk, and alternatives.
8. Commit with a Conventional Commit message that references the issue identifier when practical.
9. Push the branch and open or update a pull request when the repo policy supports it.
10. Before handoff, run the repo-native validation gate plus the targeted checks below, and fix failures caused by the current change.
11. Sweep reviewer feedback for existing or updated PRs; address actionable comments or document justified pushback before returning to review.
12. Move the Linear issue to `Human Review` only after code, tests, docs, PR metadata, validation evidence, and rollback notes are complete. `Done` means the PR is merged or the workflow owner explicitly marks the issue complete.

## Validation contract

- Always run the smallest relevant checks first, then broaden before handoff.

### Repo-native validation gate

- Before handoff, detect and run canonical repo gates when present and relevant:
  - `./precommit.sh` on POSIX/Git Bash runners.
  - `./precommit.ps1` or `.\precommit.ps1` on Windows/PowerShell runners.
  - Make targets such as `precommit`, `ci`, `test`, or `lint` when a `Makefile` documents them.
  - Package-manager scripts such as `lint`, `test`, `typecheck`, or `build` when `package.json` defines them.
- Prefer the repo's documented aggregate gate over hand-assembling commands, but still run targeted tests for the changed behavior when the aggregate gate is too broad or unavailable.
- If validation fails, fix failures introduced by the current change. For clearly unrelated pre-existing failures, capture evidence in the handoff, create or reference a follow-up issue, and do not move to `Human Review` unless the required scope validation is green or the blocker is explicit.
- Rust: run `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` when the workspace supports them. If this repo has a narrower documented command in `README.md`, prefer that command and cite it in the final note.
- Documentation: grep for scaffold markers, fake contacts, and secrets before handoff: `Populate this file with|TODO: Populate|security@example.com|<API_KEY>` should not appear as accidental final content except as intentional placeholder guidance.

## Reviewer feedback loop

- If a PR already exists for the issue or branch, inspect open review comments, failed checks, and bot feedback before adding new work.
- Treat actionable reviewer feedback as blocking until it is addressed in code/docs/tests or answered with concise, justified pushback.
- Re-run the relevant validation gate after feedback-driven changes and push the updated branch before handoff.
- Do not move the issue back to `Human Review` while required checks are failing or actionable review comments remain unresolved.

## Linear handoff

If Symphony exposes the `linear_graphql` tool, use it for tracker updates instead of reading raw credentials. Add a short final comment with:

- summary of changes
- validation evidence
- PR/branch link
- rollout or rollback notes for production-impacting work
- any blockers or follow-up risks

## Safety posture

This workflow assumes a trusted internal agent runner with repository-scoped workspaces. Continue to fail closed for auth, policy, parsing, network, and deployment uncertainty. For security-sensitive, production, IaC, or GitOps changes, include threat assumptions and rollback guidance in the final handoff.
