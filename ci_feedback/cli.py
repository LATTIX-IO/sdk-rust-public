from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any

from .config import ConfigurationError, load_config
from .github import GitHubClient
from .linear import LinearClient
from .service import FeedbackService


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Trusted GitHub Actions to Linear CI feedback integration.")
    parser.add_argument(
        "--config",
        default="config/ci-feedback.json",
        help="Path to the checked-in JSON policy configuration.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    process = subparsers.add_parser("process", help="Process one completed workflow_run event.")
    process.add_argument("--event", required=True, help="Path to the GitHub event JSON.")

    validate = subparsers.add_parser("validate", help="Validate checked-in configuration.")
    validate.add_argument(
        "--live-linear",
        action="store_true",
        help="Also validate the configured team, project, states, and labels against Linear.",
    )

    path_policy = subparsers.add_parser(
        "check-path-policy",
        help="Fail when a Symphony pull request changes a human-review-only path.",
    )
    path_policy.add_argument("--event", required=True, help="Path to the pull_request_target event JSON.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        if args.command == "validate":
            if args.live_linear:
                token = _required_env("LINEAR_API_KEY")
                LinearClient(config.linear, token).validate_prerequisites()
            print("CI feedback configuration is valid.")
            return 0

        event = _load_event(args.event)
        repository = _repository_name(event)
        github = GitHubClient(repository, _required_env("GITHUB_TOKEN"))
        linear = LinearClient(config.linear, _required_env("LINEAR_API_KEY")) if args.command == "process" else None
        service = FeedbackService(config, github, linear)  # type: ignore[arg-type]

        if args.command == "process":
            result = service.process_workflow_run(event)
            print(
                json.dumps(
                    {
                        "action": result.action,
                        "created": result.created,
                        "updated": result.updated,
                        "closed": result.closed,
                        "idempotent_replays": result.idempotent_replays,
                        "issues": list(result.issue_identifiers),
                    },
                    sort_keys=True,
                )
            )
            return 0

        violations = service.check_pull_request_path_policy(event)
        if violations:
            print("Symphony branch changes require human review for protected paths:", file=sys.stderr)
            for path in violations:
                print(f"- {path}", file=sys.stderr)
            return 2
        print("Symphony protected-path policy passed.")
        return 0
    except (ConfigurationError, RuntimeError, ValueError) as exc:
        print(f"ci-feedback: {exc}", file=sys.stderr)
        return 1


def _load_event(path: str) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Unable to load GitHub event JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("GitHub event root must be an object.")
    return payload


def _repository_name(payload: dict[str, Any]) -> str:
    repository = payload.get("repository")
    if not isinstance(repository, dict) or not isinstance(repository.get("full_name"), str):
        raise ValueError("GitHub event is missing repository.full_name.")
    return repository["full_name"]


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ValueError(f"Required environment variable is not set: {name}")
    return value


if __name__ == "__main__":
    raise SystemExit(main())
