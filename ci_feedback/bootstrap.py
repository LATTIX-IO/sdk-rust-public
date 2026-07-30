from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import urllib.error
import urllib.request
from typing import Any, Callable


LINEAR_ENDPOINT = "https://api.linear.app/graphql"
GENERATED_LABELS = [
    "type:ci-failure",
    "source:github-actions",
    "auto-generated",
    "auto-remediation",
    "agent:eligible",
]


class BootstrapError(RuntimeError):
    """Raised when repository-to-Linear routing cannot be resolved safely."""


Transport = Callable[[str, dict[str, Any]], dict[str, Any]]


def resolve_config(
    *,
    repository: str,
    project_slug: str,
    team_key: str,
    token: str,
    endpoint: str = LINEAR_ENDPOINT,
    transport: Transport | None = None,
) -> dict[str, Any]:
    if not repository or "/" not in repository:
        raise BootstrapError("repository must be an owner/name pair.")
    if not project_slug.strip():
        raise BootstrapError("project_slug is required.")
    if not team_key.strip():
        raise BootstrapError("team_key is required.")
    if not token:
        raise BootstrapError("Linear API key is required.")
    if not endpoint.startswith("https://"):
        raise BootstrapError("Linear endpoint must use HTTPS.")

    send = transport or _http_transport(endpoint, token)
    project_data = _graphql(
        send,
        """
        query CiFeedbackProject($projectSlug: String!) {
          projects(filter: { slugId: { eq: $projectSlug } }, first: 2) {
            nodes {
              id
              slugId
              teams { nodes { id key name } }
            }
          }
        }
        """,
        {"projectSlug": project_slug},
    )
    projects = ((project_data.get("projects") or {}).get("nodes") or [])
    if len(projects) != 1 or not isinstance(projects[0], dict):
        raise BootstrapError(
            f"Expected one Linear project for slug {project_slug!r}; found {len(projects)}."
        )
    project = projects[0]
    if project.get("slugId") != project_slug:
        raise BootstrapError("Linear project slug did not match the requested routing.")

    normalized_team_key = team_key.strip().upper()
    teams = ((project.get("teams") or {}).get("nodes") or [])
    matching_teams = [
        team
        for team in teams
        if isinstance(team, dict) and str(team.get("key") or "").upper() == normalized_team_key
    ]
    if len(matching_teams) != 1:
        raise BootstrapError(
            f"Project {project_slug!r} is not assigned uniquely to Linear team {normalized_team_key!r}."
        )
    team = matching_teams[0]
    team_id = _required_string(team, "id", "Linear project team")

    team_data = _graphql(
        send,
        """
        query CiFeedbackTeam($teamId: String!) {
          team(id: $teamId) {
            id
            key
            states { nodes { id name type } }
          }
        }
        """,
        {"teamId": team_id},
    )
    resolved_team = team_data.get("team")
    if not isinstance(resolved_team, dict):
        raise BootstrapError("Linear team query returned no team.")
    if resolved_team.get("id") != team_id or resolved_team.get("key") != normalized_team_key:
        raise BootstrapError("Linear team identity drifted while resolving CI feedback routing.")

    states = {
        node.get("name"): node.get("id")
        for node in ((resolved_team.get("states") or {}).get("nodes") or [])
        if isinstance(node, dict)
        and isinstance(node.get("name"), str)
        and isinstance(node.get("id"), str)
    }
    required_states = ("Todo", "In Progress", "In Review", "Done")
    missing_states = [name for name in required_states if name not in states]
    if missing_states:
        raise BootstrapError(
            "Linear team is missing required CI feedback states: " + ", ".join(missing_states)
        )

    project_id = _required_string(project, "id", "Linear project")
    return {
        "version": 1,
        "repository_allowlist": [repository],
        "linear": {
            "endpoint": endpoint,
            "team_id": team_id,
            "team_key": normalized_team_key,
            "project_id": project_id,
            "project_slug": project_slug,
            "states": {
                "todo": states["Todo"],
                "in_progress": states["In Progress"],
                "in_review": states["In Review"],
                "done": states["Done"],
                # The current Linear teams have no dedicated Escalated state.
                # Fail closed into In Review with human-review labels at the limit.
                "escalated": states["In Review"],
            },
            "generated_labels": GENERATED_LABELS,
        },
        "policy": {
            "actionable_conclusions": [
                "failure",
                "timed_out",
                "action_required",
                "startup_failure",
            ],
            "max_remediation_depth": 3,
            "human_review_after": 3,
            "systemic_after": 4,
            "history_limit": 50,
            "symphony_branch_prefix": "symphony/",
            "denied_agent_paths": [
                ".github/workflows/**",
                ".github/actions/**",
                "CODEOWNERS",
                "security-policy/**",
                "branch-protection/**",
                "rulesets/**",
                "deployment/**",
                "production-infrastructure/**",
            ],
        },
    }


def write_config(path: str | Path, payload: dict[str, Any]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Resolve repository-local Linear routing into trusted CI feedback configuration."
    )
    parser.add_argument("--repository", required=True)
    parser.add_argument("--project-slug", required=True)
    parser.add_argument("--team-key", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--endpoint", default=LINEAR_ENDPOINT)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    token = os.environ.get("LINEAR_API_KEY", "")
    try:
        payload = resolve_config(
            repository=args.repository,
            project_slug=args.project_slug,
            team_key=args.team_key,
            token=token,
            endpoint=args.endpoint,
        )
        write_config(args.output, payload)
        print(
            "Resolved trusted CI feedback routing for "
            f"{args.repository} -> {payload['linear']['team_key']}/{args.project_slug}."
        )
        return 0
    except BootstrapError as exc:
        print(f"ci-feedback bootstrap: {exc}", file=os.sys.stderr)
        return 1


def _required_string(payload: dict[str, Any], key: str, label: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise BootstrapError(f"{label} omitted {key}.")
    return value


def _graphql(
    transport: Transport,
    query: str,
    variables: dict[str, Any],
) -> dict[str, Any]:
    payload = transport(query, variables)
    errors = payload.get("errors")
    if errors:
        raise BootstrapError(f"Linear GraphQL returned {len(errors)} error(s).")
    data = payload.get("data")
    if not isinstance(data, dict):
        raise BootstrapError("Linear GraphQL response did not contain a data object.")
    return data


def _http_transport(endpoint: str, token: str) -> Transport:
    def send(query: str, variables: dict[str, Any]) -> dict[str, Any]:
        request = urllib.request.Request(
            endpoint,
            data=json.dumps({"query": query, "variables": variables}).encode("utf-8"),
            headers={
                "Authorization": token,
                "Content-Type": "application/json",
                "User-Agent": "lattix-ci-feedback-bootstrap/1",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = json.loads(response.read())
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise BootstrapError("Linear API request failed.") from exc
        if not isinstance(payload, dict):
            raise BootstrapError("Linear returned a non-object JSON response.")
        return payload

    return send


if __name__ == "__main__":
    raise SystemExit(main())
