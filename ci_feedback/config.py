from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any


class ConfigurationError(ValueError):
    """Raised when the checked-in control-plane configuration is unsafe or incomplete."""


@dataclass(frozen=True)
class StateConfig:
    todo: str
    in_progress: str
    in_review: str
    done: str
    escalated: str


@dataclass(frozen=True)
class LinearConfig:
    endpoint: str
    team_id: str
    team_key: str
    project_id: str
    project_slug: str
    states: StateConfig
    generated_labels: tuple[str, ...]


@dataclass(frozen=True)
class PolicyConfig:
    actionable_conclusions: frozenset[str]
    max_remediation_depth: int
    human_review_after: int
    systemic_after: int
    history_limit: int
    denied_agent_paths: tuple[str, ...]
    symphony_branch_prefix: str


@dataclass(frozen=True)
class AppConfig:
    repositories: frozenset[str]
    linear: LinearConfig
    policy: PolicyConfig

    def allows_repository(self, repository: str) -> bool:
        return repository.casefold() in {value.casefold() for value in self.repositories}


def load_config(path: str | Path) -> AppConfig:
    config_path = Path(path)
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"Unable to load configuration from {config_path}: {exc}") from exc

    if not isinstance(payload, dict):
        raise ConfigurationError("Configuration root must be an object.")

    _require_equal(payload.get("version"), 1, "version")
    repositories = _non_empty_strings(payload.get("repository_allowlist"), "repository_allowlist")
    linear = _required_mapping(payload, "linear")
    policy = _required_mapping(payload, "policy")
    states = _required_mapping(linear, "states")

    app_config = AppConfig(
        repositories=frozenset(repositories),
        linear=LinearConfig(
            endpoint=_https_url(linear.get("endpoint"), "linear.endpoint"),
            team_id=_non_empty_string(linear.get("team_id"), "linear.team_id"),
            team_key=_non_empty_string(linear.get("team_key"), "linear.team_key"),
            project_id=_non_empty_string(linear.get("project_id"), "linear.project_id"),
            project_slug=_non_empty_string(linear.get("project_slug"), "linear.project_slug"),
            states=StateConfig(
                todo=_non_empty_string(states.get("todo"), "linear.states.todo"),
                in_progress=_non_empty_string(states.get("in_progress"), "linear.states.in_progress"),
                in_review=_non_empty_string(states.get("in_review"), "linear.states.in_review"),
                done=_non_empty_string(states.get("done"), "linear.states.done"),
                escalated=_non_empty_string(states.get("escalated"), "linear.states.escalated"),
            ),
            generated_labels=tuple(_non_empty_strings(linear.get("generated_labels"), "linear.generated_labels")),
        ),
        policy=PolicyConfig(
            actionable_conclusions=frozenset(
                value.casefold()
                for value in _non_empty_strings(
                    policy.get("actionable_conclusions"),
                    "policy.actionable_conclusions",
                )
            ),
            max_remediation_depth=_positive_int(
                policy.get("max_remediation_depth"),
                "policy.max_remediation_depth",
            ),
            human_review_after=_positive_int(
                policy.get("human_review_after"),
                "policy.human_review_after",
            ),
            systemic_after=_positive_int(policy.get("systemic_after"), "policy.systemic_after"),
            history_limit=_positive_int(policy.get("history_limit"), "policy.history_limit"),
            denied_agent_paths=tuple(
                _non_empty_strings(policy.get("denied_agent_paths"), "policy.denied_agent_paths")
            ),
            symphony_branch_prefix=_non_empty_string(
                policy.get("symphony_branch_prefix"),
                "policy.symphony_branch_prefix",
            ),
        ),
    )
    _validate_cross_fields(app_config)
    return app_config


def _validate_cross_fields(config: AppConfig) -> None:
    if config.policy.human_review_after >= config.policy.systemic_after:
        raise ConfigurationError("human_review_after must be lower than systemic_after.")
    if config.policy.systemic_after > config.policy.history_limit:
        raise ConfigurationError("history_limit must retain at least systemic_after observations.")

    required = {
        "type:ci-failure",
        "source:github-actions",
        "auto-generated",
        "agent:eligible",
    }
    missing = sorted(required.difference(config.linear.generated_labels))
    if missing:
        raise ConfigurationError(f"linear.generated_labels is missing required values: {', '.join(missing)}")


def _required_mapping(payload: dict[str, Any], key: str) -> dict[str, Any]:
    value = payload.get(key)
    if not isinstance(value, dict):
        raise ConfigurationError(f"{key} must be an object.")
    return value


def _non_empty_strings(value: Any, name: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ConfigurationError(f"{name} must be a non-empty array.")
    normalized = [_non_empty_string(item, name) for item in value]
    if len(set(normalized)) != len(normalized):
        raise ConfigurationError(f"{name} must not contain duplicates.")
    return normalized


def _non_empty_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(f"{name} must be a non-empty string.")
    return value.strip()


def _https_url(value: Any, name: str) -> str:
    normalized = _non_empty_string(value, name)
    if not normalized.startswith("https://"):
        raise ConfigurationError(f"{name} must use HTTPS.")
    return normalized


def _positive_int(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ConfigurationError(f"{name} must be a positive integer.")
    return value


def _require_equal(value: Any, expected: Any, name: str) -> None:
    if value != expected:
        raise ConfigurationError(f"{name} must be {expected!r}.")
