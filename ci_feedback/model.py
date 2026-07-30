from __future__ import annotations

import base64
import binascii
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import re
from typing import Any


MANAGED_START = "<!-- ci-feedback:managed:start -->"
MANAGED_END = "<!-- ci-feedback:managed:end -->"
METADATA_PREFIX = "<!-- ci-feedback:metadata "
METADATA_V2_PREFIX = "<!-- ci-feedback:metadata-v2 "
METADATA_SUFFIX = " -->"
_METADATA_V2_PATTERN = re.compile(
    re.escape(METADATA_V2_PREFIX)
    + r"(?P<payload>[A-Za-z0-9_-]+)"
    + re.escape(METADATA_SUFFIX)
)
_METADATA_PATTERN = re.compile(
    re.escape(METADATA_PREFIX) + r"(?P<payload>\{.*?\})" + re.escape(METADATA_SUFFIX),
    re.DOTALL,
)
_MANAGED_PATTERN = re.compile(
    re.escape(MANAGED_START) + r".*?" + re.escape(MANAGED_END),
    re.DOTALL,
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class PullRequestContext:
    number: int | None
    url: str | None
    title: str
    body: str
    branch: str
    base_branch: str
    commit_sha: str
    originating_issue: str | None
    symphony_execution_id: str | None
    remediation_depth: int = 0


@dataclass(frozen=True)
class WorkflowContext:
    repository: str
    workflow_id: int
    workflow_run_id: int
    workflow_name: str
    workflow_url: str
    conclusion: str
    observed_at: str
    pull_request: PullRequestContext


@dataclass(frozen=True)
class FailureEvent:
    event_id: str
    observation_key: str
    repository: str
    workflow_id: int
    workflow_run_id: int
    workflow_name: str
    workflow_url: str
    job_id: int
    job_name: str
    job_url: str
    check_name: str
    category: str
    conclusion: str
    branch: str
    base_branch: str
    commit_sha: str
    pull_request_number: int | None
    pull_request_url: str | None
    originating_issue: str | None
    symphony_execution_id: str | None
    failure_signature: str
    failure_summary: str
    severity: str
    linear_priority: int
    priority_class: str
    remediation_depth: int
    fingerprint: str
    observed_at: str


@dataclass
class DefectMetadata:
    fingerprint: str
    repository: str
    workflow_id: int
    workflow_name: str
    branch: str
    base_branch: str
    pull_request_number: int | None
    originating_issue: str | None
    originating_execution: str | None
    recurrence_count: int
    first_seen: str
    last_seen: str
    remediation_depth: int
    status: str = "open"
    observations: list[dict[str, Any]] = field(default_factory=list)
    recovery_keys: list[str] = field(default_factory=list)
    last_success_url: str | None = None

    @classmethod
    def from_event(cls, event: FailureEvent) -> "DefectMetadata":
        return cls(
            fingerprint=event.fingerprint,
            repository=event.repository,
            workflow_id=event.workflow_id,
            workflow_name=event.workflow_name,
            branch=event.branch,
            base_branch=event.base_branch,
            pull_request_number=event.pull_request_number,
            originating_issue=event.originating_issue,
            originating_execution=event.symphony_execution_id,
            recurrence_count=1,
            first_seen=event.observed_at,
            last_seen=event.observed_at,
            remediation_depth=event.remediation_depth,
            observations=[observation_from_event(event)],
        )

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "DefectMetadata":
        return cls(
            fingerprint=str(payload["fingerprint"]),
            repository=str(payload["repository"]),
            workflow_id=int(payload["workflow_id"]),
            workflow_name=str(payload["workflow_name"]),
            branch=str(payload["branch"]),
            base_branch=str(payload["base_branch"]),
            pull_request_number=_optional_int(payload.get("pull_request_number")),
            originating_issue=_optional_string(payload.get("originating_issue")),
            originating_execution=_optional_string(payload.get("originating_execution")),
            recurrence_count=int(payload["recurrence_count"]),
            first_seen=str(payload["first_seen"]),
            last_seen=str(payload["last_seen"]),
            remediation_depth=int(payload.get("remediation_depth", 0)),
            status=str(payload.get("status", "open")),
            observations=list(payload.get("observations", [])),
            recovery_keys=[str(value) for value in payload.get("recovery_keys", [])],
            last_success_url=_optional_string(payload.get("last_success_url")),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def contains_observation(self, observation_key: str) -> bool:
        return any(item.get("key") == observation_key for item in self.observations)

    def record_failure(self, event: FailureEvent, history_limit: int) -> bool:
        if self.contains_observation(event.observation_key):
            return False

        self.recurrence_count += 1
        self.last_seen = event.observed_at
        self.status = "open"
        self.branch = event.branch
        self.base_branch = event.base_branch
        self.pull_request_number = event.pull_request_number
        self.originating_issue = event.originating_issue or self.originating_issue
        self.originating_execution = event.symphony_execution_id or self.originating_execution
        self.remediation_depth = max(self.remediation_depth, event.remediation_depth)
        self.observations.append(observation_from_event(event))
        self.observations = self.observations[-history_limit:]
        return True

    def record_recovery(self, recovery_key: str, workflow_url: str, observed_at: str, history_limit: int) -> bool:
        if recovery_key in self.recovery_keys:
            return False

        self.status = "resolved"
        self.last_seen = observed_at
        self.last_success_url = workflow_url
        self.recovery_keys.append(recovery_key)
        self.recovery_keys = self.recovery_keys[-history_limit:]
        return True


def observation_from_event(event: FailureEvent) -> dict[str, Any]:
    return {
        "key": event.observation_key,
        "observed_at": event.observed_at,
        "workflow_run_id": event.workflow_run_id,
        "workflow_url": event.workflow_url,
        "job_id": event.job_id,
        "job_name": event.job_name,
        "job_url": event.job_url,
        "check_name": event.check_name,
        "conclusion": event.conclusion,
        "summary": event.failure_summary,
        "commit_sha": event.commit_sha,
    }


def parse_metadata(description: str | None) -> DefectMetadata | None:
    if not description:
        return None
    versioned_match = _METADATA_V2_PATTERN.search(description)
    if versioned_match:
        encoded = versioned_match.group("payload")
        padding = "=" * (-len(encoded) % 4)
        try:
            decoded = base64.urlsafe_b64decode(encoded + padding).decode("utf-8")
            payload = json.loads(decoded)
            if not isinstance(payload, dict):
                return None
            return DefectMetadata.from_dict(payload)
        except (
            binascii.Error,
            UnicodeDecodeError,
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ):
            return None

    match = _METADATA_PATTERN.search(description)
    if not match:
        return None
    try:
        payload = json.loads(match.group("payload"))
        if not isinstance(payload, dict):
            return None
        return DefectMetadata.from_dict(payload)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


def replace_managed_description(existing: str | None, managed: str) -> str:
    block = f"{MANAGED_START}\n{managed.rstrip()}\n{MANAGED_END}"
    if not existing:
        return block
    if _MANAGED_PATTERN.search(existing):
        return _MANAGED_PATTERN.sub(block, existing, count=1)
    return f"{block}\n\n## Operator notes\n\n{existing.strip()}"


def metadata_marker(metadata: DefectMetadata) -> str:
    payload = json.dumps(
        metadata.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    encoded = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    return f"{METADATA_V2_PREFIX}{encoded}{METADATA_SUFFIX}"


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    return int(value)
