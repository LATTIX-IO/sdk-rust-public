from __future__ import annotations

import fnmatch
import hashlib
import re
from typing import Iterable

from .model import FailureEvent


_WINDOWS_TEMP_PATH = re.compile(r"(?i)[a-z]:\\(?:users\\[^\\]+\\appdata\\local\\temp|temp)\\[^\s:]+")
_POSIX_TEMP_PATH = re.compile(r"(?i)/(?:tmp|var/tmp)/[^\s:]+")
_ISO_TIMESTAMP = re.compile(r"\b\d{4}-\d{2}-\d{2}[tT ][0-9:.+-]+Z?\b")
_HEX_SHA = re.compile(r"\b[0-9a-f]{7,64}\b", re.IGNORECASE)
_PORT = re.compile(r"(?i)\b(port[ =:]*)\d{2,5}\b")
_LINE_COLUMN = re.compile(r"(?i)(?::|\bline\s+)\d+(?::\d+)?\b")
_SPACE = re.compile(r"\s+")
_ISSUE_IDENTIFIER = re.compile(r"\b([A-Z][A-Z0-9]{1,15}-\d+)\b")
_EXECUTION_ID = re.compile(r"(?im)^\s*Symphony-Execution:\s*(sym-[A-Za-z0-9-]+)\s*$")
_REMEDIATION_DEPTH = re.compile(r"(?im)^\s*Remediation-Depth:\s*(\d+)\s*$")


CATEGORY_LABELS = {
    "build": "ci:build",
    "unit": "ci:unit",
    "integration": "ci:integration",
    "regression": "ci:regression",
    "e2e": "ci:e2e",
    "lint": "ci:lint",
    "typecheck": "ci:typecheck",
    "sast": "ci:sast",
    "dast": "ci:dast",
    "pentest": "ci:pentest",
    "dependency": "ci:dependency",
    "secret": "ci:secret",
    "container": "ci:container",
    "iac": "ci:iac",
    "policy": "ci:policy",
    "performance": "ci:performance",
    "fuzz": "ci:fuzz",
    "infrastructure": "ci:infrastructure",
    "unknown": "ci:unknown",
}


def normalize_signature(value: str, limit: int = 512) -> str:
    normalized = _WINDOWS_TEMP_PATH.sub("<temp-path>", value)
    normalized = normalized.replace("\\", "/")
    normalized = _POSIX_TEMP_PATH.sub("<temp-path>", normalized)
    normalized = _ISO_TIMESTAMP.sub("<timestamp>", normalized)
    normalized = _HEX_SHA.sub("<sha>", normalized)
    normalized = _PORT.sub(r"\1<port>", normalized)
    normalized = _LINE_COLUMN.sub(":<line>", normalized)
    normalized = _SPACE.sub(" ", normalized).strip().casefold()
    return normalized[:limit]


def normalize_path(value: str) -> str:
    normalized = value.replace("\\", "/").strip()
    normalized = re.sub(r"^(?:[A-Za-z]:)?/(?:home|users)/[^/]+/", "", normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"^\./", "", normalized)
    return normalized.casefold()


def classify_failure(workflow_name: str, job_name: str, check_name: str) -> str:
    haystack = f"{workflow_name} {job_name} {check_name}".casefold()
    rules: tuple[tuple[str, tuple[str, ...]], ...] = (
        ("secret", ("secret", "gitleaks", "trufflehog")),
        ("sast", ("sast", "codeql", "semgrep", "static analysis")),
        ("dast", ("dast", "zap", "dynamic application")),
        ("pentest", ("pentest", "penetration")),
        ("dependency", ("dependency", "snyk", "grype", "cargo audit", "npm audit", "sca")),
        ("container", ("container scan", "trivy", "image scan")),
        ("iac", ("terraform", "checkov", "iac", "infrastructure as code")),
        ("policy", ("policy", "conftest", "kyverno", "opa", "agent path")),
        ("typecheck", ("typecheck", "type check", "mypy", "tsc")),
        ("lint", ("lint", "format", "fmt", "clippy")),
        ("performance", ("performance", "benchmark")),
        ("fuzz", ("fuzz",)),
        ("e2e", ("end-to-end", "end to end", "e2e")),
        ("regression", ("regression",)),
        ("integration", ("integration",)),
        ("unit", ("unit", "pytest", "unittest", "cargo test", "test")),
        ("infrastructure", ("runner", "infrastructure", "startup", "environment")),
        ("build", ("build", "compile", "package")),
    )
    for category, tokens in rules:
        if any(token in haystack for token in tokens):
            return category
    return "unknown"


def severity_and_priority(category: str, branch: str) -> tuple[str, int, str]:
    if category in {"secret", "sast", "dast", "pentest"}:
        return "critical", 1, "P0"
    if branch in {"main", "master"} and category in {"build", "infrastructure", "policy"}:
        return "critical", 1, "P0"
    if category in {"build", "unit", "integration", "regression", "e2e", "dependency", "container", "iac", "policy"}:
        return "high", 2, "P1"
    if category in {"infrastructure", "performance", "fuzz", "unknown"}:
        return "medium", 2, "P1"
    return "low", 3, "P3"


def calculate_fingerprint(
    repository: str,
    base_branch: str,
    workflow_name: str,
    category: str,
    tool: str,
    rule_id: str,
    path: str,
    signature: str,
) -> str:
    fields = (
        repository.casefold().strip(),
        base_branch.casefold().strip(),
        workflow_name.casefold().strip(),
        category.casefold().strip(),
        normalize_signature(tool),
        normalize_signature(rule_id),
        normalize_path(path),
        normalize_signature(signature),
    )
    digest = hashlib.sha256("|".join(fields).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def category_label(category: str) -> str:
    return CATEGORY_LABELS.get(category, CATEGORY_LABELS["unknown"])


def severity_label(severity: str) -> str:
    normalized = severity.casefold()
    if normalized not in {"critical", "high", "medium", "low", "informational"}:
        normalized = "medium"
    return f"severity:{normalized}"


def extract_originating_issue(branch: str, title: str, body: str) -> str | None:
    for candidate in (branch, title, body):
        match = _ISSUE_IDENTIFIER.search(candidate or "")
        if match:
            return match.group(1)
    return None


def extract_execution_id(body: str) -> str | None:
    match = _EXECUTION_ID.search(body or "")
    return match.group(1) if match else None


def extract_remediation_depth(body: str) -> int:
    match = _REMEDIATION_DEPTH.search(body or "")
    return int(match.group(1)) if match else 0


def denied_path_matches(paths: Iterable[str], denied_patterns: Iterable[str]) -> list[str]:
    normalized_patterns = [pattern.replace("\\", "/") for pattern in denied_patterns]
    violations: list[str] = []
    for path in paths:
        normalized = path.replace("\\", "/")
        while normalized.startswith("./"):
            normalized = normalized[2:]
        if any(fnmatch.fnmatchcase(normalized, pattern) for pattern in normalized_patterns):
            violations.append(normalized)
    return sorted(set(violations))


def build_failure_event(
    *,
    repository: str,
    workflow_id: int,
    workflow_run_id: int,
    workflow_name: str,
    workflow_url: str,
    job_id: int,
    job_name: str,
    job_url: str,
    check_name: str,
    conclusion: str,
    branch: str,
    base_branch: str,
    commit_sha: str,
    pull_request_number: int | None,
    pull_request_url: str | None,
    originating_issue: str | None,
    symphony_execution_id: str | None,
    failure_summary: str,
    remediation_depth: int,
    observed_at: str,
) -> FailureEvent:
    category = classify_failure(workflow_name, job_name, check_name)
    signature = normalize_signature(f"{job_name}: {check_name}: {failure_summary}")
    severity, priority, priority_class = severity_and_priority(category, branch)
    fingerprint = calculate_fingerprint(
        repository=repository,
        base_branch=base_branch,
        workflow_name=str(workflow_id),
        category=category,
        tool=job_name,
        rule_id=check_name,
        path="",
        signature=signature,
    )
    observation_key = f"{repository.casefold()}:{workflow_run_id}:{job_id}"
    return FailureEvent(
        event_id=observation_key,
        observation_key=observation_key,
        repository=repository,
        workflow_id=workflow_id,
        workflow_run_id=workflow_run_id,
        workflow_name=workflow_name,
        workflow_url=workflow_url,
        job_id=job_id,
        job_name=job_name[:160],
        job_url=job_url,
        check_name=check_name[:160],
        category=category,
        conclusion=conclusion.casefold(),
        branch=branch,
        base_branch=base_branch,
        commit_sha=commit_sha[:64],
        pull_request_number=pull_request_number,
        pull_request_url=pull_request_url,
        originating_issue=originating_issue,
        symphony_execution_id=symphony_execution_id,
        failure_signature=signature,
        failure_summary=normalize_signature(failure_summary),
        severity=severity,
        linear_priority=priority,
        priority_class=priority_class,
        remediation_depth=remediation_depth,
        fingerprint=fingerprint,
        observed_at=observed_at,
    )
