from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from .config import AppConfig
from .linear import LinearIssue
from .model import (
    DefectMetadata,
    FailureEvent,
    PullRequestContext,
    WorkflowContext,
    metadata_marker,
    parse_metadata,
    replace_managed_description,
    utc_now,
)
from .policy import (
    build_failure_event,
    category_label,
    denied_path_matches,
    extract_execution_id,
    extract_originating_issue,
    extract_remediation_depth,
    severity_label,
)


class GitHubGateway(Protocol):
    def list_workflow_jobs(self, workflow_run_id: int) -> list[dict[str, Any]]: ...

    def get_pull_request(self, number: int) -> dict[str, Any]: ...

    def list_pull_request_files(self, number: int) -> list[str]: ...


class LinearGateway(Protocol):
    def validate_prerequisites(self) -> None: ...

    def list_project_issues(self) -> list[LinearIssue]: ...

    def get_issue(self, issue_id_or_identifier: str) -> LinearIssue | None: ...

    def resolve_label_ids(self, names: tuple[str, ...] | list[str] | set[str]) -> dict[str, str]: ...

    def create_issue(
        self,
        *,
        title: str,
        description: str,
        priority: int,
        state_id: str,
        label_ids: list[str],
        parent_id: str | None,
    ) -> LinearIssue: ...

    def update_issue(
        self,
        issue_id: str,
        *,
        description: str | None = None,
        priority: int | None = None,
        state_id: str | None = None,
        label_ids: list[str] | None = None,
    ) -> LinearIssue: ...

    def create_comment(self, issue_id: str, body: str) -> None: ...


@dataclass(frozen=True)
class FeedbackResult:
    action: str
    created: int = 0
    updated: int = 0
    closed: int = 0
    idempotent_replays: int = 0
    issue_identifiers: tuple[str, ...] = ()


class FeedbackService:
    def __init__(
        self,
        config: AppConfig,
        github: GitHubGateway,
        linear: LinearGateway,
    ) -> None:
        self.config = config
        self.github = github
        self.linear = linear

    def process_workflow_run(self, payload: dict[str, Any]) -> FeedbackResult:
        context = self._normalize_workflow_context(payload)
        if not self.config.allows_repository(context.repository):
            raise ValueError(f"Repository is not allowlisted: {context.repository}")
        self.linear.validate_prerequisites()

        if context.conclusion == "success":
            return self._process_recovery(context)
        if context.conclusion not in self.config.policy.actionable_conclusions:
            return FeedbackResult(action="ignored")
        return self._process_failures(context)

    def check_pull_request_path_policy(self, payload: dict[str, Any]) -> list[str]:
        pull_request = payload.get("pull_request")
        repository = payload.get("repository")
        if not isinstance(pull_request, dict) or not isinstance(repository, dict):
            raise ValueError("pull_request_target payload is missing pull_request or repository.")
        repository_name = repository.get("full_name")
        if not isinstance(repository_name, str) or not self.config.allows_repository(repository_name):
            raise ValueError("pull_request_target repository is not allowlisted.")
        head = pull_request.get("head")
        if not isinstance(head, dict):
            raise ValueError("pull_request_target payload is missing the head branch.")
        branch = head.get("ref")
        if not isinstance(branch, str):
            raise ValueError("pull_request_target payload has an invalid head branch.")
        if not branch.startswith(self.config.policy.symphony_branch_prefix):
            return []
        number = pull_request.get("number")
        if not isinstance(number, int):
            raise ValueError("pull_request_target payload is missing a pull request number.")
        paths = self.github.list_pull_request_files(number)
        return denied_path_matches(paths, self.config.policy.denied_agent_paths)

    def _process_failures(self, context: WorkflowContext) -> FeedbackResult:
        issues = self.linear.list_project_issues()
        indexed = self._index_defects(issues)
        jobs = self.github.list_workflow_jobs(context.workflow_run_id)
        events = self._failure_events(context, jobs)

        created = 0
        updated = 0
        replays = 0
        identifiers: list[str] = []
        for event in events:
            existing = indexed.get(event.fingerprint)
            if existing is None:
                issue = self._create_defect(event)
                created += 1
                indexed[event.fingerprint] = issue
                identifiers.append(issue.identifier)
                continue

            metadata = parse_metadata(existing.description)
            if metadata is None:
                raise ValueError(
                    f"Existing fingerprint match lacks valid managed metadata: {existing.identifier}"
                )
            if not metadata.record_failure(event, self.config.policy.history_limit):
                replays += 1
                identifiers.append(existing.identifier)
                continue

            updated_issue = self._update_defect(existing, event, metadata)
            updated += 1
            indexed[event.fingerprint] = updated_issue
            identifiers.append(updated_issue.identifier)

        return FeedbackResult(
            action="failure",
            created=created,
            updated=updated,
            idempotent_replays=replays,
            issue_identifiers=tuple(identifiers),
        )

    def _process_recovery(self, context: WorkflowContext) -> FeedbackResult:
        issues = self.linear.list_project_issues()
        recovery_key = f"{context.repository.casefold()}:{context.workflow_run_id}:success"
        closed = 0
        replays = 0
        identifiers: list[str] = []
        origins: set[str] = set()
        resolved_issue_ids: set[str] = set()

        for issue in issues:
            metadata = parse_metadata(issue.description)
            if metadata is None or not self._matches_recovery(metadata, context):
                continue
            if metadata.status == "resolved":
                if recovery_key in metadata.recovery_keys:
                    replays += 1
                    if metadata.originating_issue:
                        origins.add(metadata.originating_issue)
                continue
            if not metadata.record_recovery(
                recovery_key,
                context.workflow_url,
                context.observed_at,
                self.config.policy.history_limit,
            ):
                replays += 1
                continue

            description = replace_managed_description(
                issue.description,
                self._render_managed_description(None, metadata),
            )
            self.linear.update_issue(
                issue.id,
                description=description,
                state_id=self.config.linear.states.done,
            )
            self.linear.create_comment(
                issue.id,
                f"Required workflow recovered.\n\nRun: {context.workflow_url}\n"
                f"Commit: `{context.pull_request.commit_sha}`",
            )
            closed += 1
            resolved_issue_ids.add(issue.id)
            identifiers.append(issue.identifier)
            if metadata.originating_issue:
                origins.add(metadata.originating_issue)

        for origin in sorted(origins):
            self._resume_originating_issue(origin, context, issues, resolved_issue_ids)

        return FeedbackResult(
            action="recovery",
            closed=closed,
            idempotent_replays=replays,
            issue_identifiers=tuple(identifiers),
        )

    def _create_defect(self, event: FailureEvent) -> LinearIssue:
        metadata = DefectMetadata.from_event(event)
        labels = self._desired_labels(event, metadata)
        label_ids = self.linear.resolve_label_ids(labels)
        parent = self.linear.get_issue(event.originating_issue) if event.originating_issue else None
        state_id = self._state_for(event, metadata)
        issue = self.linear.create_issue(
            title=self._defect_title(event),
            description=replace_managed_description(
                None,
                self._render_managed_description(event, metadata),
            ),
            priority=self._priority_for(event, metadata),
            state_id=state_id,
            label_ids=[label_ids[name] for name in labels],
            parent_id=parent.id if parent else None,
        )
        if parent:
            self.linear.create_comment(
                parent.id,
                f"Required CI created blocking defect {issue.identifier}: {issue.url}\n\n"
                f"Workflow run: {event.workflow_url}\nFingerprint: `{event.fingerprint}`",
            )
        return issue

    def _update_defect(
        self,
        issue: LinearIssue,
        event: FailureEvent,
        metadata: DefectMetadata,
    ) -> LinearIssue:
        labels = self._desired_labels(event, metadata)
        label_ids = self.linear.resolve_label_ids(labels)
        updated = self.linear.update_issue(
            issue.id,
            description=replace_managed_description(
                issue.description,
                self._render_managed_description(event, metadata),
            ),
            priority=self._priority_for(event, metadata),
            state_id=self._state_for(event, metadata),
            label_ids=[label_ids[name] for name in labels],
        )
        self.linear.create_comment(
            issue.id,
            f"CI failure recurred (occurrence {metadata.recurrence_count}).\n\n"
            f"Run: {event.workflow_url}\nCommit: `{event.commit_sha}`",
        )
        return updated

    def _resume_originating_issue(
        self,
        identifier: str,
        context: WorkflowContext,
        project_issues: list[LinearIssue],
        resolved_issue_ids: set[str],
    ) -> None:
        still_open = False
        for issue in project_issues:
            metadata = parse_metadata(issue.description)
            if (
                issue.id not in resolved_issue_ids
                and
                metadata
                and metadata.originating_issue == identifier
                and metadata.repository.casefold() == context.repository.casefold()
                and metadata.pull_request_number == context.pull_request.number
                and metadata.status != "resolved"
            ):
                still_open = True
                break
        if still_open:
            return

        origin = self.linear.get_issue(identifier)
        if origin is None or origin.state_type in {"completed", "canceled"}:
            return
        self.linear.update_issue(origin.id, state_id=self.config.linear.states.in_review)
        self.linear.create_comment(
            origin.id,
            f"Required CI recovered; autonomous remediation may resume review.\n\n"
            f"Workflow run: {context.workflow_url}",
        )

    def _failure_events(
        self,
        context: WorkflowContext,
        jobs: list[dict[str, Any]],
    ) -> list[FailureEvent]:
        events: list[FailureEvent] = []
        for job in jobs:
            conclusion = str(job.get("conclusion") or "").casefold()
            if conclusion not in self.config.policy.actionable_conclusions:
                continue
            job_id = job.get("id")
            if not isinstance(job_id, int):
                continue
            job_name = str(job.get("name") or "unknown job")
            check_name = self._failed_step_name(job)
            summary = f"{job_name} / {check_name} concluded {conclusion}"
            events.append(
                build_failure_event(
                    repository=context.repository,
                    workflow_id=context.workflow_id,
                    workflow_run_id=context.workflow_run_id,
                    workflow_name=context.workflow_name,
                    workflow_url=context.workflow_url,
                    job_id=job_id,
                    job_name=job_name,
                    job_url=str(job.get("html_url") or context.workflow_url),
                    check_name=check_name,
                    conclusion=conclusion,
                    branch=context.pull_request.branch,
                    base_branch=context.pull_request.base_branch,
                    commit_sha=context.pull_request.commit_sha,
                    pull_request_number=context.pull_request.number,
                    pull_request_url=context.pull_request.url,
                    originating_issue=context.pull_request.originating_issue,
                    symphony_execution_id=context.pull_request.symphony_execution_id,
                    failure_summary=summary,
                    remediation_depth=context.pull_request.remediation_depth,
                    observed_at=context.observed_at,
                )
            )

        if events:
            return events

        return [
            build_failure_event(
                repository=context.repository,
                workflow_id=context.workflow_id,
                workflow_run_id=context.workflow_run_id,
                workflow_name=context.workflow_name,
                workflow_url=context.workflow_url,
                job_id=0,
                job_name=context.workflow_name,
                job_url=context.workflow_url,
                check_name="workflow completion",
                conclusion=context.conclusion,
                branch=context.pull_request.branch,
                base_branch=context.pull_request.base_branch,
                commit_sha=context.pull_request.commit_sha,
                pull_request_number=context.pull_request.number,
                pull_request_url=context.pull_request.url,
                originating_issue=context.pull_request.originating_issue,
                symphony_execution_id=context.pull_request.symphony_execution_id,
                failure_summary=f"{context.workflow_name} concluded {context.conclusion} without an actionable job payload",
                remediation_depth=context.pull_request.remediation_depth,
                observed_at=context.observed_at,
            )
        ]

    def _normalize_workflow_context(self, payload: dict[str, Any]) -> WorkflowContext:
        if payload.get("action") != "completed":
            raise ValueError("Only completed workflow_run events are accepted.")
        run = payload.get("workflow_run")
        repository = payload.get("repository")
        if not isinstance(run, dict) or not isinstance(repository, dict):
            raise ValueError("workflow_run payload is missing workflow_run or repository.")
        repository_name = repository.get("full_name")
        if not isinstance(repository_name, str):
            raise ValueError("workflow_run repository name is missing.")

        pull_requests = run.get("pull_requests")
        pr_number: int | None = None
        if isinstance(pull_requests, list) and pull_requests and isinstance(pull_requests[0], dict):
            candidate = pull_requests[0].get("number")
            if isinstance(candidate, int):
                pr_number = candidate

        pr_payload = self.github.get_pull_request(pr_number) if pr_number is not None else {}
        head = pr_payload.get("head") if isinstance(pr_payload, dict) else {}
        base = pr_payload.get("base") if isinstance(pr_payload, dict) else {}
        branch = (
            head.get("ref")
            if isinstance(head, dict) and isinstance(head.get("ref"), str)
            else str(run.get("head_branch") or "")
        )
        base_branch = (
            base.get("ref")
            if isinstance(base, dict) and isinstance(base.get("ref"), str)
            else str(repository.get("default_branch") or "main")
        )
        commit_sha = (
            head.get("sha")
            if isinstance(head, dict) and isinstance(head.get("sha"), str)
            else str(run.get("head_sha") or "")
        )
        title = str(pr_payload.get("title") or "")
        body = str(pr_payload.get("body") or "")
        pr_url = str(pr_payload.get("html_url") or "") or None
        observed_at = str(run.get("updated_at") or run.get("created_at") or utc_now())
        workflow_id = run.get("workflow_id")
        workflow_run_id = run.get("id")
        if not isinstance(workflow_id, int) or not isinstance(workflow_run_id, int):
            raise ValueError("workflow_run payload has invalid workflow identifiers.")
        workflow_name = str(run.get("name") or payload.get("workflow", {}).get("name") or "unknown")
        workflow_url = str(run.get("html_url") or "")
        conclusion = str(run.get("conclusion") or "").casefold()
        if not branch or not commit_sha or not workflow_url or not conclusion:
            raise ValueError("workflow_run payload omitted branch, commit, URL, or conclusion.")

        return WorkflowContext(
            repository=repository_name,
            workflow_id=workflow_id,
            workflow_run_id=workflow_run_id,
            workflow_name=workflow_name[:160],
            workflow_url=workflow_url,
            conclusion=conclusion,
            observed_at=observed_at,
            pull_request=PullRequestContext(
                number=pr_number,
                url=pr_url,
                title=title,
                body=body,
                branch=branch,
                base_branch=base_branch,
                commit_sha=commit_sha,
                originating_issue=extract_originating_issue(branch, title, body),
                symphony_execution_id=extract_execution_id(body),
                remediation_depth=extract_remediation_depth(body),
            ),
        )

    def _desired_labels(
        self,
        event: FailureEvent,
        metadata: DefectMetadata,
    ) -> tuple[str, ...]:
        labels = set(self.config.linear.generated_labels)
        labels.add(category_label(event.category))
        labels.add(severity_label(event.severity))
        if metadata.recurrence_count > 1:
            labels.add("recurring")
        if metadata.recurrence_count >= self.config.policy.human_review_after:
            labels.discard("agent:eligible")
            labels.add("agent:human-review-required")
        if metadata.recurrence_count >= self.config.policy.systemic_after:
            labels.add("needs-triage")
        if metadata.remediation_depth >= self.config.policy.max_remediation_depth:
            labels.discard("agent:eligible")
            labels.add("agent:human-review-required")
            labels.add("needs-triage")
        return tuple(sorted(labels))

    def _state_for(self, event: FailureEvent, metadata: DefectMetadata) -> str:
        if metadata.remediation_depth >= self.config.policy.max_remediation_depth:
            return self.config.linear.states.escalated
        return self.config.linear.states.todo

    def _priority_for(self, event: FailureEvent, metadata: DefectMetadata) -> int:
        if metadata.recurrence_count >= 2:
            return max(1, event.linear_priority - 1)
        return event.linear_priority

    def _matches_recovery(self, metadata: DefectMetadata, context: WorkflowContext) -> bool:
        if metadata.repository.casefold() != context.repository.casefold():
            return False
        if metadata.workflow_id != context.workflow_id:
            return False
        if metadata.pull_request_number is not None or context.pull_request.number is not None:
            return metadata.pull_request_number == context.pull_request.number
        return metadata.branch == context.pull_request.branch

    def _index_defects(self, issues: list[LinearIssue]) -> dict[str, LinearIssue]:
        index: dict[str, LinearIssue] = {}
        for issue in issues:
            metadata = parse_metadata(issue.description)
            if metadata is None:
                continue
            previous = index.get(metadata.fingerprint)
            if previous is not None and previous.id != issue.id:
                raise ValueError(
                    f"Duplicate Linear CI defects share fingerprint {metadata.fingerprint}: "
                    f"{previous.identifier}, {issue.identifier}"
                )
            index[metadata.fingerprint] = issue
        return index

    @staticmethod
    def _failed_step_name(job: dict[str, Any]) -> str:
        steps = job.get("steps")
        if isinstance(steps, list):
            for step in steps:
                if not isinstance(step, dict):
                    continue
                if str(step.get("conclusion") or "").casefold() in {
                    "failure",
                    "timed_out",
                    "action_required",
                    "startup_failure",
                }:
                    return str(step.get("name") or "failed step")
        return "job completion"

    @staticmethod
    def _defect_title(event: FailureEvent) -> str:
        summary = f"{event.job_name}: {event.check_name}".strip(": ")
        return f"[CI][{event.category.upper()}] {summary}"[:250]

    def _render_managed_description(
        self,
        event: FailureEvent | None,
        metadata: DefectMetadata,
    ) -> str:
        latest = metadata.observations[-1] if metadata.observations else {}
        category = event.category if event else "recovered"
        severity = event.severity if event else "resolved"
        priority_class = event.priority_class if event else "resolved"
        job_name = event.job_name if event else str(latest.get("job_name") or "unknown")
        check_name = event.check_name if event else str(latest.get("check_name") or "unknown")
        summary = event.failure_summary if event else "The required validation profile recovered."
        if metadata.pull_request_number and event and event.pull_request_url:
            pr_text = f"[#{metadata.pull_request_number}]({event.pull_request_url})"
        elif metadata.pull_request_number:
            pr_text = f"#{metadata.pull_request_number}"
        else:
            pr_text = "none"
        observations = "\n".join(
            f"- [{item.get('observed_at', 'unknown')}]({item.get('workflow_url', '')}) — "
            f"`{item.get('job_name', 'unknown')}` / `{item.get('check_name', 'unknown')}` "
            f"on `{str(item.get('commit_sha', ''))[:12]}`"
            for item in metadata.observations[-10:]
        ) or "- No failure observation retained."

        return f"""## Summary

{summary}

## Classification

- Category: `{category}`
- Severity: `{severity}`
- Priority class: `{priority_class}`
- Tool/job: `{job_name}`
- Rule/check: `{check_name}`
- Confidence: `medium` (job and failed-step classification)

## Origin

- Repository: `{metadata.repository}`
- Branch: `{metadata.branch}`
- Base branch: `{metadata.base_branch}`
- Pull request: {pr_text}
- Workflow: `{metadata.workflow_name}` (`{metadata.workflow_id}`)
- Originating Linear issue: `{metadata.originating_issue or "unknown"}`
- Symphony execution: `{metadata.originating_execution or "unknown"}`

## Failure evidence

{observations}

## Remediation requirements

- Correct the root cause; do not disable, weaken, skip, or remove the failed validation.
- Add or update regression coverage where the failure represents product behavior.
- Preserve branch protection, required checks, security controls, and authorized scope.
- Push the remediation to the originating branch when safe.
- Run the applicable validation profile and retain successful evidence.

## Acceptance criteria

- The fingerprint no longer reproduces.
- The targeted check passes as part of the complete required workflow.
- No equivalent or higher-severity failure is introduced.
- The originating pull request remains within authorized scope.

## Machine metadata

- Fingerprint: `{metadata.fingerprint}`
- Recurrence count: `{metadata.recurrence_count}`
- Remediation depth: `{metadata.remediation_depth}`
- First seen: `{metadata.first_seen}`
- Last seen: `{metadata.last_seen}`
- Status: `{metadata.status}`

{metadata_marker(metadata)}"""
