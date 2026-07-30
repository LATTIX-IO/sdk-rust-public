from __future__ import annotations

from dataclasses import dataclass
import json
import random
import time
import urllib.error
import urllib.request
from typing import Any, Callable

from .config import LinearConfig


class LinearApiError(RuntimeError):
    """Raised when Linear rejects or cannot complete a GraphQL operation."""


class LinearPrerequisiteError(LinearApiError):
    """Raised when required team configuration is absent or has drifted."""


@dataclass(frozen=True)
class LinearIssue:
    id: str
    identifier: str
    title: str
    description: str
    priority: int
    url: str
    state_id: str
    state_name: str
    state_type: str
    labels: tuple[str, ...]


Transport = Callable[[str, dict[str, Any], bool], dict[str, Any]]


class LinearClient:
    _ISSUE_FIELDS = """
      id
      identifier
      title
      description
      priority
      url
      state { id name type }
      labels { nodes { id name } }
    """

    def __init__(
        self,
        config: LinearConfig,
        token: str,
        *,
        timeout_seconds: int = 30,
        transport: Transport | None = None,
    ) -> None:
        self.config = config
        self.token = token
        self.timeout_seconds = timeout_seconds
        self._transport = transport or self._http_transport

    def validate_prerequisites(self) -> None:
        query = """
        query CiFeedbackPrerequisites($teamId: String!, $projectId: String!) {
          team(id: $teamId) {
            id
            key
            states { nodes { id name type } }
          }
          project(id: $projectId) {
            id
            slugId
            teams { nodes { id } }
          }
        }
        """
        data = self._graphql(
            query,
            {"teamId": self.config.team_id, "projectId": self.config.project_id},
            retryable=True,
        )
        team = data.get("team")
        project = data.get("project")
        if not isinstance(team, dict) or team.get("id") != self.config.team_id:
            raise LinearPrerequisiteError("Configured Linear team is unavailable.")
        if team.get("key") != self.config.team_key:
            raise LinearPrerequisiteError("Configured Linear team key has drifted.")
        if not isinstance(project, dict) or project.get("id") != self.config.project_id:
            raise LinearPrerequisiteError("Configured Linear project is unavailable.")
        if project.get("slugId") != self.config.project_slug:
            raise LinearPrerequisiteError("Configured Linear project slug has drifted.")
        project_team_ids = {
            node.get("id")
            for node in ((project.get("teams") or {}).get("nodes") or [])
            if isinstance(node, dict)
        }
        if self.config.team_id not in project_team_ids:
            raise LinearPrerequisiteError("Configured Linear project is not assigned to the configured team.")

        state_ids = {
            node.get("id")
            for node in ((team.get("states") or {}).get("nodes") or [])
            if isinstance(node, dict)
        }
        configured_state_ids = {
            self.config.states.todo,
            self.config.states.in_progress,
            self.config.states.in_review,
            self.config.states.done,
            self.config.states.escalated,
        }
        missing_states = sorted(configured_state_ids.difference(state_ids))
        if missing_states:
            raise LinearPrerequisiteError(
                f"Configured Linear state IDs are unavailable: {', '.join(missing_states)}"
            )

        self.resolve_label_ids(self.config.generated_labels)

    def list_project_issues(self) -> list[LinearIssue]:
        query = f"""
        query CiFeedbackProjectIssues($projectSlug: String!, $first: Int!, $after: String) {{
          issues(filter: {{project: {{slugId: {{eq: $projectSlug}}}}}}, first: $first, after: $after) {{
            nodes {{ {self._ISSUE_FIELDS} }}
            pageInfo {{ hasNextPage endCursor }}
          }}
        }}
        """
        issues: list[LinearIssue] = []
        cursor: str | None = None
        for _page in range(100):
            data = self._graphql(
                query,
                {"projectSlug": self.config.project_slug, "first": 50, "after": cursor},
                retryable=True,
            )
            connection = data.get("issues")
            if not isinstance(connection, dict):
                raise LinearApiError("Linear returned a malformed issues connection.")
            issues.extend(self._parse_issues(connection.get("nodes")))
            page_info = connection.get("pageInfo")
            if not isinstance(page_info, dict) or page_info.get("hasNextPage") is not True:
                return issues
            cursor = page_info.get("endCursor")
            if not isinstance(cursor, str) or not cursor:
                raise LinearApiError("Linear pagination omitted the next cursor.")
        raise LinearApiError("Linear issue pagination exceeded the safety limit.")

    def get_issue(self, issue_id_or_identifier: str) -> LinearIssue | None:
        query = f"""
        query CiFeedbackIssue($id: String!) {{
          issue(id: $id) {{ {self._ISSUE_FIELDS} }}
        }}
        """
        data = self._graphql(query, {"id": issue_id_or_identifier}, retryable=True)
        payload = data.get("issue")
        if payload is None:
            return None
        return self._parse_issue(payload)

    def resolve_label_ids(self, names: tuple[str, ...] | list[str] | set[str]) -> dict[str, str]:
        wanted = {name for name in names if name}
        query = """
        query CiFeedbackLabels($first: Int!, $after: String) {
          issueLabels(first: $first, after: $after) {
            nodes { id name }
            pageInfo { hasNextPage endCursor }
          }
        }
        """
        available: dict[str, set[str]] = {}
        cursor: str | None = None
        for _page in range(20):
            data = self._graphql(
                query,
                {"first": 250, "after": cursor},
                retryable=True,
            )
            connection = data.get("issueLabels")
            if not isinstance(connection, dict):
                raise LinearApiError("Linear returned a malformed label connection.")
            for node in connection.get("nodes") or []:
                if not isinstance(node, dict):
                    continue
                name = node.get("name")
                label_id = node.get("id")
                if isinstance(name, str) and name and isinstance(label_id, str) and label_id:
                    available.setdefault(name, set()).add(label_id)
            page_info = connection.get("pageInfo")
            if not isinstance(page_info, dict) or page_info.get("hasNextPage") is not True:
                break
            cursor = page_info.get("endCursor")
            if not isinstance(cursor, str) or not cursor:
                raise LinearApiError("Linear label pagination omitted the next cursor.")

        resolved: dict[str, str] = {}
        missing: list[str] = []
        for qualified_name in sorted(wanted):
            # Linear label groups are presented as "group:label" in the UI,
            # while the GraphQL IssueLabel.name field contains only the leaf.
            # Prefer an exact API name and fall back to the qualified leaf.
            candidates = available.get(qualified_name)
            if not candidates and ":" in qualified_name:
                candidates = available.get(qualified_name.rsplit(":", 1)[1])
            if not candidates:
                missing.append(qualified_name)
                continue
            if len(candidates) != 1:
                raise LinearPrerequisiteError(
                    f"Required Linear label is ambiguous: {qualified_name}"
                )
            resolved[qualified_name] = next(iter(candidates))

        if missing:
            raise LinearPrerequisiteError(
                "Required Linear labels are missing; bootstrap them before enabling CI feedback: "
                + ", ".join(missing)
            )
        return resolved

    def create_issue(
        self,
        *,
        title: str,
        description: str,
        priority: int,
        state_id: str,
        label_ids: list[str],
        parent_id: str | None,
    ) -> LinearIssue:
        mutation = f"""
        mutation CiFeedbackCreateIssue($input: IssueCreateInput!) {{
          issueCreate(input: $input) {{
            success
            issue {{ {self._ISSUE_FIELDS} }}
          }}
        }}
        """
        input_payload: dict[str, Any] = {
            "teamId": self.config.team_id,
            "projectId": self.config.project_id,
            "stateId": state_id,
            "title": title,
            "description": description,
            "priority": priority,
            "labelIds": label_ids,
        }
        if parent_id:
            input_payload["parentId"] = parent_id
        data = self._graphql(mutation, {"input": input_payload}, retryable=False)
        result = data.get("issueCreate")
        if not isinstance(result, dict) or result.get("success") is not True:
            raise LinearApiError("Linear did not confirm CI defect creation.")
        return self._parse_issue(result.get("issue"))

    def update_issue(
        self,
        issue_id: str,
        *,
        description: str | None = None,
        priority: int | None = None,
        state_id: str | None = None,
        label_ids: list[str] | None = None,
    ) -> LinearIssue:
        mutation = f"""
        mutation CiFeedbackUpdateIssue($id: String!, $input: IssueUpdateInput!) {{
          issueUpdate(id: $id, input: $input) {{
            success
            issue {{ {self._ISSUE_FIELDS} }}
          }}
        }}
        """
        input_payload: dict[str, Any] = {}
        if description is not None:
            input_payload["description"] = description
        if priority is not None:
            input_payload["priority"] = priority
        if state_id is not None:
            input_payload["stateId"] = state_id
        if label_ids is not None:
            input_payload["labelIds"] = label_ids
        if not input_payload:
            issue = self.get_issue(issue_id)
            if issue is None:
                raise LinearApiError(f"Linear issue not found: {issue_id}")
            return issue

        data = self._graphql(
            mutation,
            {"id": issue_id, "input": input_payload},
            retryable=False,
        )
        result = data.get("issueUpdate")
        if not isinstance(result, dict) or result.get("success") is not True:
            raise LinearApiError("Linear did not confirm CI defect update.")
        return self._parse_issue(result.get("issue"))

    def create_comment(self, issue_id: str, body: str) -> None:
        mutation = """
        mutation CiFeedbackComment($input: CommentCreateInput!) {
          commentCreate(input: $input) { success }
        }
        """
        data = self._graphql(
            mutation,
            {"input": {"issueId": issue_id, "body": body[:10_000]}},
            retryable=False,
        )
        result = data.get("commentCreate")
        if not isinstance(result, dict) or result.get("success") is not True:
            raise LinearApiError("Linear did not confirm comment creation.")

    def _graphql(self, query: str, variables: dict[str, Any], *, retryable: bool) -> dict[str, Any]:
        payload = self._transport(query, variables, retryable)
        errors = payload.get("errors")
        if errors:
            raise LinearApiError(f"Linear GraphQL returned {len(errors)} error(s).")
        data = payload.get("data")
        if not isinstance(data, dict):
            raise LinearApiError("Linear GraphQL response did not contain a data object.")
        return data

    def _http_transport(self, query: str, variables: dict[str, Any], retryable: bool) -> dict[str, Any]:
        body = json.dumps({"query": query, "variables": variables}).encode("utf-8")
        attempts = 3 if retryable else 1
        for attempt in range(1, attempts + 1):
            request = urllib.request.Request(
                self.config.endpoint,
                data=body,
                headers={
                    "Authorization": self.token,
                    "Content-Type": "application/json",
                    "User-Agent": "lattix-ci-feedback/1",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                    response_body = response.read()
                payload = json.loads(response_body)
                if not isinstance(payload, dict):
                    raise LinearApiError("Linear returned a non-object JSON response.")
                return payload
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                if attempt == attempts:
                    raise LinearApiError("Linear API request failed.") from exc
                delay = min(8.0, (2 ** (attempt - 1)) + random.uniform(0.0, 0.25))
                time.sleep(delay)
        raise AssertionError("unreachable")

    def _parse_issues(self, payload: Any) -> list[LinearIssue]:
        if not isinstance(payload, list):
            raise LinearApiError("Linear returned malformed issue nodes.")
        return [self._parse_issue(item) for item in payload]

    def _parse_issue(self, payload: Any) -> LinearIssue:
        if not isinstance(payload, dict):
            raise LinearApiError("Linear returned a malformed issue.")
        state = payload.get("state")
        labels = payload.get("labels")
        if not isinstance(state, dict) or not isinstance(labels, dict):
            raise LinearApiError("Linear issue omitted state or labels.")
        label_names = tuple(
            node["name"]
            for node in labels.get("nodes") or []
            if isinstance(node, dict) and isinstance(node.get("name"), str)
        )
        required_strings = {
            "id": payload.get("id"),
            "identifier": payload.get("identifier"),
            "title": payload.get("title"),
            "url": payload.get("url"),
            "state_id": state.get("id"),
            "state_name": state.get("name"),
            "state_type": state.get("type"),
        }
        if any(not isinstance(value, str) or not value for value in required_strings.values()):
            raise LinearApiError("Linear issue omitted required fields.")
        return LinearIssue(
            id=required_strings["id"],
            identifier=required_strings["identifier"],
            title=required_strings["title"],
            description=payload.get("description") if isinstance(payload.get("description"), str) else "",
            priority=payload.get("priority") if isinstance(payload.get("priority"), int) else 0,
            url=required_strings["url"],
            state_id=required_strings["state_id"],
            state_name=required_strings["state_name"],
            state_type=required_strings["state_type"],
            labels=label_names,
        )
