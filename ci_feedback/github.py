from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class GitHubApiError(RuntimeError):
    """Raised when a trusted GitHub API read cannot be completed."""


class GitHubClient:
    def __init__(
        self,
        repository: str,
        token: str,
        *,
        api_url: str = "https://api.github.com",
        timeout_seconds: int = 30,
    ) -> None:
        self.repository = repository
        self.token = token
        self.api_url = api_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def list_workflow_jobs(self, workflow_run_id: int) -> list[dict[str, Any]]:
        return self._list_paginated(
            f"/repos/{self.repository}/actions/runs/{workflow_run_id}/jobs",
            collection_key="jobs",
        )

    def get_pull_request(self, number: int) -> dict[str, Any]:
        payload = self._request_json(f"/repos/{self.repository}/pulls/{number}")
        if not isinstance(payload, dict):
            raise GitHubApiError("GitHub returned a malformed pull-request response.")
        return payload

    def list_pull_request_files(self, number: int) -> list[str]:
        files = self._list_paginated(
            f"/repos/{self.repository}/pulls/{number}/files",
            collection_key=None,
        )
        result: list[str] = []
        for item in files:
            filename = item.get("filename")
            if isinstance(filename, str) and filename:
                result.append(filename)
        return result

    def _list_paginated(self, path: str, collection_key: str | None) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        page = 1
        while True:
            separator = "&" if "?" in path else "?"
            payload = self._request_json(f"{path}{separator}per_page=100&page={page}")
            collection = payload.get(collection_key) if collection_key and isinstance(payload, dict) else payload
            if not isinstance(collection, list):
                raise GitHubApiError(f"GitHub returned a malformed paginated response for {path}.")
            valid_items = [item for item in collection if isinstance(item, dict)]
            results.extend(valid_items)
            if len(collection) < 100:
                return results
            page += 1
            if page > 100:
                raise GitHubApiError(f"GitHub pagination exceeded the safety limit for {path}.")

    def _request_json(self, path: str) -> Any:
        request = urllib.request.Request(
            f"{self.api_url}{path}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "User-Agent": "lattix-ci-feedback/1",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                body = response.read()
        except urllib.error.HTTPError as exc:
            raise GitHubApiError(f"GitHub API request failed with HTTP {exc.code}.") from exc
        except urllib.error.URLError as exc:
            raise GitHubApiError("GitHub API request failed.") from exc

        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise GitHubApiError("GitHub returned invalid JSON.") from exc
