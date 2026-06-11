"""Read-only GitHub API client.

Guarantees enforced here:
- Only HTTP GET requests are ever issued. Any other method raises before a
  connection is opened.
- Raw secret values returned by the secret-scanning API are hashed with
  SHA-256 the moment the response is parsed; the raw value is discarded and
  never stored on any object this module returns.
- Alert state is never modified; there is no code path that writes.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Iterator, Optional

import base64

from . import __version__
from .models import FAMILY_CODE_SCANNING, FAMILY_DEPENDABOT, Alert
from .redact import hash_secret, redact_text

API_ROOT = "https://api.github.com"
USER_AGENT = f"groundcyber/{__version__} (read-only closure audit)"


class GitHubError(RuntimeError):
    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(redact_text(message))
        self.status = status


class ReadOnlyViolation(RuntimeError):
    """Raised if anything attempts a non-GET request. This must never fire."""


def _normalize_severity(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    value = value.lower()
    return value if value in ("critical", "high", "medium", "low") else value or None


def dependabot_alert_from_payload(raw: dict[str, Any], repo_full_name: str) -> Alert:
    dependency = raw.get("dependency") or {}
    package = dependency.get("package") or {}
    advisory = raw.get("security_advisory") or {}
    vulnerability = raw.get("security_vulnerability") or {}
    first_patched = vulnerability.get("first_patched_version") or {}
    dismisser = raw.get("dismissed_by")
    return Alert(
        number=raw.get("number", 0),
        repo=repo_full_name,
        family=FAMILY_DEPENDABOT,
        state=raw.get("state") or "open",
        severity=_normalize_severity(
            vulnerability.get("severity") or advisory.get("severity")
        ),
        dismissed_reason=raw.get("dismissed_reason"),
        dismissed_comment=raw.get("dismissed_comment"),
        created_at=raw.get("created_at"),
        updated_at=raw.get("updated_at"),
        fixed_at=raw.get("fixed_at"),
        resolved_at=raw.get("fixed_at") or raw.get("dismissed_at"),
        resolved_by=dismisser.get("login") if isinstance(dismisser, dict) else None,
        html_url=raw.get("html_url"),
        package_name=package.get("name"),
        package_ecosystem=package.get("ecosystem"),
        manifest_path=dependency.get("manifest_path"),
        vulnerable_range=vulnerability.get("vulnerable_version_range"),
        first_patched_version=first_patched.get("identifier"),
        advisory_id=advisory.get("ghsa_id") or advisory.get("cve_id"),
    )


def code_scanning_alert_from_payload(raw: dict[str, Any], repo_full_name: str) -> Alert:
    rule = raw.get("rule") or {}
    tool = raw.get("tool") or {}
    dismisser = raw.get("dismissed_by")
    return Alert(
        number=raw.get("number", 0),
        repo=repo_full_name,
        family=FAMILY_CODE_SCANNING,
        state=raw.get("state") or "open",
        severity=_normalize_severity(
            rule.get("security_severity_level") or rule.get("severity")
        ),
        dismissed_reason=raw.get("dismissed_reason"),
        dismissed_comment=raw.get("dismissed_comment"),
        created_at=raw.get("created_at"),
        updated_at=raw.get("updated_at"),
        fixed_at=raw.get("fixed_at"),
        resolved_at=raw.get("fixed_at") or raw.get("dismissed_at"),
        resolved_by=dismisser.get("login") if isinstance(dismisser, dict) else None,
        html_url=raw.get("html_url"),
        rule_id=rule.get("id") or rule.get("name"),
        rule_description=rule.get("description"),
        tool_name=tool.get("name"),
    )


def sanitize_alert_payload(raw: dict[str, Any]) -> dict[str, Any]:
    """Hash and remove the raw secret value from an API alert payload.

    Returns a new dict; the input dict also has its 'secret' key removed so
    no caller can accidentally retain the raw value.
    """
    secret_value = raw.pop("secret", None)
    sanitized = dict(raw)
    sanitized.pop("secret", None)
    if isinstance(secret_value, str) and secret_value:
        sanitized["secret_hash"] = hash_secret(secret_value)
        del secret_value
    else:
        sanitized["secret_hash"] = None
    return sanitized


def alert_from_payload(raw: dict[str, Any], repo_full_name: str) -> Alert:
    sanitized = sanitize_alert_payload(raw)
    return Alert(
        number=sanitized.get("number", 0),
        repo=repo_full_name,
        state=sanitized.get("state") or "open",
        secret_type=sanitized.get("secret_type") or "unknown",
        secret_type_display=(
            sanitized.get("secret_type_display_name")
            or sanitized.get("secret_type")
            or "unknown"
        ),
        resolution=sanitized.get("resolution"),
        validity=sanitized.get("validity"),
        secret_hash=sanitized.get("secret_hash"),
        created_at=sanitized.get("created_at"),
        updated_at=sanitized.get("updated_at"),
        resolved_at=sanitized.get("resolved_at"),
        resolved_by=(sanitized.get("resolved_by") or {}).get("login")
        if isinstance(sanitized.get("resolved_by"), dict)
        else None,
        publicly_leaked=sanitized.get("publicly_leaked"),
        multi_repo=sanitized.get("multi_repo"),
        push_protection_bypassed=sanitized.get("push_protection_bypassed"),
        html_url=sanitized.get("html_url"),
    )


class GitHubClient:
    def __init__(
        self,
        token: str,
        api_root: str = API_ROOT,
        max_retries: int = 3,
        sleep=time.sleep,
    ):
        self.token = token
        self.api_root = api_root.rstrip("/")
        self.max_retries = max_retries
        self._sleep = sleep

    # ── transport ────────────────────────────────────────────────────────
    def _get(self, path: str, params: Optional[dict[str, str]] = None) -> tuple[Any, dict[str, str]]:
        """Issue a GET request. Returns (parsed_json, response_headers)."""
        url = path if path.startswith("http") else f"{self.api_root}{path}"
        if params:
            sep = "&" if "?" in url else "?"
            url = url + sep + urllib.parse.urlencode(params)

        request = urllib.request.Request(
            url,
            method="GET",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": USER_AGENT,
            },
        )
        if request.get_method() != "GET":
            raise ReadOnlyViolation(
                f"non-GET request blocked: {request.get_method()} {url}"
            )

        last_error: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    body = response.read().decode("utf-8")
                    headers = {k.lower(): v for k, v in response.headers.items()}
                    return (json.loads(body) if body else None), headers
            except urllib.error.HTTPError as exc:
                detail = ""
                try:
                    detail = json.loads(exc.read().decode("utf-8")).get("message", "")
                except Exception:
                    pass
                if exc.code in (429, 502, 503) or (
                    exc.code == 403 and "rate limit" in detail.lower()
                ):
                    last_error = GitHubError(
                        f"GET {path} failed with {exc.code}: {detail}", exc.code
                    )
                    if attempt < self.max_retries:
                        self._sleep(2**attempt)
                        continue
                raise GitHubError(
                    f"GET {path} failed with {exc.code}: {detail}", exc.code
                ) from exc
            except urllib.error.URLError as exc:
                last_error = GitHubError(f"GET {path} failed: {exc.reason}")
                if attempt < self.max_retries:
                    self._sleep(2**attempt)
                    continue
                raise last_error from exc
        raise last_error or GitHubError(f"GET {path} failed")

    def _paginate(
        self, path: str, params: Optional[dict[str, str]] = None
    ) -> Iterator[Any]:
        params = dict(params or {})
        params.setdefault("per_page", "100")
        url: Optional[str] = path
        first = True
        while url:
            data, headers = self._get(url, params if first else None)
            first = False
            if isinstance(data, list):
                yield from data
            else:
                yield data
            url = _next_link(headers.get("link", ""))

    # ── read-only endpoints ──────────────────────────────────────────────
    def rate_limit(self) -> dict[str, Any]:
        data, _ = self._get("/rate_limit")
        return data

    def current_user(self) -> tuple[dict[str, Any], dict[str, str]]:
        return self._get("/user")

    def repo_alerts(self, repo_full_name: str) -> list[Alert]:
        owner_repo = repo_full_name.strip("/")
        path = f"/repos/{owner_repo}/secret-scanning/alerts"
        return [
            alert_from_payload(item, owner_repo)
            for item in self._paginate(path)
            if isinstance(item, dict)
        ]

    def org_alerts(self, org: str) -> list[Alert]:
        path = f"/orgs/{org}/secret-scanning/alerts"
        alerts = []
        for item in self._paginate(path):
            if not isinstance(item, dict):
                continue
            repo = (item.get("repository") or {}).get("full_name") or "unknown/unknown"
            alerts.append(alert_from_payload(item, repo))
        return alerts

    def repo_dependabot_alerts(self, repo_full_name: str) -> list[Alert]:
        owner_repo = repo_full_name.strip("/")
        path = f"/repos/{owner_repo}/dependabot/alerts"
        return [
            dependabot_alert_from_payload(item, owner_repo)
            for item in self._paginate(path)
            if isinstance(item, dict)
        ]

    def org_dependabot_alerts(self, org: str) -> list[Alert]:
        alerts = []
        for item in self._paginate(f"/orgs/{org}/dependabot/alerts"):
            if not isinstance(item, dict):
                continue
            repo = (item.get("repository") or {}).get("full_name") or "unknown/unknown"
            alerts.append(dependabot_alert_from_payload(item, repo))
        return alerts

    def repo_code_scanning_alerts(self, repo_full_name: str) -> list[Alert]:
        owner_repo = repo_full_name.strip("/")
        path = f"/repos/{owner_repo}/code-scanning/alerts"
        return [
            code_scanning_alert_from_payload(item, owner_repo)
            for item in self._paginate(path)
            if isinstance(item, dict)
        ]

    def org_code_scanning_alerts(self, org: str) -> list[Alert]:
        alerts = []
        for item in self._paginate(f"/orgs/{org}/code-scanning/alerts"):
            if not isinstance(item, dict):
                continue
            repo = (item.get("repository") or {}).get("full_name") or "unknown/unknown"
            alerts.append(code_scanning_alert_from_payload(item, repo))
        return alerts

    def fetch_file_text(self, repo_full_name: str, path: str) -> Optional[str]:
        """Read a repository file (read-only contents API). None if unavailable."""
        owner_repo = repo_full_name.strip("/")
        clean_path = path.lstrip("/")
        try:
            data, _ = self._get(f"/repos/{owner_repo}/contents/{clean_path}")
        except GitHubError:
            return None
        if not isinstance(data, dict) or data.get("encoding") != "base64":
            return None
        try:
            return base64.b64decode(data.get("content") or "").decode(
                "utf-8", errors="replace"
            )
        except (ValueError, TypeError):
            return None

    def latest_analysis_time(
        self, repo_full_name: str, tool_name: Optional[str]
    ) -> Optional[str]:
        """Timestamp of the most recent code-scanning analysis for a tool.

        Returns None when the analyses API is unavailable — callers must
        treat that as 'continuity unknown', never as evidence.
        """
        owner_repo = repo_full_name.strip("/")
        params = {"per_page": "1"}
        if tool_name:
            params["tool_name"] = tool_name
        try:
            data, _ = self._get(
                f"/repos/{owner_repo}/code-scanning/analyses", params
            )
        except GitHubError:
            return None
        if isinstance(data, list) and data and isinstance(data[0], dict):
            return data[0].get("created_at")
        return None

    _PROBE_PATHS = {
        "secret_scanning": "secret-scanning/alerts",
        "dependabot": "dependabot/alerts",
        "code_scanning": "code-scanning/alerts",
    }

    def probe_alert_family(
        self, family: str, org: str = "", repo: str = ""
    ) -> tuple[bool, str]:
        """Check alert API access for a family without retrieving secrets."""
        suffix = self._PROBE_PATHS.get(family)
        if suffix is None:
            return False, f"unknown alert family {family!r}"
        if org:
            path = f"/orgs/{org}/{suffix}"
        elif repo:
            path = f"/repos/{repo}/{suffix}"
        else:
            return False, "no org or repo provided to probe"
        try:
            self._get(path, {"per_page": "1"})
            return True, f"{suffix} API reachable"
        except GitHubError as exc:
            return False, str(exc)

    def probe_secret_scanning(self, org: str = "", repo: str = "") -> tuple[bool, str]:
        """Check secret-scanning API access without retrieving secret values."""
        return self.probe_alert_family("secret_scanning", org=org, repo=repo)


def _next_link(link_header: str) -> Optional[str]:
    for part in link_header.split(","):
        section = part.split(";")
        if len(section) < 2:
            continue
        if 'rel="next"' in section[1]:
            return section[0].strip().strip("<>")
    return None
