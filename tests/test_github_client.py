"""GitHub client: raw-secret sanitization, GET-only guarantee, fail-closed audit."""

import hashlib
import json
import urllib.request

import pytest

from groundcyber.audit import run_audit
from groundcyber.config import Config
from groundcyber.github_client import (
    GitHubClient,
    GitHubError,
    _next_link,
    alert_from_payload,
    sanitize_alert_payload,
)

RAW_SECRET = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"


def alert_payload(**overrides):
    payload = {
        "number": 42,
        "state": "resolved",
        "secret_type": "github_personal_access_token",
        "secret_type_display_name": "GitHub Personal Access Token",
        "secret": RAW_SECRET,
        "resolution": "revoked",
        "validity": "unknown",
        "created_at": "2026-01-01T00:00:00Z",
        "resolved_at": "2026-02-01T00:00:00Z",
        "resolved_by": {"login": "alice"},
        "publicly_leaked": False,
        "html_url": "https://github.com/acme/api/security/secret-scanning/42",
    }
    payload.update(overrides)
    return payload


def test_sanitize_hashes_and_discards_raw_secret():
    raw = alert_payload()
    sanitized = sanitize_alert_payload(raw)
    expected = hashlib.sha256(RAW_SECRET.encode()).hexdigest()
    assert sanitized["secret_hash"] == expected
    assert "secret" not in sanitized
    assert "secret" not in raw  # input dict is purged too
    assert RAW_SECRET not in json.dumps(sanitized)


def test_sanitize_handles_missing_secret_field():
    sanitized = sanitize_alert_payload(alert_payload(secret=None))
    assert sanitized["secret_hash"] is None


def test_alert_from_payload_never_carries_raw_secret():
    alert = alert_from_payload(alert_payload(), "acme/api")
    assert RAW_SECRET not in repr(alert)
    assert alert.secret_hash == hashlib.sha256(RAW_SECRET.encode()).hexdigest()
    assert alert.number == 42
    assert alert.resolved_by == "alice"


def test_client_only_issues_get_requests(monkeypatch):
    captured = []

    class FakeResponse:
        headers = {}

        def read(self):
            return b"[]"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def fake_urlopen(request, timeout=0):
        captured.append(request)
        return FakeResponse()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    client = GitHubClient("token")
    client.repo_alerts("acme/api")
    client.org_alerts("acme")
    client.rate_limit()
    assert captured, "no requests captured"
    for request in captured:
        assert request.get_method() == "GET"


def test_pagination_link_parsing():
    header = (
        '<https://api.github.com/repos/a/b/secret-scanning/alerts?page=2>; rel="next", '
        '<https://api.github.com/repos/a/b/secret-scanning/alerts?page=5>; rel="last"'
    )
    assert _next_link(header) == (
        "https://api.github.com/repos/a/b/secret-scanning/alerts?page=2"
    )
    assert _next_link('<https://x>; rel="last"') is None
    assert _next_link("") is None


class FailingClient:
    def org_alerts(self, org):
        raise GitHubError("HTTP 403: org access denied", 403)

    def repo_alerts(self, repo):
        raise GitHubError("HTTP 500: upstream error", 500)

    org_dependabot_alerts = org_alerts
    org_code_scanning_alerts = org_alerts
    repo_dependabot_alerts = repo_alerts
    repo_code_scanning_alerts = repo_alerts


def test_audit_with_api_failures_fails_closed():
    """API failures must surface as errors, never as a clean/safe report."""
    config = Config(org="acme", repos=["acme/api"])
    result = run_audit(FailingClient(), config)
    assert result.findings == []
    # one org error and one repo error per enabled alert family
    assert len(result.errors) == 2 * len(config.families)
    assert any("unverified" in e or "incomplete" in e for e in result.errors)
    # Nothing in a failed audit may claim verified closure.
    assert all(not f.closure_confirmed for f in result.findings)


class FakeClient:
    def __init__(self, org_alerts=(), repo_alerts=()):
        self._org = list(org_alerts)
        self._repo = list(repo_alerts)

    def org_alerts(self, org):
        return self._org

    def repo_alerts(self, repo):
        return self._repo

    def org_dependabot_alerts(self, org):
        return []

    def org_code_scanning_alerts(self, org):
        return []

    def repo_dependabot_alerts(self, repo):
        return []

    def repo_code_scanning_alerts(self, repo):
        return []


def test_audit_applies_include_exclude_filters():
    org_alerts = [
        alert_from_payload(alert_payload(number=1), "acme/api"),
        alert_from_payload(alert_payload(number=2), "acme/sandbox-x"),
    ]
    config = Config(org="acme", exclude_repos=["acme/sandbox-*"])
    result = run_audit(FakeClient(org_alerts=org_alerts), config)
    repos = {f.alert.repo for f in result.findings}
    assert repos == {"acme/api"}


def test_audit_dedupes_org_and_repo_overlap():
    alert = alert_from_payload(alert_payload(number=1), "acme/api")
    config = Config(org="acme", repos=["acme/api"])
    result = run_audit(
        FakeClient(org_alerts=[alert], repo_alerts=[alert]), config
    )
    assert len(result.findings) == 1


def test_github_error_message_is_redacted():
    err = GitHubError(f"GET /x failed: leaked {RAW_SECRET} in error body")
    assert RAW_SECRET not in str(err)


def test_retry_then_failure(monkeypatch):
    client = GitHubClient("token", max_retries=2, sleep=lambda s: None)

    import urllib.error

    calls = {"n": 0}

    def fake_urlopen(request, timeout=0):
        calls["n"] += 1
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(GitHubError):
        client.rate_limit()
    assert calls["n"] == 3  # initial + 2 retries
