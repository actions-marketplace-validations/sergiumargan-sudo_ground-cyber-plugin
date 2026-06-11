"""CLI behavior: init, dry-run isolation, fail-on exit codes, no-secret output."""

import json
import urllib.request

import pytest

import groundcyber.cli as cli
from groundcyber.cli import EXIT_API, EXIT_CONFIG, EXIT_FAIL_ON, EXIT_OK, main
from groundcyber.config import load_config
from groundcyber.github_client import alert_from_payload

RAW_SECRET = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("network access attempted during CLI test")

    monkeypatch.setattr(urllib.request, "urlopen", boom)


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    return tmp_path


def test_init_creates_valid_config(workdir, capsys):
    assert main(["init"]) == EXIT_OK
    config = load_config(str(workdir / ".groundcyber.yml"))
    assert config.outputs == ["markdown", "json"]
    assert main(["init"]) == EXIT_CONFIG  # refuses overwrite
    assert main(["init", "--force"]) == EXIT_OK


def test_version_runs(capsys):
    assert main(["version"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "groundcyber" in out
    assert "read-only" in out


def test_audit_requires_scope(workdir):
    assert main(["audit", "github"]) == EXIT_CONFIG


def test_audit_requires_token(workdir):
    assert main(["audit", "github", "--repo", "acme/api"]) == EXIT_API


def test_dry_run_makes_no_api_calls_and_needs_no_token(workdir, capsys):
    # The autouse no_network fixture asserts if any request is attempted.
    code = main(
        ["audit", "github", "--org", "acme", "--repo", "acme/api", "--dry-run"]
    )
    assert code == EXIT_OK
    out = capsys.readouterr().out
    assert "GET /orgs/acme/secret-scanning/alerts" in out
    assert "GET /repos/acme/api/secret-scanning/alerts" in out


def make_fake_client(alerts):
    class FakeClient:
        def __init__(self, token):
            pass

        def org_alerts(self, org):
            return alerts

        def repo_alerts(self, repo):
            return alerts

        def org_dependabot_alerts(self, org):
            return []

        def org_code_scanning_alerts(self, org):
            return []

        def repo_dependabot_alerts(self, repo):
            return []

        def repo_code_scanning_alerts(self, repo):
            return []

    return FakeClient


def payload(number, state, resolution, validity):
    return {
        "number": number,
        "state": state,
        "secret_type": "github_personal_access_token",
        "secret_type_display_name": "GitHub PAT",
        "secret": RAW_SECRET,
        "resolution": resolution,
        "validity": validity,
        "created_at": "2026-01-01T00:00:00Z",
    }


def run_audit_cli(monkeypatch, workdir, alerts, *extra_args):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setattr(cli, "GitHubClient", make_fake_client(alerts))
    return main(
        ["audit", "github", "--repo", "acme/api", "--out-dir", str(workdir / "out")]
        + list(extra_args)
    )


def test_audit_writes_reports_without_raw_secrets(monkeypatch, workdir, capsys):
    alerts = [
        alert_from_payload(payload(1, "resolved", "revoked", "inactive"), "acme/api"),
        alert_from_payload(payload(2, "resolved", "used_in_tests", "unknown"), "acme/api"),
    ]
    code = run_audit_cli(monkeypatch, workdir, alerts, "--output", "markdown,json")
    assert code == EXIT_OK

    out_dir = workdir / "out"
    md = (out_dir / "groundcyber-report.md").read_text()
    js = (out_dir / "groundcyber-report.json").read_text()
    terminal = capsys.readouterr().out
    for text in (md, js, terminal):
        assert RAW_SECRET not in text

    parsed = json.loads(js)
    assert parsed["summary"]["total"] == 2
    assert parsed["summary"]["verified_closed"] == 1
    assert parsed["summary"]["false_closure_risk"] == 1
    assert "Total alerts scanned: 2" in terminal


def test_fail_on_gcs3(monkeypatch, workdir):
    alerts = [
        alert_from_payload(payload(2, "resolved", "wont_fix", "unknown"), "acme/api"),
    ]
    assert run_audit_cli(monkeypatch, workdir, alerts, "--fail-on-gcs3") == EXIT_FAIL_ON
    assert run_audit_cli(monkeypatch, workdir, alerts) == EXIT_OK


def test_fail_on_gcs4(monkeypatch, workdir):
    alerts = [
        alert_from_payload(payload(3, "open", None, "active"), "acme/api"),
    ]
    assert run_audit_cli(monkeypatch, workdir, alerts, "--fail-on-gcs4") == EXIT_FAIL_ON
    assert run_audit_cli(monkeypatch, workdir, alerts) == EXIT_OK


def test_fail_on_gcs3_does_not_trigger_on_clean_audit(monkeypatch, workdir):
    alerts = [
        alert_from_payload(payload(1, "resolved", "revoked", "inactive"), "acme/api"),
    ]
    code = run_audit_cli(
        monkeypatch, workdir, alerts, "--fail-on-gcs3", "--fail-on-gcs4"
    )
    assert code == EXIT_OK


def test_invalid_output_format_is_config_error(monkeypatch, workdir):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    code = main(["audit", "github", "--repo", "acme/api", "--output", "pdf"])
    assert code == EXIT_CONFIG


def test_redact_repo_names_flag(monkeypatch, workdir):
    alerts = [
        alert_from_payload(payload(1, "resolved", "revoked", "inactive"), "acme/api"),
    ]
    code = run_audit_cli(
        monkeypatch, workdir, alerts, "--redact-repo-names", "--output", "json"
    )
    assert code == EXIT_OK
    js = (workdir / "out" / "groundcyber-report.json").read_text()
    assert "acme/api" not in js
