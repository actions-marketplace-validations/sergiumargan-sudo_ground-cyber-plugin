"""Evidence enrichment: payload parsing, continuity, and report fields."""

import json

from groundcyber.audit import (
    enrich_code_scanning_evidence,
    enrich_dependabot_evidence,
    run_audit,
)
from groundcyber.config import Config
from groundcyber.github_client import (
    code_scanning_alert_from_payload,
    dependabot_alert_from_payload,
)
from groundcyber.models import FAMILY_CODE_SCANNING, FAMILY_DEPENDABOT, GCS, Alert
from groundcyber.report import build_json
from groundcyber.models import AuditResult
from groundcyber.scoring import score_alerts


def test_dependabot_payload_parsing():
    payload = {
        "number": 7,
        "state": "dismissed",
        "dismissed_reason": "tolerable_risk",
        "dismissed_comment": "accepted for dev",
        "dependency": {
            "package": {"name": "lodash", "ecosystem": "npm"},
            "manifest_path": "package-lock.json",
        },
        "security_advisory": {"ghsa_id": "GHSA-xxxx", "severity": "high"},
        "security_vulnerability": {
            "severity": "high",
            "vulnerable_version_range": "< 4.17.21",
            "first_patched_version": {"identifier": "4.17.21"},
        },
        "created_at": "2026-01-01T00:00:00Z",
        "html_url": "https://github.com/acme/api/security/dependabot/7",
    }
    alert = dependabot_alert_from_payload(payload, "acme/api")
    assert alert.family == FAMILY_DEPENDABOT
    assert alert.package_name == "lodash"
    assert alert.vulnerable_range == "< 4.17.21"
    assert alert.first_patched_version == "4.17.21"
    assert alert.severity == "high"
    assert alert.dismissed_reason == "tolerable_risk"


def test_code_scanning_payload_parsing():
    payload = {
        "number": 3,
        "state": "fixed",
        "fixed_at": "2026-06-01T00:00:00Z",
        "rule": {
            "id": "js/sql-injection",
            "description": "SQL injection",
            "security_severity_level": "critical",
        },
        "tool": {"name": "CodeQL"},
        "created_at": "2026-01-01T00:00:00Z",
    }
    alert = code_scanning_alert_from_payload(payload, "acme/api")
    assert alert.family == FAMILY_CODE_SCANNING
    assert alert.rule_id == "js/sql-injection"
    assert alert.tool_name == "CodeQL"
    assert alert.severity == "critical"
    assert alert.fixed_at == "2026-06-01T00:00:00Z"


class StubClient:
    def __init__(self, file_text=None, latest_analysis=None):
        self._file_text = file_text
        self._latest = latest_analysis

    def fetch_file_text(self, repo, path):
        return self._file_text

    def latest_analysis_time(self, repo, tool_name):
        return self._latest


def _fixed_dependabot_alert():
    return Alert(
        number=1,
        repo="acme/api",
        family=FAMILY_DEPENDABOT,
        state="fixed",
        package_name="lodash",
        manifest_path="package-lock.json",
        vulnerable_range="< 4.17.21",
        fixed_at="2026-06-01T00:00:00Z",
    )


def test_dependabot_enrichment_confirms_fix():
    alert = _fixed_dependabot_alert()
    lock = json.dumps({"packages": {"node_modules/lodash": {"version": "4.17.21"}}})
    enrich_dependabot_evidence(StubClient(file_text=lock), alert)
    assert alert.manifest_verified is True


def test_dependabot_enrichment_unreadable_manifest_fails_closed():
    alert = _fixed_dependabot_alert()
    enrich_dependabot_evidence(StubClient(file_text=None), alert)
    assert alert.manifest_verified is None
    assert "could not be read" in alert.manifest_verification_note


def _fixed_code_alert():
    return Alert(
        number=2,
        repo="acme/api",
        family=FAMILY_CODE_SCANNING,
        state="fixed",
        tool_name="CodeQL",
        fixed_at="2026-06-01T00:00:00Z",
    )


def test_continuity_confirmed_when_analysis_after_fix():
    alert = _fixed_code_alert()
    enrich_code_scanning_evidence(
        StubClient(latest_analysis="2026-06-10T00:00:00Z"), alert
    )
    assert alert.scan_continuity is True


def test_continuity_drift_when_analysis_predates_fix():
    alert = _fixed_code_alert()
    enrich_code_scanning_evidence(
        StubClient(latest_analysis="2026-05-01T00:00:00Z"), alert
    )
    assert alert.scan_continuity is False


def test_continuity_unknown_when_analyses_unreadable():
    alert = _fixed_code_alert()
    enrich_code_scanning_evidence(StubClient(latest_analysis=None), alert)
    assert alert.scan_continuity is None


def test_json_report_carries_evidence_fields():
    alerts = [
        Alert(
            number=1,
            repo="acme/api",
            family=FAMILY_DEPENDABOT,
            state="dismissed",
            dismissed_reason="no_bandwidth",
            package_name="lodash",
            vulnerable_range="< 4.17.21",
            severity="high",
        ),
    ]
    findings = score_alerts(alerts, Config())
    result = AuditResult(
        findings=findings,
        scope_description="repo acme/api",
        generated_at="2026-06-11T12:00:00Z",
    )
    payload = build_json(result, Config())
    finding = payload["findings"][0]
    for key in (
        "family",
        "closure_claim",
        "evidence_chain",
        "evidence_strength",
        "evidence_source",
        "proof_grade",
        "why_not_gcs0",
        "recommended_next_evidence",
    ):
        assert key in finding, key
    assert finding["gcs"] == "GCS-3"
    assert finding["proof_grade"] == "administrative"
    assert finding["why_not_gcs0"]


def test_org_audit_covers_all_enabled_families():
    calls = []

    class RecordingClient:
        def org_alerts(self, org):
            calls.append("secret")
            return []

        def org_dependabot_alerts(self, org):
            calls.append("dependabot")
            return []

        def org_code_scanning_alerts(self, org):
            calls.append("code")
            return []

    run_audit(RecordingClient(), Config(org="acme"))
    assert calls == ["secret", "dependabot", "code"]


def test_family_filter_limits_fetches():
    calls = []

    class RecordingClient:
        def repo_alerts(self, repo):
            calls.append("secret")
            return []

        def repo_dependabot_alerts(self, repo):
            calls.append("dependabot")
            return []

        def repo_code_scanning_alerts(self, repo):
            calls.append("code")
            return []

    run_audit(
        RecordingClient(),
        Config(repos=["acme/api"], families=["dependabot"]),
    )
    assert calls == ["dependabot"]
