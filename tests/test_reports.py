"""Report generation: structure, redaction, and the no-raw-secret guarantee."""

import json

from groundcyber.config import Config
from groundcyber.models import GCS, Alert, AuditResult
from groundcyber.report import (
    build_json,
    render_html,
    render_json,
    render_markdown,
    summary_block,
    write_reports,
)
from groundcyber.scoring import score_alerts

RAW_SECRET = "ghp_" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"


def build_result(config=None) -> AuditResult:
    config = config or Config()
    alerts = [
        Alert(
            number=1842,
            repo="acme/payments-api",
            state="resolved",
            secret_type="github_pat",
            # A hostile/buggy upstream value: a raw secret inside a text field.
            secret_type_display=f"GitHub PAT {RAW_SECRET}",
            resolution="used_in_tests",
            validity="unknown",
            resolved_at="2026-05-01T00:00:00Z",
        ),
        Alert(
            number=7,
            repo="acme/payments-api",
            state="resolved",
            secret_type="aws_access_key_id",
            secret_type_display="AWS Access Key ID",
            resolution="revoked",
            validity="inactive",
        ),
        Alert(
            number=9,
            repo="acme/infra",
            state="open",
            secret_type="slack_api_token",
            secret_type_display="Slack API Token",
            validity="active",
        ),
        Alert(
            number=12,
            repo="acme/infra",
            state="open",
            secret_type="stripe_api_key",
            secret_type_display="Stripe API Key",
            validity=None,
        ),
    ]
    findings = score_alerts(alerts, config)
    return AuditResult(
        findings=findings,
        scope_description="GitHub Secret Scanning alerts — organization 'acme'",
        generated_at="2026-06-11T12:00:00Z",
        errors=["Failed to fetch alerts for 'acme/legacy': HTTP 403"],
    )


def test_summary_block_counts_and_highest_risk():
    result = build_result()
    summary = summary_block(result)
    assert "Total alerts scanned: 4" in summary
    assert "Verified closed: 1" in summary
    assert "False-closure risk: 1" in summary
    assert "Active risk: 1" in summary
    assert "Highest-risk finding:" in summary
    assert "GCS-4" in summary


def test_markdown_report_structure():
    md = render_markdown(build_result(), Config())
    for section in (
        "# Ground Cyber Closure Report",
        "## Executive summary",
        "## Scope",
        "## Methodology",
        "## Security and privacy model",
        "## Closure summary",
        "## Findings",
        "## Per-alert reasoning",
        "## Recommended remediation order",
        "## Limitations",
        "## Evidence appendix",
    ):
        assert section in md
    assert "used_in_tests" in md
    assert "Closure confirmed:** true" in md  # the verified one
    assert "Data-collection errors (fail-closed)" in md


def test_no_raw_secret_in_any_report_format():
    result = build_result()
    config = Config(outputs=["markdown", "json", "html"])
    for rendered in (
        render_markdown(result, config),
        render_json(result, config),
        render_html(result, config),
        summary_block(result),
    ):
        assert RAW_SECRET not in rendered
        assert "[REDACTED-SECRET:sha256:" in rendered or "ghp_" not in rendered


def test_json_report_has_no_secret_key_anywhere():
    payload = build_json(build_result(), Config())

    def walk(node):
        if isinstance(node, dict):
            assert "secret" not in node
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(payload)
    assert payload["summary"]["total"] == 4
    assert payload["summary"]["verified_closed"] == 1
    by_number = {f["alert_number"]: f for f in payload["findings"]}
    assert by_number[7]["closure_confirmed"] is True
    assert by_number[7]["gcs"] == "GCS-0"
    assert by_number[1842]["gcs"] == "GCS-3"
    assert by_number[1842]["closure_confirmed"] is False
    assert by_number[9]["gcs"] == "GCS-4"
    assert by_number[12]["gcs"] == "GCS-2"


def test_json_is_valid_and_states_closure_rule():
    parsed = json.loads(render_json(build_result(), Config()))
    assert "defensible evidence chain" in parsed["closure_rule"]
    assert "provider " in parsed["closure_rule"] or "validity" in parsed["closure_rule"]


def test_repo_name_redaction():
    config = Config(redact_repo_names=True)
    md = render_markdown(build_result(config), config)
    js = render_json(build_result(config), config)
    for rendered in (md, js):
        assert "acme/payments-api" not in rendered
        assert "acme/infra" not in rendered
        assert "repo-" in rendered


def test_write_reports_creates_requested_files(tmp_path):
    config = Config(outputs=["markdown", "json", "html"])
    written = write_reports(build_result(), config, str(tmp_path))
    names = sorted(p.name for p in written)
    assert names == [
        "groundcyber-report.html",
        "groundcyber-report.json",
        "groundcyber-report.md",
    ]
    for path in written:
        assert path.exists()
        assert RAW_SECRET not in path.read_text()


def test_empty_result_renders():
    result = AuditResult(findings=[], scope_description="repo 'a/b'",
                         generated_at="2026-06-11T12:00:00Z")
    md = render_markdown(result, Config())
    assert "No alerts were found" in md
    assert summary_block(result).count("0") >= 5
    assert result.highest_risk is None
