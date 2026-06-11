"""Evidence-chain rules: platform state alone must never produce GCS-0."""

from datetime import datetime, timezone

from groundcyber.config import Config
from groundcyber.models import (
    EVIDENCE_MODERATE,
    EVIDENCE_STRONG,
    FAMILY_CODE_SCANNING,
    FAMILY_DEPENDABOT,
    GCS,
    PROOF_ADMINISTRATIVE,
    PROOF_INDEPENDENT_VERIFICATION,
    PROOF_PLATFORM_STATE,
    PROOF_SCANNER_VERIFIED,
    Alert,
)
from groundcyber.scoring import (
    score_code_scanning_alert,
    score_dependabot_alert,
)

NOW = datetime(2026, 6, 11, 12, 0, 0, tzinfo=timezone.utc)


def dependabot_alert(**kwargs) -> Alert:
    defaults = dict(
        number=10,
        repo="acme/api",
        family=FAMILY_DEPENDABOT,
        state="open",
        severity="high",
        package_name="lodash",
        package_ecosystem="npm",
        manifest_path="package-lock.json",
        vulnerable_range="< 4.17.21",
        first_patched_version="4.17.21",
    )
    defaults.update(kwargs)
    return Alert(**defaults)


def code_alert(**kwargs) -> Alert:
    defaults = dict(
        number=20,
        repo="acme/api",
        family=FAMILY_CODE_SCANNING,
        state="open",
        severity="high",
        rule_id="js/sql-injection",
        tool_name="CodeQL",
    )
    defaults.update(kwargs)
    return Alert(**defaults)


# ── Dependabot ──────────────────────────────────────────────────────────────
def test_dependabot_fixed_alone_is_not_gcs0():
    """Platform-reported fixed without independent verification caps at GCS-1."""
    finding = score_dependabot_alert(
        dependabot_alert(state="fixed", fixed_at="2026-06-01T00:00:00Z"),
        Config(),
        now=NOW,
    )
    assert finding.gcs is GCS.LOW_RESIDUAL_RISK
    assert finding.closure_confirmed is False
    assert finding.proof_grade == PROOF_PLATFORM_STATE
    assert finding.evidence_strength == EVIDENCE_MODERATE
    assert finding.why_not_gcs0


def test_dependabot_fixed_with_manifest_verification_is_gcs0():
    finding = score_dependabot_alert(
        dependabot_alert(
            state="fixed",
            fixed_at="2026-06-01T00:00:00Z",
            manifest_verified=True,
            manifest_verification_note="all present versions outside the range",
        ),
        Config(),
        now=NOW,
    )
    assert finding.gcs is GCS.VERIFIED_CLOSED
    assert finding.closure_confirmed is True
    assert finding.proof_grade == PROOF_INDEPENDENT_VERIFICATION
    assert finding.evidence_strength == EVIDENCE_STRONG
    assert finding.why_not_gcs0 == ""


def test_dependabot_fixed_contradicted_by_manifest_is_active_risk():
    finding = score_dependabot_alert(
        dependabot_alert(
            state="fixed",
            manifest_verified=False,
            manifest_verification_note="version 4.17.0 still inside '< 4.17.21'",
        ),
        Config(),
        now=NOW,
    )
    assert finding.gcs is GCS.ACTIVE_RISK
    assert finding.closure_confirmed is False


def test_dependabot_dismissals_are_never_gcs0():
    for state, reason in [
        ("dismissed", "tolerable_risk"),
        ("dismissed", "no_bandwidth"),
        ("dismissed", "inaccurate"),
        ("dismissed", "not_used"),
        ("dismissed", None),
        ("auto_dismissed", None),
    ]:
        finding = score_dependabot_alert(
            dependabot_alert(state=state, dismissed_reason=reason),
            Config(),
            now=NOW,
        )
        assert finding.gcs is GCS.FALSE_CLOSURE_RISK, (state, reason)
        assert finding.closure_confirmed is False
        assert finding.proof_grade == PROOF_ADMINISTRATIVE


def test_dependabot_dismissal_comment_is_risk_acceptance_not_closure():
    finding = score_dependabot_alert(
        dependabot_alert(
            state="dismissed",
            dismissed_reason="tolerable_risk",
            dismissed_comment="we accept this in the dev environment",
        ),
        Config(),
        now=NOW,
    )
    assert finding.gcs is GCS.FALSE_CLOSURE_RISK
    assert any("risk acceptance" in e for e in finding.evidence_chain)


def test_dependabot_open_severity_mapping():
    high = score_dependabot_alert(
        dependabot_alert(state="open", severity="critical"), Config(), now=NOW
    )
    assert high.gcs is GCS.ACTIVE_RISK
    low = score_dependabot_alert(
        dependabot_alert(state="open", severity="low"), Config(), now=NOW
    )
    assert low.gcs is GCS.PROVISIONAL


def test_dependabot_fetch_error_fails_closed():
    finding = score_dependabot_alert(
        dependabot_alert(state="fixed", manifest_verified=True,
                         fetch_error="HTTP 500"),
        Config(),
        now=NOW,
    )
    assert finding.gcs is GCS.PROVISIONAL
    assert finding.closure_confirmed is False


# ── Code scanning ───────────────────────────────────────────────────────────
def test_code_scanning_fixed_alone_is_not_gcs0():
    finding = score_code_scanning_alert(
        code_alert(state="fixed", fixed_at="2026-06-01T00:00:00Z"),
        Config(),
        now=NOW,
    )
    assert finding.gcs is GCS.PROVISIONAL
    assert finding.closure_confirmed is False
    assert finding.why_not_gcs0


def test_code_scanning_fixed_with_continuity_is_gcs0():
    finding = score_code_scanning_alert(
        code_alert(
            state="fixed",
            fixed_at="2026-06-01T00:00:00Z",
            scan_continuity=True,
            scan_continuity_note="CodeQL uploaded an analysis after the fix",
        ),
        Config(),
        now=NOW,
    )
    assert finding.gcs is GCS.VERIFIED_CLOSED
    assert finding.closure_confirmed is True
    assert finding.proof_grade == PROOF_SCANNER_VERIFIED


def test_code_scanning_scanner_drift_is_false_closure_risk():
    finding = score_code_scanning_alert(
        code_alert(
            state="fixed",
            scan_continuity=False,
            scan_continuity_note="no CodeQL analysis since before the fix",
        ),
        Config(),
        now=NOW,
    )
    assert finding.gcs is GCS.FALSE_CLOSURE_RISK
    assert finding.closure_confirmed is False
    assert any("drift" in b.lower() for b in finding.blockers)


def test_code_scanning_dismissals_are_never_gcs0():
    for reason in ("false positive", "won't fix", "used in tests", None):
        finding = score_code_scanning_alert(
            code_alert(state="dismissed", dismissed_reason=reason),
            Config(),
            now=NOW,
        )
        assert finding.gcs is GCS.FALSE_CLOSURE_RISK, reason
        assert finding.closure_confirmed is False
        assert finding.proof_grade == PROOF_ADMINISTRATIVE


def test_code_scanning_dismissal_without_comment_is_called_out():
    finding = score_code_scanning_alert(
        code_alert(state="dismissed", dismissed_reason="false positive"),
        Config(),
        now=NOW,
    )
    assert any("No dismissal comment" in e for e in finding.evidence_chain)


def test_code_scanning_open_severity_mapping():
    high = score_code_scanning_alert(
        code_alert(state="open", severity="high"), Config(), now=NOW
    )
    assert high.gcs is GCS.ACTIVE_RISK
    note = score_code_scanning_alert(
        code_alert(state="open", severity="medium"), Config(), now=NOW
    )
    assert note.gcs is GCS.PROVISIONAL


def test_no_family_reaches_gcs0_from_platform_state_alone():
    """Exhaustive: every state without independent evidence stays below GCS-0."""
    for state in ("open", "fixed", "dismissed", "auto_dismissed"):
        finding = score_dependabot_alert(
            dependabot_alert(state=state), Config(), now=NOW
        )
        assert finding.gcs is not GCS.VERIFIED_CLOSED, f"dependabot {state}"
    for state in ("open", "fixed", "dismissed"):
        finding = score_code_scanning_alert(
            code_alert(state=state), Config(), now=NOW
        )
        assert finding.gcs is not GCS.VERIFIED_CLOSED, f"code scanning {state}"
