"""Deterministic GCS scoring with per-family evidence chains.

No AI is involved in closure decisions. Every verdict is produced by the
rule tables below and is reproducible from the same inputs.

The closure rule (cannot be weakened by configuration): GCS-0 requires a
defensible evidence chain stronger than platform status alone.

  Secret scanning  provider-side validity == "inactive". Nothing else.
  Dependabot       "fixed" (dependency-graph evidence) AND independent
                   read-only manifest verification that the vulnerable
                   range is gone. "fixed" alone is moderate evidence and
                   caps at GCS-1.
  Code scanning    "fixed" (scanner re-scan evidence) AND scan continuity:
                   the same tool demonstrably kept analyzing the repo
                   afterwards. A finding that vanished because scanning
                   stopped is scanner drift, not closure.

Dismissals, resolution labels, and auto-dismissals are administrative
statements in every family: risk acceptance, never closure evidence.
Unknown or unavailable evidence is never safe; everything fails closed.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from .config import Config
from .models import (
    EVIDENCE_MODERATE,
    EVIDENCE_STRONG,
    EVIDENCE_UNAVAILABLE,
    FAMILY_CODE_SCANNING,
    FAMILY_DEPENDABOT,
    GCS,
    PROOF_ADMINISTRATIVE,
    PROOF_INDEPENDENT_VERIFICATION,
    PROOF_NONE,
    PROOF_PLATFORM_STATE,
    PROOF_PROVIDER_VALIDITY,
    PROOF_SCANNER_VERIFIED,
    VALIDITY_ACTIVE,
    VALIDITY_INACTIVE,
    Alert,
    Finding,
)

RECHECK_WINDOW_HOURS = 24
HIGH_SEVERITIES = ("critical", "high")


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _fail_closed_finding(alert: Alert) -> Finding:
    return Finding(
        alert=alert,
        gcs=GCS.PROVISIONAL,
        closure_confirmed=False,
        basis=(
            "Closure evidence could not be retrieved; the result is "
            "provisional, not safe (fail-closed)."
        ),
        blockers=[f"Evidence unavailable: {alert.fetch_error}"],
        recommended_action=(
            "Re-run the audit with working API access, then verify closure "
            "evidence for this alert."
        ),
        closure_claim=f"Platform state: {alert.state!r} (evidence fetch failed)",
        evidence_chain=[f"Evidence fetch failed: {alert.fetch_error}"],
        evidence_strength=EVIDENCE_UNAVAILABLE,
        evidence_source="none",
        proof_grade=PROOF_NONE,
        why_not_gcs0="Evidence could not be retrieved; absence of data is not proof.",
        recommended_next_evidence="Restore API access and re-run the audit.",
    )


# ── Secret scanning ─────────────────────────────────────────────────────────
def score_secret_alert(
    alert: Alert, config: Config, now: Optional[datetime] = None
) -> Finding:
    """Score a secret-scanning alert. Pure function of (alert, config, now)."""
    now = now or _now()
    validity = (alert.validity or "unknown").lower()
    resolved = alert.state == "resolved"
    resolution = alert.resolution or None
    claim = (
        f"Alert resolved as {resolution!r}" if resolved else "Alert open"
    ) + f"; provider validity: {validity!r}"

    if alert.fetch_error:
        return _fail_closed_finding(alert)

    # An active credential is active risk regardless of alert state.
    if validity == VALIDITY_ACTIVE:
        blockers = ["Provider-side validity check reports the credential is ACTIVE."]
        if resolved:
            blockers.append(
                f"Alert was resolved as {resolution!r} while the credential "
                "is still active: the resolution is contradicted by evidence."
            )
        return Finding(
            alert=alert,
            gcs=GCS.ACTIVE_RISK,
            closure_confirmed=False,
            basis=(
                "Provider validity is 'active': the credential is usable right "
                "now"
                + (
                    " even though the alert is marked resolved."
                    if resolved
                    else " and the alert is open."
                )
            ),
            blockers=blockers,
            recommended_action=(
                "Revoke or rotate the credential at the issuing provider "
                "immediately, then confirm validity flips to 'inactive'."
            ),
            closure_claim=claim,
            evidence_chain=["Provider validity check: credential ACTIVE."],
            evidence_strength=EVIDENCE_STRONG,
            evidence_source="GitHub provider validity check",
            proof_grade=PROOF_PROVIDER_VALIDITY,
            why_not_gcs0="The credential is active; closure is contradicted.",
            recommended_next_evidence=(
                "Provider validity flipping to 'inactive' after revocation."
            ),
        )

    if resolved:
        if validity == VALIDITY_INACTIVE:
            chain = [
                f"Alert resolved as {resolution!r} (administrative statement).",
                "Provider validity check: credential INACTIVE (closure evidence).",
            ]
            if config.require_delayed_recheck:
                resolved_at = _parse_ts(alert.resolved_at)
                if resolved_at and now - resolved_at < timedelta(
                    hours=RECHECK_WINDOW_HOURS
                ):
                    return Finding(
                        alert=alert,
                        gcs=GCS.LOW_RESIDUAL_RISK,
                        closure_confirmed=False,
                        basis=(
                            "Provider validity is 'inactive', but the alert was "
                            f"resolved less than {RECHECK_WINDOW_HOURS}h ago and "
                            "the configuration requires a delayed re-check before "
                            "verified closure."
                        ),
                        blockers=[
                            "Delayed re-check pending: re-run the audit after "
                            f"{RECHECK_WINDOW_HOURS}h to confirm the credential "
                            "stayed inactive."
                        ],
                        recommended_action=(
                            "Re-run the audit after the re-check window to "
                            "confirm GCS-0."
                        ),
                        closure_claim=claim,
                        evidence_chain=chain
                        + ["Delayed re-check window has not elapsed."],
                        evidence_strength=EVIDENCE_MODERATE,
                        evidence_source="GitHub provider validity check",
                        proof_grade=PROOF_PROVIDER_VALIDITY,
                        why_not_gcs0="Configured delayed re-check has not elapsed.",
                        recommended_next_evidence=(
                            "A second inactive validity reading after the "
                            "re-check window."
                        ),
                    )
            return Finding(
                alert=alert,
                gcs=GCS.VERIFIED_CLOSED,
                closure_confirmed=True,
                basis=(
                    "Provider-side validity check confirms the credential is "
                    "inactive. This is closure evidence, independent of the "
                    f"resolution label ({resolution!r})."
                ),
                blockers=[],
                recommended_action="None. Closure is verified by provider evidence.",
                closure_claim=claim,
                evidence_chain=chain,
                evidence_strength=EVIDENCE_STRONG,
                evidence_source="GitHub provider validity check",
                proof_grade=PROOF_PROVIDER_VALIDITY,
                why_not_gcs0="",
                recommended_next_evidence="None required.",
            )

        # Resolved without inactive evidence: the false-closure case.
        label_note = (
            f"Resolution label {resolution!r} is an administrative statement, "
            "not closure evidence."
            if resolution
            else "Alert is resolved with no resolution label and no closure evidence."
        )
        blockers = [
            label_note,
            "No provider-side inactive-validity evidence was found "
            f"(validity: {validity!r}).",
        ]
        resolved_at = _parse_ts(alert.resolved_at)
        if (
            resolved_at
            and config.stale_resolved_days
            and now - resolved_at > timedelta(days=config.stale_resolved_days)
        ):
            blockers.append(
                f"Resolution is older than {config.stale_resolved_days} days "
                "and the evidence gap was never closed."
            )
        return Finding(
            alert=alert,
            gcs=GCS.FALSE_CLOSURE_RISK,
            closure_confirmed=False,
            basis=(
                f"Alert was closed as {resolution!r}, but no provider-side "
                "inactive-validity evidence exists. A label is a status, not "
                "proof the credential is dead."
            ),
            blockers=blockers,
            recommended_action=(
                "Verify at the issuing provider that the credential is revoked; "
                "if it cannot be proven dead, rotate it and re-check validity."
            ),
            closure_claim=claim,
            evidence_chain=[
                f"Resolution label {resolution!r}: administrative statement only.",
                f"Provider validity: {validity!r} — no closure evidence.",
            ],
            evidence_strength=EVIDENCE_UNAVAILABLE,
            evidence_source="resolution label only",
            proof_grade=PROOF_ADMINISTRATIVE,
            why_not_gcs0=(
                "No provider-side inactive-validity evidence; a resolution "
                "label is not proof."
            ),
            recommended_next_evidence=(
                "Provider validity reading of 'inactive', or provider-side "
                "revocation confirmation after rotation."
            ),
        )

    # Open alerts.
    if validity == VALIDITY_INACTIVE:
        return Finding(
            alert=alert,
            gcs=GCS.LOW_RESIDUAL_RISK,
            closure_confirmed=False,
            basis=(
                "Provider validity is 'inactive' but the alert is still open. "
                "The credential appears dead; the alert workflow is unfinished."
            ),
            blockers=["Alert remains open despite inactive validity."],
            recommended_action=(
                "Confirm the credential was rotated/revoked intentionally, "
                "then resolve the alert with that evidence on record."
            ),
            closure_claim=claim,
            evidence_chain=[
                "Provider validity check: credential INACTIVE.",
                "Alert workflow not completed (still open).",
            ],
            evidence_strength=EVIDENCE_STRONG,
            evidence_source="GitHub provider validity check",
            proof_grade=PROOF_PROVIDER_VALIDITY,
            why_not_gcs0="Alert is still open; the closure workflow is unfinished.",
            recommended_next_evidence="Resolve the alert; re-audit confirms GCS-0.",
        )

    # Open with unknown/absent validity.
    if alert.publicly_leaked:
        return Finding(
            alert=alert,
            gcs=GCS.ACTIVE_RISK,
            closure_confirmed=False,
            basis=(
                "Open alert with unknown validity for a credential GitHub "
                "reports as publicly leaked. Exposure must be treated as "
                "exploitable until proven inactive."
            ),
            blockers=[
                "Credential is publicly leaked.",
                "No provider-side validity evidence (validity: "
                f"{validity!r}).",
            ],
            recommended_action=(
                "Rotate or revoke the credential immediately and confirm "
                "validity flips to 'inactive'."
            ),
            closure_claim=claim,
            evidence_chain=[
                "GitHub reports the credential as publicly leaked.",
                f"Provider validity: {validity!r} — no inactive evidence.",
            ],
            evidence_strength=EVIDENCE_STRONG,
            evidence_source="GitHub public-leak detection",
            proof_grade=PROOF_PLATFORM_STATE,
            why_not_gcs0="Publicly leaked credential with no inactive evidence.",
            recommended_next_evidence=(
                "Provider validity 'inactive' after revocation/rotation."
            ),
        )

    if config.treat_unknown_validity_as == "active_risk":
        gcs = GCS.ACTIVE_RISK
        basis = (
            "Open alert with unknown validity; configuration treats unknown "
            "validity as active risk."
        )
    else:
        gcs = GCS.PROVISIONAL
        basis = (
            "Open alert with no provider-side validity evidence. Unknown "
            "validity is not safe; the alert is provisional until proven "
            "inactive."
        )
    return Finding(
        alert=alert,
        gcs=gcs,
        closure_confirmed=False,
        basis=basis,
        blockers=[
            f"No provider-side validity evidence (validity: {validity!r})."
        ],
        recommended_action=(
            "Determine whether the credential is live (provider validity check "
            "or manual verification); revoke/rotate if it is, then resolve "
            "with evidence."
        ),
        closure_claim=claim,
        evidence_chain=[f"Provider validity: {validity!r} — no evidence either way."],
        evidence_strength=EVIDENCE_UNAVAILABLE,
        evidence_source="none",
        proof_grade=PROOF_NONE,
        why_not_gcs0="Unknown validity is not safe.",
        recommended_next_evidence=(
            "Provider validity reading, or manual verification at the issuer."
        ),
    )


# ── Dependabot ──────────────────────────────────────────────────────────────
def score_dependabot_alert(
    alert: Alert, config: Config, now: Optional[datetime] = None
) -> Finding:
    if alert.fetch_error:
        return _fail_closed_finding(alert)

    package = alert.package_name or "dependency"
    rng = alert.vulnerable_range or "unknown range"
    claim = f"Dependabot state: {alert.state!r} for {package} ({rng})"

    if alert.state == "fixed":
        platform_evidence = (
            "GitHub dependency graph no longer resolves the vulnerable "
            f"version (state 'fixed' at {alert.fixed_at or 'unknown time'})."
        )
        if alert.manifest_verified is True:
            return Finding(
                alert=alert,
                gcs=GCS.VERIFIED_CLOSED,
                closure_confirmed=True,
                basis=(
                    "Platform reports the alert fixed AND independent "
                    "read-only inspection of the manifest confirms the "
                    "vulnerable range is gone."
                ),
                blockers=[],
                recommended_action="None. Closure evidence is strong.",
                closure_claim=claim,
                evidence_chain=[
                    platform_evidence,
                    f"Independent verification: {alert.manifest_verification_note}",
                ],
                evidence_strength=EVIDENCE_STRONG,
                evidence_source="dependency graph + independent manifest inspection",
                proof_grade=PROOF_INDEPENDENT_VERIFICATION,
                why_not_gcs0="",
                recommended_next_evidence="None required.",
            )
        if alert.manifest_verified is False:
            return Finding(
                alert=alert,
                gcs=GCS.ACTIVE_RISK,
                closure_confirmed=False,
                basis=(
                    "Platform reports the alert fixed, but independent "
                    "inspection still finds a version inside the vulnerable "
                    "range. The fix claim is contradicted by evidence."
                ),
                blockers=[
                    f"Contradiction: {alert.manifest_verification_note}",
                ],
                recommended_action=(
                    "Update the dependency to a patched version "
                    f"({alert.first_patched_version or 'see advisory'}) and "
                    "re-run the audit."
                ),
                closure_claim=claim,
                evidence_chain=[
                    platform_evidence,
                    f"Independent verification FAILED: {alert.manifest_verification_note}",
                ],
                evidence_strength=EVIDENCE_STRONG,
                evidence_source="independent manifest inspection",
                proof_grade=PROOF_INDEPENDENT_VERIFICATION,
                why_not_gcs0="Vulnerable range still present in the manifest.",
                recommended_next_evidence=(
                    "Manifest showing only versions outside the vulnerable range."
                ),
            )
        note = (
            alert.manifest_verification_note
            or "independent manifest verification was not available"
        )
        return Finding(
            alert=alert,
            gcs=GCS.LOW_RESIDUAL_RISK,
            closure_confirmed=False,
            basis=(
                "GitHub reports this alert as fixed (dependency-graph "
                "evidence), but Ground Cyber could not independently verify "
                f"the manifest: {note}."
            ),
            blockers=[f"Independent verification unavailable: {note}."],
            recommended_action=(
                "Confirm the lockfile/manifest no longer resolves the "
                f"vulnerable range '{rng}', or re-run where the manifest is "
                "readable."
            ),
            closure_claim=claim,
            evidence_chain=[
                platform_evidence,
                f"Independent verification: unavailable — {note}.",
            ],
            evidence_strength=EVIDENCE_MODERATE,
            evidence_source="GitHub dependency graph (platform state)",
            proof_grade=PROOF_PLATFORM_STATE,
            why_not_gcs0=(
                "Platform-reported fixed; independent manifest verification "
                "unavailable. Platform status alone is not verified closure."
            ),
            recommended_next_evidence=(
                "Read-only manifest inspection confirming the vulnerable "
                "range is absent."
            ),
        )

    if alert.state in ("dismissed", "auto_dismissed"):
        auto = alert.state == "auto_dismissed"
        reason = alert.dismissed_reason or ("auto-dismiss rule" if auto else "none given")
        chain = [
            f"{'Auto-dismissed' if auto else 'Dismissed'} with reason "
            f"{reason!r}: an administrative statement, not remediation evidence.",
            f"Vulnerable range '{rng}' for {package} was never shown to be removed.",
        ]
        if alert.dismissed_comment:
            chain.append(
                "A dismissal comment exists: documented risk acceptance, "
                "still not closure evidence."
            )
        return Finding(
            alert=alert,
            gcs=GCS.FALSE_CLOSURE_RISK,
            closure_confirmed=False,
            basis=(
                f"Alert was {'auto-' if auto else ''}dismissed "
                f"({reason!r}) without fix evidence. Dismissal is risk "
                "acceptance, not verified closure."
            ),
            blockers=[
                f"Dismissal reason {reason!r} is an assertion, not evidence.",
                "No dependency-graph or manifest evidence that the "
                "vulnerable range was removed.",
            ],
            recommended_action=(
                "Either fix the dependency (upgrade to "
                f"{alert.first_patched_version or 'a patched version'}) or "
                "record the dismissal explicitly as accepted risk with an "
                "owner and review date."
            ),
            closure_claim=claim,
            evidence_chain=chain,
            evidence_strength=EVIDENCE_UNAVAILABLE,
            evidence_source="dismissal metadata only",
            proof_grade=PROOF_ADMINISTRATIVE,
            why_not_gcs0="Dismissal is risk acceptance, not closure evidence.",
            recommended_next_evidence=(
                "State 'fixed' plus manifest confirmation that the "
                "vulnerable range is gone."
            ),
        )

    # Open.
    severe = (alert.severity or "") in HIGH_SEVERITIES
    return Finding(
        alert=alert,
        gcs=GCS.ACTIVE_RISK if severe else GCS.PROVISIONAL,
        closure_confirmed=False,
        basis=(
            f"Open Dependabot alert: the dependency graph currently resolves "
            f"a version of {package} inside the vulnerable range"
            + (
                f". Severity is {alert.severity}: treat as exploitable."
                if severe
                else f" (severity: {alert.severity or 'unknown'})."
            )
        ),
        blockers=[
            f"Vulnerable range '{rng}' is present per the dependency graph."
        ],
        recommended_action=(
            "Upgrade to "
            f"{alert.first_patched_version or 'a patched version'} and "
            "confirm the alert transitions to 'fixed'."
        ),
        closure_claim=claim,
        evidence_chain=[
            "Dependency graph: vulnerable version currently present.",
        ],
        evidence_strength=EVIDENCE_STRONG,
        evidence_source="GitHub dependency graph",
        proof_grade=PROOF_PLATFORM_STATE,
        why_not_gcs0="The vulnerability is unremediated.",
        recommended_next_evidence=(
            "State 'fixed' plus manifest confirmation after upgrading."
        ),
    )


# ── Code scanning ───────────────────────────────────────────────────────────
def score_code_scanning_alert(
    alert: Alert, config: Config, now: Optional[datetime] = None
) -> Finding:
    if alert.fetch_error:
        return _fail_closed_finding(alert)

    rule = alert.rule_id or "rule"
    tool = alert.tool_name or "scanner"
    claim = f"Code scanning state: {alert.state!r} for {rule} ({tool})"

    if alert.state == "fixed":
        scan_evidence = (
            f"{tool} re-scanned and no longer reports {rule} at this location "
            f"(state 'fixed' at {alert.fixed_at or 'unknown time'})."
        )
        if alert.scan_continuity is True:
            return Finding(
                alert=alert,
                gcs=GCS.VERIFIED_CLOSED,
                closure_confirmed=True,
                basis=(
                    "The finding was fixed according to a subsequent scan by "
                    "the same tool, and scan continuity is confirmed: the "
                    "tool kept analyzing the repository after the fix."
                ),
                blockers=[],
                recommended_action="None. Closure is scanner-verified.",
                closure_claim=claim,
                evidence_chain=[
                    scan_evidence,
                    f"Scan continuity: {alert.scan_continuity_note}",
                ],
                evidence_strength=EVIDENCE_STRONG,
                evidence_source=f"{tool} analyses (scan continuity confirmed)",
                proof_grade=PROOF_SCANNER_VERIFIED,
                why_not_gcs0="",
                recommended_next_evidence="None required.",
            )
        if alert.scan_continuity is False:
            return Finding(
                alert=alert,
                gcs=GCS.FALSE_CLOSURE_RISK,
                closure_confirmed=False,
                basis=(
                    "The alert is marked fixed, but the scanner demonstrably "
                    "stopped analyzing the repository afterwards. A finding "
                    "that vanished because scanning stopped is scanner "
                    "drift, not closure."
                ),
                blockers=[
                    f"Scanner drift: {alert.scan_continuity_note}",
                ],
                recommended_action=(
                    f"Restore {tool} analysis uploads for this repository, "
                    "then re-run the audit to confirm the finding stays gone."
                ),
                closure_claim=claim,
                evidence_chain=[
                    scan_evidence,
                    f"Scan continuity FAILED: {alert.scan_continuity_note}",
                ],
                evidence_strength=EVIDENCE_UNAVAILABLE,
                evidence_source="code-scanning analyses timeline",
                proof_grade=PROOF_PLATFORM_STATE,
                why_not_gcs0=(
                    "The disappearance coincides with scanning stopping; "
                    "closure cannot be distinguished from drift."
                ),
                recommended_next_evidence=(
                    "A fresh analysis by the same tool showing the finding "
                    "absent."
                ),
            )
        return Finding(
            alert=alert,
            gcs=GCS.PROVISIONAL,
            closure_confirmed=False,
            basis=(
                "GitHub reports this alert as fixed, but Ground Cyber could "
                "not establish scan continuity"
                + (
                    f": {alert.scan_continuity_note}."
                    if alert.scan_continuity_note
                    else " (analyses API unavailable)."
                )
            ),
            blockers=[
                "Scan continuity could not be established; a disabled "
                "scanner, excluded path, or stopped SARIF upload would look "
                "identical to a fix."
            ],
            recommended_action=(
                f"Confirm {tool} is still analyzing this repository, then "
                "re-run the audit."
            ),
            closure_claim=claim,
            evidence_chain=[
                scan_evidence,
                "Scan continuity: could not be established.",
            ],
            evidence_strength=EVIDENCE_MODERATE,
            evidence_source="GitHub code-scanning state (platform state)",
            proof_grade=PROOF_PLATFORM_STATE,
            why_not_gcs0=(
                "Fixed state without scan-continuity evidence is not "
                "verified closure."
            ),
            recommended_next_evidence=(
                "Recent analyses by the same tool after the fix timestamp."
            ),
        )

    if alert.state == "dismissed":
        reason = alert.dismissed_reason or "none given"
        chain = [
            f"Dismissed with reason {reason!r}: an administrative statement.",
            "No subsequent scan evidence shows the finding absent.",
        ]
        if alert.dismissed_comment:
            chain.append(
                "A dismissal comment exists: documented risk acceptance, "
                "still not closure evidence."
            )
        else:
            chain.append("No dismissal comment was recorded.")
        return Finding(
            alert=alert,
            gcs=GCS.FALSE_CLOSURE_RISK,
            closure_confirmed=False,
            basis=(
                f"Alert was dismissed as {reason!r}"
                + (
                    " with no dismissal comment"
                    if not alert.dismissed_comment
                    else ""
                )
                + ". Treat as risk acceptance, not verified closure."
            ),
            blockers=[
                f"Dismissal reason {reason!r} is an assertion, not scan evidence.",
            ],
            recommended_action=(
                "Either fix the finding so a subsequent scan closes it, or "
                "record the dismissal as accepted risk with justification, "
                "owner, and review date."
            ),
            closure_claim=claim,
            evidence_chain=chain,
            evidence_strength=EVIDENCE_UNAVAILABLE,
            evidence_source="dismissal metadata only",
            proof_grade=PROOF_ADMINISTRATIVE,
            why_not_gcs0="Dismissal is risk acceptance, not closure evidence.",
            recommended_next_evidence=(
                "A subsequent scan by the same tool showing the finding "
                "fixed, with scan continuity."
            ),
        )

    # Open.
    severe = (alert.severity or "") in HIGH_SEVERITIES
    return Finding(
        alert=alert,
        gcs=GCS.ACTIVE_RISK if severe else GCS.PROVISIONAL,
        closure_confirmed=False,
        basis=(
            f"Open code-scanning finding {rule} reported by {tool}"
            + (
                f". Security severity is {alert.severity}: treat as "
                "exploitable until fixed."
                if severe
                else f" (severity: {alert.severity or 'unknown'})."
            )
        ),
        blockers=[f"The finding is unremediated per the latest {tool} scan."],
        recommended_action=(
            "Fix the finding so a subsequent scan closes the alert."
        ),
        closure_claim=claim,
        evidence_chain=[f"Latest {tool} scan reports the finding present."],
        evidence_strength=EVIDENCE_STRONG,
        evidence_source=f"{tool} scan results",
        proof_grade=PROOF_PLATFORM_STATE,
        why_not_gcs0="The finding is unremediated.",
        recommended_next_evidence=(
            "A subsequent scan showing the finding fixed, with continuity."
        ),
    )


# ── Dispatcher and cross-alert passes ───────────────────────────────────────
_SCORERS = {
    FAMILY_DEPENDABOT: score_dependabot_alert,
    FAMILY_CODE_SCANNING: score_code_scanning_alert,
}


def score_alert(alert: Alert, config: Config, now: Optional[datetime] = None) -> Finding:
    scorer = _SCORERS.get(alert.family, score_secret_alert)
    return scorer(alert, config, now=now)


def apply_duplicate_exposure(findings: list[Finding]) -> list[Finding]:
    """Escalate secret alerts whose secret (by hash) is active elsewhere.

    If the same credential appears in another alert scored GCS-4, a calmer
    verdict on this alert is an illusion: the credential is exploitable.
    """
    active_hashes = {
        f.alert.secret_hash
        for f in findings
        if f.gcs is GCS.ACTIVE_RISK and f.alert.secret_hash
    }
    for f in findings:
        h = f.alert.secret_hash
        if h and h in active_hashes and f.gcs is not GCS.ACTIVE_RISK:
            f.gcs = GCS.ACTIVE_RISK
            f.closure_confirmed = False
            f.blockers.append(
                "Duplicate active exposure: the same credential (matched by "
                "hash) is active in another alert in scope."
            )
            f.basis += (
                " Escalated to active risk: the same credential is active in "
                "another alert."
            )
            f.recommended_action = (
                "Revoke or rotate the credential at the issuing provider; it "
                "is active in at least one other location."
            )
            f.evidence_chain.append(
                "Cross-alert evidence: same credential hash is active elsewhere."
            )
            f.why_not_gcs0 = (
                "The same credential is active in another alert in scope."
            )
            f.proof_grade = PROOF_PROVIDER_VALIDITY
    return findings


def score_alerts(
    alerts: list[Alert], config: Config, now: Optional[datetime] = None
) -> list[Finding]:
    findings = [score_alert(a, config, now=now) for a in alerts]
    return apply_duplicate_exposure(findings)
