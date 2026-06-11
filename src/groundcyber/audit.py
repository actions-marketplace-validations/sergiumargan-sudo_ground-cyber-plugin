"""Audit orchestration: resolve scope, fetch alerts read-only, enrich the
evidence chain (manifest verification, scan continuity), score, report."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from .config import Config
from .github_client import GitHubClient, GitHubError
from .models import (
    FAMILY_CODE_SCANNING,
    FAMILY_DEPENDABOT,
    FAMILY_SECRET_SCANNING,
    FAMILY_TITLES,
    Alert,
    AuditResult,
)
from .scoring import _parse_ts, score_alerts


def describe_scope(config: Config) -> str:
    parts = []
    if config.org:
        parts.append(f"organization '{config.org}'")
    if config.repos:
        parts.append("repositories: " + ", ".join(config.repos))
    if config.include_repos:
        parts.append("include filters: " + ", ".join(config.include_repos))
    if config.exclude_repos:
        parts.append("exclude filters: " + ", ".join(config.exclude_repos))
    if not parts:
        return "no scope configured"
    families = ", ".join(FAMILY_TITLES[f] for f in config.families)
    return f"GitHub alerts ({families}) — " + "; ".join(parts)


_FETCHERS = {
    FAMILY_SECRET_SCANNING: ("org_alerts", "repo_alerts"),
    FAMILY_DEPENDABOT: ("org_dependabot_alerts", "repo_dependabot_alerts"),
    FAMILY_CODE_SCANNING: ("org_code_scanning_alerts", "repo_code_scanning_alerts"),
}


def _collect_alerts(
    client: GitHubClient, config: Config, errors: list[str]
) -> list[Alert]:
    alerts: list[Alert] = []
    for family in config.families:
        org_method, repo_method = _FETCHERS[family]
        title = FAMILY_TITLES[family]
        if config.org:
            try:
                for alert in getattr(client, org_method)(config.org):
                    if config.repo_in_scope(alert.repo):
                        alerts.append(alert)
            except GitHubError as exc:
                errors.append(
                    f"Failed to fetch org-level {title} alerts for "
                    f"'{config.org}': {exc}. Results are incomplete; treat "
                    "missing repos as unverified."
                )
        for repo in config.repos:
            if not config.repo_in_scope(repo):
                continue
            try:
                alerts.extend(getattr(client, repo_method)(repo))
            except GitHubError as exc:
                errors.append(
                    f"Failed to fetch {title} alerts for '{repo}': {exc}. "
                    "This repository is unverified, not safe."
                )
    return alerts


def enrich_dependabot_evidence(client: GitHubClient, alert: Alert) -> None:
    """Independent read-only manifest verification for a fixed alert."""
    if alert.state != "fixed":
        return
    if not alert.manifest_path or not alert.package_name:
        alert.manifest_verification_note = (
            "alert does not record a manifest path/package to verify"
        )
        return
    from .verify import verify_manifest

    text = client.fetch_file_text(alert.repo, alert.manifest_path)
    if text is None:
        alert.manifest_verification_note = (
            f"manifest {alert.manifest_path} could not be read "
            "(missing, moved, too large, or insufficient permissions)"
        )
        return
    verdict, note = verify_manifest(
        text,
        alert.manifest_path,
        alert.package_name,
        alert.vulnerable_range or "",
    )
    alert.manifest_verified = verdict
    alert.manifest_verification_note = note


def enrich_code_scanning_evidence(client: GitHubClient, alert: Alert) -> None:
    """Scan-continuity check for a fixed alert: did the tool keep running?"""
    if alert.state != "fixed":
        return
    latest = client.latest_analysis_time(alert.repo, alert.tool_name)
    if latest is None:
        alert.scan_continuity = None
        alert.scan_continuity_note = (
            "code-scanning analyses are not readable for this repository"
        )
        return
    fixed_at = _parse_ts(alert.fixed_at)
    latest_at = _parse_ts(latest)
    if fixed_at is None or latest_at is None:
        alert.scan_continuity = None
        alert.scan_continuity_note = (
            f"latest {alert.tool_name or 'scanner'} analysis at {latest}, but "
            "timestamps could not be compared"
        )
        return
    if latest_at >= fixed_at:
        alert.scan_continuity = True
        alert.scan_continuity_note = (
            f"{alert.tool_name or 'scanner'} uploaded an analysis at {latest}, "
            "after the alert was fixed"
        )
    else:
        alert.scan_continuity = False
        alert.scan_continuity_note = (
            f"no {alert.tool_name or 'scanner'} analysis since {latest}, which "
            "predates the fix; the scanner may have stopped running"
        )


def run_audit(
    client: GitHubClient,
    config: Config,
    now: Optional[datetime] = None,
) -> AuditResult:
    errors: list[str] = []
    alerts = _collect_alerts(client, config, errors)

    deduped: list[Alert] = []
    seen: set[tuple[str, str, int]] = set()
    for alert in alerts:
        key = (alert.family, alert.repo, alert.number)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(alert)

    for alert in deduped:
        try:
            if alert.family == FAMILY_DEPENDABOT:
                enrich_dependabot_evidence(client, alert)
            elif alert.family == FAMILY_CODE_SCANNING:
                enrich_code_scanning_evidence(client, alert)
        except GitHubError as exc:
            # Enrichment failures fail closed: the evidence stays
            # unavailable, which can never produce GCS-0.
            note = f"evidence enrichment failed: {exc}"
            if alert.family == FAMILY_DEPENDABOT:
                alert.manifest_verification_note = note
            else:
                alert.scan_continuity_note = note

    findings = score_alerts(deduped, config, now=now)
    return AuditResult(
        findings=findings,
        scope_description=describe_scope(config),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        errors=errors,
    )
