"""Relocation / migration detection.

Answers the question the closure model implies but doesn't yet check:
when a risk is marked closed in one place, is the *same risk* still alive
somewhere else in scope?

This is deterministic and evidence-only. A relocation is asserted ONLY when
both ends are observed in the fetched alert set:

  - an ORIGIN alert that is closed (resolved / fixed / dismissed), AND
  - at least one DESTINATION alert in the same causal class that is still
    live (open, or an active credential), at a different location.

Causal classes (what makes two alerts "the same risk"):
  secret scanning  same secret SHA-256 hash
  dependabot       same package + advisory (GHSA/CVE)
  code scanning    same tool + rule id

A single observed alert can never produce a relocation finding. Nothing is
inferred from data that was not fetched. No synthetic input is accepted.
Where a destination alert was created *after* the origin was closed, the
time delta is a real observed relocation interval (from GitHub timestamps),
recorded as ``observed_relocation_seconds``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from .models import (
    FAMILY_CODE_SCANNING,
    FAMILY_DEPENDABOT,
    FAMILY_SECRET_SCANNING,
    VALIDITY_ACTIVE,
    Alert,
    RelocationFinding,
)
from .scoring import _parse_ts


def _is_closed(alert: Alert) -> bool:
    if alert.family == FAMILY_SECRET_SCANNING:
        return alert.state == "resolved"
    if alert.family == FAMILY_DEPENDABOT:
        return alert.state == "fixed"
    if alert.family == FAMILY_CODE_SCANNING:
        return alert.state in ("fixed", "dismissed")
    return False


def _is_live(alert: Alert) -> bool:
    if alert.family == FAMILY_SECRET_SCANNING:
        return alert.state == "open" or (alert.validity or "").lower() == VALIDITY_ACTIVE
    return alert.state == "open"


def _causal_class(alert: Alert) -> Optional[str]:
    """Stable, redaction-safe key, or None if the alert can't be classed."""
    if alert.family == FAMILY_SECRET_SCANNING:
        if not alert.secret_hash:
            return None
        return f"secret:{alert.secret_hash[:12]}"
    if alert.family == FAMILY_DEPENDABOT:
        if not alert.package_name or not alert.advisory_id:
            return None
        return f"dep:{alert.package_name}:{alert.advisory_id}"
    if alert.family == FAMILY_CODE_SCANNING:
        if not alert.rule_id:
            return None
        return f"code:{alert.tool_name or 'scanner'}:{alert.rule_id}"
    return None


def _location(alert: Alert) -> tuple:
    """What distinguishes two alerts as different locations."""
    return (alert.repo, alert.manifest_path, alert.number)


_CHANNELS = {
    FAMILY_SECRET_SCANNING: "same_secret_hash_live_elsewhere",
    FAMILY_DEPENDABOT: "same_advisory_open_in_other_manifest_or_repo",
    FAMILY_CODE_SCANNING: "same_rule_open_elsewhere",
}
_CONFIDENCE = {
    FAMILY_SECRET_SCANNING: "high",   # identical credential by hash
    FAMILY_DEPENDABOT: "high",        # identical advisory
    FAMILY_CODE_SCANNING: "moderate",  # same rule class, not necessarily same sink
}


def _closure_time(alert: Alert) -> Optional[str]:
    if alert.family == FAMILY_SECRET_SCANNING:
        return alert.resolved_at
    return alert.fixed_at or alert.resolved_at


def _action(family: str, alert: Alert) -> str:
    if family == FAMILY_SECRET_SCANNING:
        return (
            "Revoke/rotate the credential at the issuing provider; closing one "
            "alert did not kill it where it remains live."
        )
    if family == FAMILY_DEPENDABOT:
        return (
            "Upgrade every manifest/repo that still resolves the vulnerable "
            f"range (patched version: {alert.first_patched_version or 'see advisory'})."
        )
    return (
        "Fix the finding everywhere the rule still fires; suppressing one "
        "location does not remove the pattern elsewhere."
    )


def detect_relocations(alerts: list[Alert]) -> list[RelocationFinding]:
    """Find risks closed in one place but still live in another (observed)."""
    groups: dict[str, list[Alert]] = {}
    for alert in alerts:
        key = _causal_class(alert)
        if key is None:
            continue
        groups.setdefault(key, []).append(alert)

    findings: list[RelocationFinding] = []
    for key, members in groups.items():
        closed = [a for a in members if _is_closed(a)]
        live = [a for a in members if _is_live(a)]
        if not closed or not live:
            continue

        # Use the earliest-closed alert as origin for stable, real timing.
        def _ct(a: Alert):
            return _parse_ts(_closure_time(a)) or datetime.max.replace(tzinfo=None)

        origin = min(closed, key=lambda a: (_ct(a) if _ct(a).tzinfo is None else _ct(a).replace(tzinfo=None)))
        family = origin.family
        origin_closed = _parse_ts(_closure_time(origin))

        destinations = []
        best_delta: Optional[int] = None
        after_closure = False
        for d in live:
            if _location(d) == _location(origin):
                continue
            created = _parse_ts(d.created_at)
            delta = None
            if origin_closed and created and created >= origin_closed:
                delta = int((created - origin_closed).total_seconds())
                after_closure = True
                if best_delta is None or delta < best_delta:
                    best_delta = delta
            destinations.append(
                {
                    "repo": d.repo,
                    "number": d.number,
                    "state": d.state
                    + ("/active" if (d.validity or "").lower() == VALIDITY_ACTIVE else ""),
                    "created_at": d.created_at,
                    "manifest_path": d.manifest_path,
                }
            )

        if not destinations:
            continue

        multi_repo = bool(origin.multi_repo) and family == FAMILY_SECRET_SCANNING
        basis = (
            f"{family.replace('_', ' ').title()} risk closed at "
            f"{origin.repo}#{origin.number} ({origin.state}), but the same "
            f"causal class ({key}) is still live in "
            f"{len(destinations)} other location(s). Closing one channel did "
            "not close the risk."
        )
        if after_closure:
            basis += (
                " At least one live location was first detected AFTER the "
                "origin was closed — an observed post-closure relocation."
            )

        findings.append(
            RelocationFinding(
                family=family,
                causal_class=key,
                channel=_CHANNELS[family],
                origin_repo=origin.repo,
                origin_number=origin.number,
                origin_state=origin.state,
                origin_closed_at=_closure_time(origin),
                destinations=destinations,
                relocation_after_closure=after_closure,
                observed_relocation_seconds=best_delta,
                confidence=_CONFIDENCE[family],
                multi_repo_attested=multi_repo,
                basis=basis,
                recommended_action=_action(family, origin),
            )
        )

    findings.sort(key=lambda r: (not r.relocation_after_closure, r.family, r.causal_class))
    return findings
