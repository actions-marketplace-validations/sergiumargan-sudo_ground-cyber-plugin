"""Report generation: markdown, JSON, and simple HTML.

Every free-text field passes through ``redact_text`` before it is written.
The JSON report is built from an explicit whitelist of fields; raw alert
payloads are never serialized, so a raw secret value cannot appear even if
one slipped past sanitization upstream.
"""

from __future__ import annotations

import html as html_module
import json
from pathlib import Path
from typing import Any

from . import __version__
from .config import Config
from .models import ALL_FAMILIES, FAMILY_TITLES, GCS, AuditResult, Finding
from .redact import pseudonymize_repo, redact_text

GCS_ORDER = [
    GCS.ACTIVE_RISK,
    GCS.FALSE_CLOSURE_RISK,
    GCS.PROVISIONAL,
    GCS.LOW_RESIDUAL_RISK,
    GCS.VERIFIED_CLOSED,
]

METHODOLOGY = """\
Ground Cyber asks one question per alert: is the underlying risk proven
closed, or merely marked resolved? Every verdict is produced by a
deterministic rule table (no AI) over an explicit evidence chain.

GCS-0 (verified closed) requires a defensible evidence chain per family:

- Secret scanning: provider-side validity == "inactive". Resolution
  labels (revoked, used_in_tests, false_positive, wont_fix,
  pattern_deleted, pattern_edited, ...) are administrative statements
  and never count as closure evidence by themselves.
- Dependabot: state "fixed" (dependency-graph evidence) AND independent
  read-only inspection of the named manifest/lockfile confirming the
  vulnerable range is gone. Platform "fixed" alone is moderate evidence
  and caps at GCS-1. Dismissals and auto-dismissals are risk acceptance
  (GCS-3).
- Code scanning: state "fixed" (scanner re-scan evidence) AND scan
  continuity — the same tool demonstrably kept analyzing the repository
  after the fix. A finding that vanished while scanning stopped is
  scanner drift (GCS-3), not closure. Dismissals are risk acceptance.

Shared rules:
- All data is fetched with read-only GET requests.
- Any raw secret value in an API response is hashed (SHA-256) immediately
  and the raw value is discarded. Hashes are used only to detect the same
  credential appearing in multiple alerts.
- Unknown, ambiguous, or unavailable evidence is never safe: such alerts
  fail closed to a provisional or risk state.
- A credential active in any alert escalates every other alert that
  shares the same secret hash (duplicate active exposure).
"""

SECURITY_MODEL = """\
- Local-first: the audit runs where you invoke it; nothing is uploaded.
- Read-only: only GitHub GET requests are issued. Alerts, repositories,
  issues, and settings are never modified.
- No raw secret storage: secret values are hashed with SHA-256 on receipt
  and discarded.
- No raw secret printing: all report text passes through a redaction
  filter that replaces secret-shaped strings with hashed markers.
- Human overrides and dismissals are treated as risk acceptance, not as
  verified closure.
"""

LIMITATIONS = """\
- Provider validity checks exist only for secret types GitHub actively
  verifies; other types can never reach GCS-0 through this tool and will
  surface as provisional or false-closure risk. That is by design:
  unknown validity is not safe.
- Validity reflects GitHub's most recent check, which may lag a recent
  revocation or reactivation.
- A credential proven inactive may still have been used during its
  exposure window; this tool verifies closure, not absence of past abuse.
- Git history is not rewritten by resolving an alert: an exposed secret
  remains in history until rotated and scrubbed.
- Dependabot manifest verification supports common lockfile formats with
  exact pinned versions; anything it cannot parse with certainty is
  reported as unverifiable (GCS-1 at best), never as verified.
- Code-scanning continuity is checked at tool level (did the tool keep
  uploading analyses). Rule-level drift — a disabled rule or an excluded
  path inside a still-running scanner — cannot be detected through the
  API and remains a residual risk on GCS-0 code-scanning verdicts.
- Organization-level scans require a token with organization-wide alert
  read access; the default Actions GITHUB_TOKEN is repo-scoped.
- Alerts GitHub never raised (undetected secret types, disabled scanners,
  missing custom patterns) are invisible to this audit.
"""


def _display_repo(finding: Finding, config: Config) -> str:
    if config.redact_repo_names:
        return pseudonymize_repo(finding.alert.repo)
    return finding.alert.repo


def _scope_text(result: AuditResult, config: Config) -> str:
    if config.redact_repo_names:
        return (
            "GitHub security alerts — scope identifiers redacted "
            "(redact_repo_names enabled)"
        )
    return _clean(result.scope_description)


def _clean(text: Any) -> str:
    return redact_text(str(text)) if text is not None else ""


def summary_block(result: AuditResult) -> str:
    family_counts = ", ".join(
        f"{FAMILY_TITLES[fam].lower()}: {result.count_family(fam)}"
        for fam in ALL_FAMILIES
        if result.count_family(fam)
    )
    lines = [
        "Ground Cyber Closure Report",
        "",
        f"Total alerts scanned: {result.total}"
        + (f" ({family_counts})" if family_counts else ""),
        f"Verified closed: {result.count(GCS.VERIFIED_CLOSED)}",
        f"Low residual risk: {result.count(GCS.LOW_RESIDUAL_RISK)}",
        f"Provisional / unknown: {result.count(GCS.PROVISIONAL)}",
        f"False-closure risk: {result.count(GCS.FALSE_CLOSURE_RISK)}",
        f"Active risk: {result.count(GCS.ACTIVE_RISK)}",
    ]
    top = result.highest_risk
    if top:
        lines += [
            "",
            "Highest-risk finding:",
            _clean(
                f"Alert #{top.alert.number} ({top.gcs.label} {top.gcs.title}): "
                f"{top.basis}"
            ),
        ]
    return "\n".join(lines)


def _sorted_findings(result: AuditResult) -> list[Finding]:
    rank = {g: i for i, g in enumerate(GCS_ORDER)}
    return sorted(
        result.findings,
        key=lambda f: (rank[f.gcs], f.alert.repo, f.alert.number),
    )


# ── JSON ────────────────────────────────────────────────────────────────────
def build_json(result: AuditResult, config: Config) -> dict[str, Any]:
    findings = []
    for f in _sorted_findings(result):
        a = f.alert
        findings.append(
            {
                "alert_number": a.number,
                "family": a.family,
                "repo": _clean(_display_repo(f, config)),
                "finding_type": _clean(a.display_type),
                "secret_type": _clean(a.secret_type) or None,
                "secret_type_display": _clean(a.secret_type_display) or None,
                "secret_hash": a.secret_hash,
                "alert_state": _clean(a.state),
                "resolution": _clean(a.resolution) or None,
                "validity": _clean(a.validity) or ("unknown" if a.family == "secret_scanning" else None),
                "severity": a.severity,
                "dismissed_reason": _clean(a.dismissed_reason) or None,
                "closure_claim": _clean(f.closure_claim),
                "evidence_chain": [_clean(e) for e in f.evidence_chain],
                "evidence_strength": f.evidence_strength,
                "evidence_source": _clean(f.evidence_source),
                "proof_grade": f.proof_grade,
                "why_not_gcs0": _clean(f.why_not_gcs0) or None,
                "recommended_next_evidence": _clean(f.recommended_next_evidence),
                "gcs": f.gcs.label,
                "gcs_title": f.gcs.title,
                "closure_confirmed": f.closure_confirmed,
                "basis": _clean(f.basis),
                "closure_blockers": [_clean(b) for b in f.blockers],
                "recommended_action": _clean(f.recommended_action),
                "publicly_leaked": a.publicly_leaked,
                "push_protection_bypassed": a.push_protection_bypassed,
                "created_at": a.created_at,
                "resolved_at": a.resolved_at,
                "updated_at": a.updated_at,
                "url": None if config.redact_repo_names else a.html_url,
                "evidence_error": _clean(a.fetch_error) or None,
            }
        )
    return {
        "tool": "groundcyber",
        "version": __version__,
        "generated_at": result.generated_at,
        "scope": _scope_text(result, config),
        "summary": {
            "total": result.total,
            "verified_closed": result.count(GCS.VERIFIED_CLOSED),
            "low_residual_risk": result.count(GCS.LOW_RESIDUAL_RISK),
            "provisional_unknown": result.count(GCS.PROVISIONAL),
            "false_closure_risk": result.count(GCS.FALSE_CLOSURE_RISK),
            "active_risk": result.count(GCS.ACTIVE_RISK),
        },
        "closure_rule": (
            "GCS-0 requires a defensible evidence chain per family: provider "
            "validity 'inactive' (secrets); 'fixed' plus independent manifest "
            "verification (dependabot); 'fixed' plus scan continuity (code "
            "scanning). Labels and dismissals are never closure evidence. "
            "Unknown evidence is not safe."
        ),
        "errors": [_clean(e) for e in result.errors],
        "findings": findings,
        "relocations": [
            {
                "family": r.family,
                "causal_class": _clean(r.causal_class),
                "channel": r.channel,
                "confidence": r.confidence,
                "origin": {
                    "repo": _clean(
                        pseudonymize_repo(r.origin_repo)
                        if config.redact_repo_names
                        else r.origin_repo
                    ),
                    "number": r.origin_number,
                    "state": _clean(r.origin_state),
                    "closed_at": r.origin_closed_at,
                },
                "destinations": [
                    {
                        "repo": _clean(
                            pseudonymize_repo(d["repo"])
                            if config.redact_repo_names
                            else d["repo"]
                        ),
                        "number": d["number"],
                        "state": _clean(d["state"]),
                        "created_at": d.get("created_at"),
                        "manifest_path": _clean(d.get("manifest_path")) or None,
                    }
                    for d in r.destinations
                ],
                "relocation_after_closure": r.relocation_after_closure,
                "observed_relocation_seconds": r.observed_relocation_seconds,
                "multi_repo_attested": r.multi_repo_attested,
                "basis": _clean(r.basis),
                "recommended_action": _clean(r.recommended_action),
            }
            for r in result.relocations
        ],
    }


def render_json(result: AuditResult, config: Config) -> str:
    return json.dumps(build_json(result, config), indent=2) + "\n"


# ── Markdown ────────────────────────────────────────────────────────────────
def render_markdown(result: AuditResult, config: Config) -> str:
    parts: list[str] = []
    parts.append("# Ground Cyber Closure Report\n")
    parts.append("> Closed is a status. Revoked is evidence. "
                 "Unknown validity is not safe.\n")

    parts.append("## Executive summary\n")
    parts.append("```text\n" + summary_block(result) + "\n```\n")

    parts.append("## Scope\n")
    parts.append(_scope_text(result, config) + "\n")
    parts.append(f"Generated at: {result.generated_at} · groundcyber v{__version__}\n")

    if config.include_methodology:
        parts.append("## Methodology\n")
        parts.append(METHODOLOGY + "\n")

    parts.append("## Security and privacy model\n")
    parts.append(SECURITY_MODEL + "\n")

    parts.append("## Closure summary\n")
    parts.append("| State | Meaning | Count |\n|---|---|---|\n")
    for gcs in GCS_ORDER:
        parts.append(f"| {gcs.label} | {gcs.title} | {result.count(gcs)} |\n")
    parts.append("\n")

    parts.append("## Findings\n")
    if not result.findings:
        parts.append("No alerts were found in scope.\n")
    else:
        parts.append(
            "| Alert | Family | Repo | Finding | State | Resolution/Reason "
            "| Evidence | GCS | Closure confirmed |\n"
            "|---|---|---|---|---|---|---|---|---|\n"
        )
        for f in _sorted_findings(result):
            a = f.alert
            resolution = a.resolution or a.dismissed_reason
            parts.append(
                f"| #{a.number} | {FAMILY_TITLES[a.family]} "
                f"| {_clean(_display_repo(f, config))} "
                f"| {_clean(a.display_type)} | {_clean(a.state)} "
                f"| {_clean(resolution) or '—'} | {f.evidence_strength} "
                f"| {f.gcs.label} | {'yes' if f.closure_confirmed else 'no'} |\n"
            )
        parts.append("\n## Per-alert reasoning\n")
        for f in _sorted_findings(result):
            a = f.alert
            parts.append(
                f"### Alert #{a.number} — {_clean(_display_repo(f, config))} "
                f"({f.gcs.label}: {f.gcs.title})\n"
            )
            parts.append(
                f"- **Family / finding:** {FAMILY_TITLES[a.family]} / "
                f"{_clean(a.display_type)}\n"
            )
            resolution = a.resolution or a.dismissed_reason
            validity_part = (
                f" / validity: {_clean(a.validity) or 'unknown'}"
                if a.family == "secret_scanning"
                else ""
            )
            parts.append(
                f"- **State / resolution:** {_clean(a.state)} / "
                f"{_clean(resolution) or '—'}{validity_part}\n"
            )
            if a.created_at:
                parts.append(f"- **Created:** {a.created_at}\n")
            if a.resolved_at:
                parts.append(f"- **Resolved:** {a.resolved_at}\n")
            parts.append(
                f"- **Closure confirmed:** "
                f"{'true' if f.closure_confirmed else 'false'}\n"
            )
            parts.append(f"- **Basis:** {_clean(f.basis)}\n")
            parts.append(f"- **Closure claim:** {_clean(f.closure_claim)}\n")
            if f.evidence_chain:
                parts.append("- **Evidence chain:**\n")
                for item in f.evidence_chain:
                    parts.append(f"  - {_clean(item)}\n")
            parts.append(
                f"- **Evidence strength / proof grade:** {f.evidence_strength} "
                f"/ {f.proof_grade}\n"
            )
            if f.why_not_gcs0:
                parts.append(f"- **Why not GCS-0:** {_clean(f.why_not_gcs0)}\n")
            if f.recommended_next_evidence:
                parts.append(
                    f"- **Next evidence needed:** "
                    f"{_clean(f.recommended_next_evidence)}\n"
                )
            if f.blockers:
                parts.append("- **Closure blockers:**\n")
                for b in f.blockers:
                    parts.append(f"  - {_clean(b)}\n")
            parts.append(
                f"- **Recommended next action:** {_clean(f.recommended_action)}\n"
            )
            if a.html_url and not config.redact_repo_names:
                parts.append(f"- **Alert:** {a.html_url}\n")
            parts.append("\n")

    parts.append("## Relocation / migration risk\n")
    if not result.relocations:
        parts.append(
            "No relocation observed: no risk in scope was found closed in one "
            "place while the same causal class (same secret hash, advisory, or "
            "rule) is live in another. Note this is observed within audited "
            "scope only — it cannot see forks, logs, or repos outside scope.\n\n"
        )
    else:
        parts.append(
            f"{len(result.relocations)} risk(s) closed in one location are "
            "still live in another — closure relocated rather than resolved:\n\n"
        )
        for r in result.relocations:
            origin = (
                pseudonymize_repo(r.origin_repo)
                if config.redact_repo_names
                else r.origin_repo
            )
            parts.append(
                f"### {FAMILY_TITLES[r.family]} — {_clean(r.causal_class)} "
                f"({r.confidence} confidence)\n"
            )
            parts.append(
                f"- **Origin (closed):** {_clean(origin)}#{r.origin_number} "
                f"({_clean(r.origin_state)})"
                + (f", closed {r.origin_closed_at}" if r.origin_closed_at else "")
                + "\n"
            )
            parts.append("- **Still live at:**\n")
            for d in r.destinations:
                drepo = (
                    pseudonymize_repo(d["repo"])
                    if config.redact_repo_names
                    else d["repo"]
                )
                loc = f"{_clean(drepo)}#{d['number']} ({_clean(d['state'])})"
                if d.get("manifest_path"):
                    loc += f" in {_clean(d['manifest_path'])}"
                parts.append(f"  - {loc}\n")
            if r.relocation_after_closure and r.observed_relocation_seconds is not None:
                days = r.observed_relocation_seconds / 86400
                parts.append(
                    f"- **Observed post-closure relocation:** a live location "
                    f"was first detected {days:.1f} days after the origin was "
                    "closed (real interval from GitHub timestamps).\n"
                )
            if r.multi_repo_attested:
                parts.append(
                    "- **Platform-attested:** GitHub flags this secret as "
                    "spanning multiple repositories.\n"
                )
            parts.append(f"- **Basis:** {_clean(r.basis)}\n")
            parts.append(f"- **Recommended action:** {_clean(r.recommended_action)}\n\n")

    parts.append("## Recommended remediation order\n")
    parts.append(
        "1. GCS-4 first: revoke/rotate active credentials at the issuing "
        "provider.\n"
        "2. GCS-3 next: produce provider-side proof of revocation for "
        "administratively closed alerts, or rotate.\n"
        "3. GCS-2: obtain validity evidence; treat as live until proven "
        "otherwise.\n"
        "4. GCS-1: finish the closure workflow (resolve open alerts whose "
        "credentials are already inactive, or re-check after the delay "
        "window).\n"
    )

    if config.include_limitations:
        parts.append("\n## Limitations\n")
        parts.append(LIMITATIONS + "\n")

    parts.append("## Evidence appendix\n")
    parts.append(
        "Evidence per alert is limited to: GitHub alert metadata (state, "
        "resolution, timestamps), the provider validity field, and SHA-256 "
        "fingerprints of secret values where the API exposed them. Raw "
        "secret values are never stored or reproduced.\n"
    )
    if result.errors:
        parts.append("\n### Data-collection errors (fail-closed)\n")
        for e in result.errors:
            parts.append(f"- {_clean(e)}\n")

    return "".join(parts)


# ── HTML ────────────────────────────────────────────────────────────────────
_GCS_COLORS = {
    GCS.VERIFIED_CLOSED: "#1a7f37",
    GCS.LOW_RESIDUAL_RISK: "#4d7c0f",
    GCS.PROVISIONAL: "#9a6700",
    GCS.FALSE_CLOSURE_RISK: "#bc4c00",
    GCS.ACTIVE_RISK: "#cf222e",
}


def render_html(result: AuditResult, config: Config) -> str:
    def esc(value: Any) -> str:
        return html_module.escape(_clean(value))

    rows = []
    for f in _sorted_findings(result):
        a = f.alert
        color = _GCS_COLORS[f.gcs]
        blockers = "".join(f"<li>{esc(b)}</li>" for b in f.blockers)
        resolution = a.resolution or a.dismissed_reason
        evidence = f.evidence_strength
        if a.family == "secret_scanning":
            evidence = f"validity: {esc(a.validity) or 'unknown'}"
        rows.append(
            f"<tr>"
            f"<td>#{a.number}<br><small>{FAMILY_TITLES[a.family]}</small></td>"
            f"<td>{esc(_display_repo(f, config))}</td>"
            f"<td>{esc(a.display_type)}</td>"
            f"<td>{esc(a.state)} / {esc(resolution) or '—'}</td>"
            f"<td>{evidence}</td>"
            f"<td><strong style='color:{color}'>{f.gcs.label}</strong> "
            f"{esc(f.gcs.title)}</td>"
            f"<td>{'yes' if f.closure_confirmed else 'no'}</td>"
            f"<td>{esc(f.basis)}<ul>{blockers}</ul>"
            f"<em>Next: {esc(f.recommended_action)}</em></td>"
            f"</tr>"
        )
    summary = html_module.escape(summary_block(result))
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Ground Cyber Closure Report</title>
<style>
body{{font-family:-apple-system,Segoe UI,sans-serif;margin:2rem;color:#1f2328}}
pre{{background:#f6f8fa;padding:1rem;border-radius:6px}}
table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #d0d7de;padding:.5rem;vertical-align:top;text-align:left}}
th{{background:#f6f8fa}}
</style>
</head>
<body>
<h1>Ground Cyber Closure Report</h1>
<p><em>Closed is a status. Revoked is evidence. Unknown validity is not safe.</em></p>
<pre>{summary}</pre>
<p>Scope: {html_module.escape(_scope_text(result, config))}<br>
Generated at: {esc(result.generated_at)} · groundcyber v{__version__}</p>
<h2>Findings</h2>
<table>
<tr><th>Alert</th><th>Repo</th><th>Finding</th><th>State / resolution</th>
<th>Evidence</th><th>GCS</th><th>Closure confirmed</th><th>Reasoning</th></tr>
{''.join(rows) if rows else '<tr><td colspan="8">No alerts in scope.</td></tr>'}
</table>
<h2>Methodology</h2><pre>{html_module.escape(METHODOLOGY)}</pre>
<h2>Security and privacy model</h2><pre>{html_module.escape(SECURITY_MODEL)}</pre>
<h2>Limitations</h2><pre>{html_module.escape(LIMITATIONS)}</pre>
</body>
</html>
"""


RENDERERS = {
    "markdown": ("groundcyber-report.md", render_markdown),
    "json": ("groundcyber-report.json", render_json),
    "html": ("groundcyber-report.html", render_html),
}


def write_reports(result: AuditResult, config: Config, out_dir: str) -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for fmt in config.outputs:
        filename, renderer = RENDERERS[fmt]
        path = out / filename
        path.write_text(renderer(result, config))
        written.append(path)
    return written
