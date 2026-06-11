"""Data model for the Ground Cyber closure audit.

GCS — Ground Closure State, applied per alert family:

  GCS-0  verified closed     defensible evidence chain only (see below)
  GCS-1  low residual risk   mostly closed, minor evidence gap
  GCS-2  provisional         incomplete or unavailable closure evidence
  GCS-3  false-closure risk  closed administratively / risk acceptance /
                             scanner drift, no closure evidence
  GCS-4  active risk         exploitable now

GCS-0 is the only state in which ``closure_confirmed`` may be true, and
each family has its own non-weakenable evidence requirement:

  secret scanning   provider-side validity == "inactive". Nothing else.
  dependabot        state "fixed" (platform dependency-graph evidence)
                    AND independent read-only manifest verification that
                    the vulnerable range is gone.
  code scanning     state "fixed" (scanner re-scan evidence) AND scan
                    continuity: the same tool demonstrably kept analyzing
                    the repository after the fix.

Resolution labels, dismissals, auto-dismissals, and human overrides never
produce GCS-0 in any family. Unknown evidence is not safe.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


class GCS(IntEnum):
    VERIFIED_CLOSED = 0
    LOW_RESIDUAL_RISK = 1
    PROVISIONAL = 2
    FALSE_CLOSURE_RISK = 3
    ACTIVE_RISK = 4

    @property
    def label(self) -> str:
        return f"GCS-{int(self)}"

    @property
    def title(self) -> str:
        return _GCS_TITLES[self]


_GCS_TITLES = {
    GCS.VERIFIED_CLOSED: "Verified closed",
    GCS.LOW_RESIDUAL_RISK: "Low residual risk",
    GCS.PROVISIONAL: "Provisional / unknown",
    GCS.FALSE_CLOSURE_RISK: "False-closure risk",
    GCS.ACTIVE_RISK: "Active risk",
}

# Alert families.
FAMILY_SECRET_SCANNING = "secret_scanning"
FAMILY_DEPENDABOT = "dependabot"
FAMILY_CODE_SCANNING = "code_scanning"
ALL_FAMILIES = (FAMILY_SECRET_SCANNING, FAMILY_DEPENDABOT, FAMILY_CODE_SCANNING)

FAMILY_TITLES = {
    FAMILY_SECRET_SCANNING: "Secret scanning",
    FAMILY_DEPENDABOT: "Dependabot",
    FAMILY_CODE_SCANNING: "Code scanning",
}

# Validity states GitHub's secret-scanning API can report.
VALIDITY_ACTIVE = "active"
VALIDITY_INACTIVE = "inactive"
VALIDITY_UNKNOWN = "unknown"

# Evidence strength for the closure evidence chain.
EVIDENCE_STRONG = "strong"
EVIDENCE_MODERATE = "moderate"
EVIDENCE_WEAK = "weak"
EVIDENCE_UNAVAILABLE = "unavailable"

# Proof grades: what kind of evidence the verdict rests on.
PROOF_PROVIDER_VALIDITY = "provider_validity"          # secret scanning
PROOF_INDEPENDENT_VERIFICATION = "independent_verification"  # dependabot manifest check
PROOF_SCANNER_VERIFIED = "scanner_verified"            # code scanning + continuity
PROOF_PLATFORM_STATE = "platform_state"                # GitHub state only
PROOF_ADMINISTRATIVE = "administrative"                # label / dismissal only
PROOF_NONE = "none"


@dataclass
class Alert:
    """A sanitized alert from any family. Never carries a raw secret value.

    ``secret_hash`` is the SHA-256 of the secret if the API exposed it
    (hashed immediately on receipt, raw value discarded); otherwise None.
    Family-specific fields are None outside their family.
    """

    number: int
    repo: str  # "owner/name"
    state: str  # secret: open|resolved · dependabot: open|fixed|dismissed|auto_dismissed · code: open|fixed|dismissed
    secret_type: str = ""
    secret_type_display: str = ""
    family: str = FAMILY_SECRET_SCANNING
    resolution: Optional[str] = None
    validity: Optional[str] = None  # "active" | "inactive" | "unknown" | None
    secret_hash: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    resolved_at: Optional[str] = None
    resolved_by: Optional[str] = None
    publicly_leaked: Optional[bool] = None
    multi_repo: Optional[bool] = None
    push_protection_bypassed: Optional[bool] = None
    html_url: Optional[str] = None
    fetch_error: Optional[str] = None  # set when evidence could not be retrieved

    # Shared risk metadata (dependabot / code scanning)
    severity: Optional[str] = None  # critical|high|medium|low (normalized)
    dismissed_reason: Optional[str] = None
    dismissed_comment: Optional[str] = None
    fixed_at: Optional[str] = None

    # Dependabot-specific
    package_name: Optional[str] = None
    package_ecosystem: Optional[str] = None
    manifest_path: Optional[str] = None
    vulnerable_range: Optional[str] = None
    first_patched_version: Optional[str] = None
    advisory_id: Optional[str] = None
    # Result of independent manifest verification:
    #   True   = vulnerable range confirmed absent (strong)
    #   False  = vulnerable version still appears present (active risk)
    #   None   = verification unavailable/unsupported (never safe)
    manifest_verified: Optional[bool] = None
    manifest_verification_note: Optional[str] = None

    # Code-scanning-specific
    rule_id: Optional[str] = None
    rule_description: Optional[str] = None
    tool_name: Optional[str] = None
    # Result of scan-continuity check:
    #   True   = same tool uploaded analyses after the alert was fixed
    #   False  = tool demonstrably stopped analyzing (drift risk)
    #   None   = continuity could not be established
    scan_continuity: Optional[bool] = None
    scan_continuity_note: Optional[str] = None

    @property
    def display_type(self) -> str:
        """What kind of finding this is, for tables and summaries."""
        if self.family == FAMILY_SECRET_SCANNING:
            return self.secret_type_display or self.secret_type or "secret"
        if self.family == FAMILY_DEPENDABOT:
            pkg = self.package_name or "dependency"
            sev = f" ({self.severity})" if self.severity else ""
            return f"{pkg}{sev}"
        rule = self.rule_id or "code finding"
        sev = f" ({self.severity})" if self.severity else ""
        return f"{rule}{sev}"


@dataclass
class Finding:
    """The deterministic closure verdict for one alert, with evidence chain."""

    alert: Alert
    gcs: GCS
    closure_confirmed: bool
    basis: str
    blockers: list[str] = field(default_factory=list)
    recommended_action: str = ""

    # Evidence-chain model
    closure_claim: str = ""          # what the platform/humans assert
    evidence_chain: list[str] = field(default_factory=list)  # evidence items, in order
    evidence_strength: str = EVIDENCE_UNAVAILABLE
    evidence_source: str = ""        # where the decisive evidence came from
    proof_grade: str = PROOF_NONE
    why_not_gcs0: str = ""           # empty only when gcs is GCS-0
    recommended_next_evidence: str = ""

    @property
    def display_repo(self) -> str:
        return self.alert.repo


@dataclass
class AuditResult:
    findings: list[Finding]
    scope_description: str
    generated_at: str
    errors: list[str] = field(default_factory=list)

    def count(self, gcs: GCS) -> int:
        return sum(1 for f in self.findings if f.gcs is gcs)

    def count_family(self, family: str) -> int:
        return sum(1 for f in self.findings if f.alert.family == family)

    @property
    def total(self) -> int:
        return len(self.findings)

    @property
    def highest_risk(self) -> Optional[Finding]:
        if not self.findings:
            return None
        worst = max(f.gcs for f in self.findings)
        if worst <= GCS.LOW_RESIDUAL_RISK:
            return None
        candidates = [f for f in self.findings if f.gcs is worst]
        return candidates[0]
