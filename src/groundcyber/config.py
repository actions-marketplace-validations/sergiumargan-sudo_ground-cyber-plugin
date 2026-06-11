"""Configuration loading for .groundcyber.yml.

Safety-critical settings cannot be weakened by configuration:
- ``require_provider_inactive_for_gcs0`` must remain true.
- ``treat_unknown_validity_as`` may map unknown validity to "provisional"
  or "active_risk", never to a safe state.
- ``read_only``, ``store_raw_secrets``, ``print_raw_secrets`` cannot be
  flipped to unsafe values.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from .models import (
    ALL_FAMILIES,
    FAMILY_CODE_SCANNING,
    FAMILY_DEPENDABOT,
    FAMILY_SECRET_SCANNING,
)

DEFAULT_CONFIG_FILENAME = ".groundcyber.yml"

# Resolution labels that are administrative statements, not closure evidence.
DEFAULT_NON_CLOSING_LABELS = [
    "revoked",
    "used_in_tests",
    "false_positive",
    "wont_fix",
    "pattern_deleted",
    "pattern_edited",
]

SAMPLE_CONFIG = """\
# Ground Cyber configuration
# Closed is a status. Revoked is evidence. Unknown validity is not safe.

scope:
  org: ""
  repos: []            # explicit "owner/name" entries audited in addition to org scope
  include_repos: []    # glob patterns; when set, only matching repos are audited
  exclude_repos: []    # glob patterns; matching repos are skipped

github:
  read_only: true                # must stay true; the tool only issues GET requests
  secret_scanning_alerts: true
  dependabot_alerts: true
  code_scanning_alerts: true

closure:
  # GCS-0 requires provider-side validity == "inactive". This rule cannot be
  # disabled; setting it to false is a configuration error.
  require_provider_inactive_for_gcs0: true
  # How an open alert with unknown/absent validity is scored:
  #   "provisional"  -> GCS-2
  #   "active_risk"  -> GCS-4
  treat_unknown_validity_as: "provisional"
  # Resolutions older than this with no inactive evidence get a staleness blocker.
  stale_resolved_days: 30
  # When true, inactive validity observed within 24h of resolution is capped at
  # GCS-1 until a delayed re-check confirms the credential stayed inactive.
  require_delayed_recheck: false
  # Administrative labels that never count as closure evidence by themselves.
  resolution_labels_do_not_close:
    - revoked
    - used_in_tests
    - false_positive
    - wont_fix
    - pattern_deleted
    - pattern_edited

privacy:
  store_raw_secrets: false   # must stay false
  print_raw_secrets: false   # must stay false
  hash_secret_values: true   # must stay true
  redact_repo_names: false
  upload_to_ground_dashboard: false  # placeholder; uploads are not implemented

report:
  outputs:
    - markdown
    - json
  out_dir: "./groundcyber-report"
  include_methodology: true
  include_limitations: true
"""

VALID_OUTPUTS = ("markdown", "json", "html")
VALID_UNKNOWN_TREATMENTS = ("provisional", "active_risk")


class ConfigError(ValueError):
    """Raised for invalid or unsafe configuration."""


@dataclass
class Config:
    org: str = ""
    repos: list[str] = field(default_factory=list)
    include_repos: list[str] = field(default_factory=list)
    exclude_repos: list[str] = field(default_factory=list)

    treat_unknown_validity_as: str = "provisional"
    stale_resolved_days: int = 30
    require_delayed_recheck: bool = False
    non_closing_labels: list[str] = field(
        default_factory=lambda: list(DEFAULT_NON_CLOSING_LABELS)
    )

    redact_repo_names: bool = False

    families: list[str] = field(default_factory=lambda: list(ALL_FAMILIES))

    outputs: list[str] = field(default_factory=lambda: ["markdown", "json"])
    out_dir: str = "./groundcyber-report"
    include_methodology: bool = True
    include_limitations: bool = True

    def repo_in_scope(self, full_name: str) -> bool:
        """Apply include/exclude glob filtering to an "owner/name" string."""
        if self.exclude_repos and any(
            fnmatch.fnmatch(full_name, pat) for pat in self.exclude_repos
        ):
            return False
        if self.include_repos:
            return any(fnmatch.fnmatch(full_name, pat) for pat in self.include_repos)
        return True


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ConfigError(message)


def load_config(path: Optional[str] = None) -> Config:
    """Load .groundcyber.yml; missing file yields safe defaults."""
    if path:
        file = Path(path)
        _require(file.exists(), f"config file not found: {path}")
    else:
        file = Path(DEFAULT_CONFIG_FILENAME)
        if not file.exists():
            return Config()
    try:
        data = yaml.safe_load(file.read_text()) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {file}: {exc}") from exc
    return parse_config(data)


def parse_config(data: dict[str, Any]) -> Config:
    if not isinstance(data, dict):
        raise ConfigError("config root must be a mapping")

    scope = data.get("scope") or {}
    github = data.get("github") or {}
    closure = data.get("closure") or {}
    privacy = data.get("privacy") or {}
    report = data.get("report") or {}

    # Reject any attempt to weaken the safety rules.
    _require(
        closure.get("require_provider_inactive_for_gcs0", True) is True,
        "closure.require_provider_inactive_for_gcs0 cannot be disabled: "
        "GCS-0 always requires provider-side inactive validity",
    )
    _require(
        github.get("read_only", True) is True,
        "github.read_only cannot be disabled: the tool only issues GET requests",
    )
    _require(
        privacy.get("store_raw_secrets", False) is False,
        "privacy.store_raw_secrets must remain false",
    )
    _require(
        privacy.get("print_raw_secrets", False) is False,
        "privacy.print_raw_secrets must remain false",
    )
    _require(
        privacy.get("hash_secret_values", True) is True,
        "privacy.hash_secret_values must remain true",
    )
    _require(
        privacy.get("upload_to_ground_dashboard", False) is False,
        "privacy.upload_to_ground_dashboard is a placeholder and must remain false",
    )

    unknown_as = closure.get("treat_unknown_validity_as", "provisional")
    _require(
        unknown_as in VALID_UNKNOWN_TREATMENTS,
        f"closure.treat_unknown_validity_as must be one of {VALID_UNKNOWN_TREATMENTS}, "
        f"got {unknown_as!r} (unknown validity is never safe)",
    )

    outputs = report.get("outputs") or ["markdown", "json"]
    for out in outputs:
        _require(out in VALID_OUTPUTS, f"unknown report output {out!r}")

    stale_days = closure.get("stale_resolved_days", 30)
    _require(
        isinstance(stale_days, int) and stale_days >= 0,
        "closure.stale_resolved_days must be a non-negative integer",
    )

    labels = closure.get("resolution_labels_do_not_close")
    non_closing = list(DEFAULT_NON_CLOSING_LABELS)
    if labels:
        # Labels may be added but the defaults can never be removed.
        for label in labels:
            if label not in non_closing:
                non_closing.append(label)

    families = []
    if github.get("secret_scanning_alerts", True):
        families.append(FAMILY_SECRET_SCANNING)
    if github.get("dependabot_alerts", True):
        families.append(FAMILY_DEPENDABOT)
    if github.get("code_scanning_alerts", True):
        families.append(FAMILY_CODE_SCANNING)
    _require(bool(families), "at least one alert family must be enabled")

    return Config(
        org=scope.get("org") or "",
        repos=list(scope.get("repos") or []),
        include_repos=list(scope.get("include_repos") or []),
        exclude_repos=list(scope.get("exclude_repos") or []),
        treat_unknown_validity_as=unknown_as,
        stale_resolved_days=stale_days,
        require_delayed_recheck=bool(closure.get("require_delayed_recheck", False)),
        non_closing_labels=non_closing,
        redact_repo_names=bool(privacy.get("redact_repo_names", False)),
        families=families,
        outputs=list(outputs),
        out_dir=report.get("out_dir") or "./groundcyber-report",
        include_methodology=bool(report.get("include_methodology", True)),
        include_limitations=bool(report.get("include_limitations", True)),
    )


def write_sample_config(path: str = DEFAULT_CONFIG_FILENAME, force: bool = False) -> Path:
    file = Path(path)
    if file.exists() and not force:
        raise ConfigError(f"{file} already exists (use --force to overwrite)")
    file.write_text(SAMPLE_CONFIG)
    return file
