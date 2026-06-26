"""Relocation detection: observed-both-ends only, no false positives."""

from groundcyber.models import (
    FAMILY_CODE_SCANNING,
    FAMILY_DEPENDABOT,
    FAMILY_SECRET_SCANNING,
    Alert,
)
from groundcyber.relocation import detect_relocations


def secret(number, repo, state, validity=None, secret_hash="a" * 64, **kw):
    return Alert(
        number=number,
        repo=repo,
        family=FAMILY_SECRET_SCANNING,
        state=state,
        validity=validity,
        secret_hash=secret_hash,
        **kw,
    )


def dep(number, repo, state, advisory="GHSA-xxxx", package="lodash", manifest="package-lock.json", **kw):
    return Alert(
        number=number,
        repo=repo,
        family=FAMILY_DEPENDABOT,
        state=state,
        advisory_id=advisory,
        package_name=package,
        manifest_path=manifest,
        **kw,
    )


def code(number, repo, state, rule="js/sqli", tool="CodeQL", **kw):
    return Alert(
        number=number,
        repo=repo,
        family=FAMILY_CODE_SCANNING,
        state=state,
        rule_id=rule,
        tool_name=tool,
        **kw,
    )


def test_secret_closed_here_live_elsewhere_is_relocation():
    alerts = [
        secret(1, "acme/api", "resolved", resolved_at="2026-01-01T00:00:00Z"),
        secret(2, "acme/web", "open", created_at="2026-01-05T00:00:00Z"),
    ]
    rel = detect_relocations(alerts)
    assert len(rel) == 1
    assert rel[0].family == FAMILY_SECRET_SCANNING
    assert rel[0].confidence == "high"
    assert rel[0].origin_number == 1
    assert any(d["number"] == 2 for d in rel[0].destinations)


def test_observed_post_closure_relocation_has_real_interval():
    alerts = [
        secret(1, "acme/api", "resolved", resolved_at="2026-01-01T00:00:00Z"),
        secret(2, "acme/web", "open", created_at="2026-01-11T00:00:00Z"),
    ]
    rel = detect_relocations(alerts)[0]
    assert rel.relocation_after_closure is True
    # 10 days in seconds
    assert rel.observed_relocation_seconds == 10 * 86400


def test_destination_predating_closure_is_relocation_but_not_after_closure():
    alerts = [
        secret(1, "acme/api", "resolved", resolved_at="2026-02-01T00:00:00Z"),
        secret(2, "acme/web", "open", created_at="2026-01-01T00:00:00Z"),
    ]
    rel = detect_relocations(alerts)[0]
    assert rel.relocation_after_closure is False
    assert rel.observed_relocation_seconds is None


def test_active_credential_counts_as_live_destination():
    alerts = [
        secret(1, "acme/api", "resolved", resolved_at="2026-01-01T00:00:00Z"),
        secret(2, "acme/api", "resolved", validity="active"),
    ]
    rel = detect_relocations(alerts)
    assert len(rel) == 1


def test_single_alert_never_produces_relocation():
    assert detect_relocations([secret(1, "acme/api", "resolved")]) == []


def test_no_false_positive_on_different_secret_hash():
    alerts = [
        secret(1, "acme/api", "resolved", secret_hash="a" * 64),
        secret(2, "acme/web", "open", secret_hash="b" * 64),
    ]
    assert detect_relocations(alerts) == []


def test_all_closed_no_relocation():
    alerts = [
        secret(1, "acme/api", "resolved"),
        secret(2, "acme/web", "resolved"),
    ]
    assert detect_relocations(alerts) == []


def test_dependabot_relocation_across_manifests():
    alerts = [
        dep(1, "acme/api", "fixed", manifest="package-lock.json",
            fixed_at="2026-01-01T00:00:00Z"),
        dep(2, "acme/api", "open", manifest="frontend/package-lock.json",
            created_at="2026-01-03T00:00:00Z"),
    ]
    rel = detect_relocations(alerts)
    assert len(rel) == 1
    assert rel[0].family == FAMILY_DEPENDABOT
    assert rel[0].relocation_after_closure is True


def test_dependabot_different_advisory_not_grouped():
    alerts = [
        dep(1, "acme/api", "fixed", advisory="GHSA-1111"),
        dep(2, "acme/api", "open", advisory="GHSA-2222", manifest="other/package-lock.json"),
    ]
    assert detect_relocations(alerts) == []


def test_code_scanning_relocation_same_rule():
    alerts = [
        code(1, "acme/api", "dismissed"),
        code(2, "acme/api", "open", created_at="2026-01-02T00:00:00Z"),
    ]
    rel = detect_relocations(alerts)
    assert len(rel) == 1
    assert rel[0].confidence == "moderate"  # rule class, not identical sink


def test_multi_repo_secret_is_attested():
    alerts = [
        secret(1, "acme/api", "resolved", multi_repo=True,
               resolved_at="2026-01-01T00:00:00Z"),
        secret(2, "acme/web", "open", multi_repo=True,
               created_at="2026-01-02T00:00:00Z"),
    ]
    rel = detect_relocations(alerts)[0]
    assert rel.multi_repo_attested is True


def test_relocation_never_contains_raw_secret_hash_in_full():
    # causal_class uses only a 12-char prefix, never the full hash.
    alerts = [
        secret(1, "acme/api", "resolved", secret_hash="f" * 64),
        secret(2, "acme/web", "open", secret_hash="f" * 64),
    ]
    rel = detect_relocations(alerts)[0]
    assert "f" * 64 not in rel.causal_class
    assert rel.causal_class == "secret:" + "f" * 12
