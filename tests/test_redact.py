"""Redaction and hashing: secret-shaped strings must never survive output."""

import hashlib

from groundcyber.redact import (
    fingerprint,
    hash_secret,
    pseudonymize_repo,
    redact_text,
)

# Samples are assembled at runtime so this file never contains a literal
# that secret scanners (e.g. GitHub push protection) would flag. The joined
# strings are identical to real token shapes; the redaction filter must
# catch every one of them.
SECRET_SAMPLES = [
    "ghp_" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
    "github_pat_" + "11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz0123456789",
    "gho_" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
    "AKIA" + "IOSFODNN7EXAMPLE",
    "sk-proj-" + "abcdefghijklmnopqrstuvwxyz0123456789",
    "xoxb-" + "123456789012-abcdefghijklmnop",
    "glpat-" + "abcdefghij1234567890",
    "AIza" + "SyA1234567890abcdefghijklmnopqrstuv",
    "sk_live_" + "abcdefghijklmnop1234",
    "npm_" + "abcdefghijklmnopqrstuvwxyz0123456789",
    "eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0" + ".dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk0",
    "-----BEGIN RSA PRIVATE" + " KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE" + " KEY-----",
    'api_key = "' + "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA" + '"',
]


def test_hash_secret_is_sha256():
    value = "ghp_" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
    assert hash_secret(value) == hashlib.sha256(value.encode()).hexdigest()


def test_every_secret_sample_is_redacted():
    for sample in SECRET_SAMPLES:
        out = redact_text(f"prefix {sample} suffix")
        core = sample.splitlines()[1] if "\n" in sample else sample
        assert core not in out, f"raw secret survived redaction: {sample[:12]}..."
        assert "[REDACTED-SECRET:sha256:" in out


def test_redaction_marker_is_stable_fingerprint():
    sample = "ghp_" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
    out = redact_text(sample)
    assert fingerprint(sample) in out
    assert redact_text(sample) == out


def test_plain_text_passes_through():
    text = "Alert #1842 was closed as used_in_tests with no inactive evidence."
    assert redact_text(text) == text


def test_empty_and_none_safe():
    assert redact_text("") == ""


def test_pseudonymize_repo_is_stable_and_opaque():
    a = pseudonymize_repo("acme/payments-api")
    b = pseudonymize_repo("acme/payments-api")
    c = pseudonymize_repo("acme/other")
    assert a == b
    assert a != c
    assert "acme" not in a
