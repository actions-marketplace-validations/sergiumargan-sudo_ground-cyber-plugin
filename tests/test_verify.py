"""Manifest verification: must fail closed on any parsing uncertainty."""

import json

from groundcyber.verify import parse_version, verify_manifest, version_in_range


def test_parse_version_strictly_numeric():
    assert parse_version("4.17.21") == (4, 17, 21)
    assert parse_version("v1.2") == (1, 2)
    assert parse_version("1.2.3-beta") is None
    assert parse_version("latest") is None
    assert parse_version("") is None


def test_version_in_range_basic():
    assert version_in_range("4.17.20", "< 4.17.21") is True
    assert version_in_range("4.17.21", "< 4.17.21") is False
    assert version_in_range("4.5.0", ">= 4.0.0, < 4.17.21") is True
    assert version_in_range("3.9.9", ">= 4.0.0, < 4.17.21") is False
    assert version_in_range("2.0", "= 2.0.0") is True


def test_version_in_range_fails_closed_on_uncertainty():
    assert version_in_range("4.17.21-rc1", "< 4.17.21") is None
    assert version_in_range("4.17.20", "~> 4.17") is None  # unknown operator
    assert version_in_range("4.17.20", "") is None


PACKAGE_LOCK_FIXED = json.dumps(
    {
        "packages": {
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/other": {"version": "1.0.0"},
        }
    }
)
PACKAGE_LOCK_VULNERABLE = json.dumps(
    {"packages": {"node_modules/lodash": {"version": "4.17.0"}}}
)
PACKAGE_LOCK_REMOVED = json.dumps({"packages": {"node_modules/other": {"version": "1.0.0"}}})


def test_package_lock_verification():
    ok, note = verify_manifest(
        PACKAGE_LOCK_FIXED, "package-lock.json", "lodash", "< 4.17.21"
    )
    assert ok is True

    bad, note = verify_manifest(
        PACKAGE_LOCK_VULNERABLE, "package-lock.json", "lodash", "< 4.17.21"
    )
    assert bad is False
    assert "4.17.0" in note

    gone, note = verify_manifest(
        PACKAGE_LOCK_REMOVED, "package-lock.json", "lodash", "< 4.17.21"
    )
    assert gone is True
    assert "no longer present" in note


def test_nested_package_lock_vulnerable_copy_detected():
    text = json.dumps(
        {
            "packages": {
                "node_modules/lodash": {"version": "4.17.21"},
                "node_modules/dep/node_modules/lodash": {"version": "4.17.0"},
            }
        }
    )
    ok, note = verify_manifest(text, "package-lock.json", "lodash", "< 4.17.21")
    assert ok is False  # the nested vulnerable copy still counts


def test_requirements_txt_verification():
    ok, _ = verify_manifest(
        "flask==2.3.0\nrequests==2.32.0\n", "requirements.txt", "requests", "< 2.31.0"
    )
    assert ok is True
    bad, _ = verify_manifest(
        "requests==2.25.0\n", "requirements.txt", "requests", "< 2.31.0"
    )
    assert bad is False
    # Loose pin: present but unverifiable -> fail closed
    loose, note = verify_manifest(
        "requests>=2.0\n", "requirements.txt", "requests", "< 2.31.0"
    )
    assert loose is None


def test_gemfile_lock_verification():
    text = "GEM\n  specs:\n    rails (7.1.2)\n    rack (3.0.8)\n"
    ok, _ = verify_manifest(text, "Gemfile.lock", "rack", "< 3.0.0")
    assert ok is True
    bad, _ = verify_manifest(text, "Gemfile.lock", "rack", "< 3.1.0")
    assert bad is False


def test_unsupported_manifest_fails_closed():
    verdict, note = verify_manifest("anything", "pom.xml", "log4j", "< 2.17.0")
    assert verdict is None
    assert "not supported" in note


def test_corrupt_json_fails_closed():
    verdict, note = verify_manifest(
        "{not json", "package-lock.json", "lodash", "< 4.17.21"
    )
    assert verdict is None
