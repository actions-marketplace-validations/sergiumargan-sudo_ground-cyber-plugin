"""Independent, read-only evidence verification for Dependabot closures.

GitHub marks a Dependabot alert "fixed" when its dependency graph no longer
resolves the vulnerable version. That is platform evidence. This module
builds the stronger, independent leg of the evidence chain: fetch the
manifest/lockfile named by the alert (read-only) and confirm the vulnerable
range is actually gone.

Everything here fails closed: any parse ambiguity, unsupported format, or
non-numeric version component returns None ("unverifiable"), never a safe
verdict. A wrong "verified" is worse than a missing one.
"""

from __future__ import annotations

import json
import re
from typing import Optional

_NUMERIC_VERSION = re.compile(r"^v?(\d+)(\.\d+)*$")


def parse_version(text: str) -> Optional[tuple[int, ...]]:
    """Parse a strictly numeric dotted version. Anything else -> None."""
    text = text.strip()
    if not _NUMERIC_VERSION.match(text):
        return None
    return tuple(int(part) for part in text.lstrip("v").split("."))


def _compare(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    length = max(len(a), len(b))
    a = a + (0,) * (length - len(a))
    b = b + (0,) * (length - len(b))
    return (a > b) - (a < b)


_CLAUSE = re.compile(r"^(<=|>=|<|>|==|=)\s*(.+)$")


def version_in_range(version: str, vulnerable_range: str) -> Optional[bool]:
    """Whether ``version`` falls inside a GitHub vulnerable_version_range.

    Range syntax: comma-separated clauses, e.g. ">= 4.0.0, < 4.17.21".
    Returns None when the version or any clause cannot be parsed with
    certainty.
    """
    parsed = parse_version(version)
    if parsed is None or not vulnerable_range:
        return None
    for clause in vulnerable_range.split(","):
        clause = clause.strip()
        if not clause:
            continue
        match = _CLAUSE.match(clause)
        if not match:
            return None
        operator, bound_text = match.groups()
        bound = parse_version(bound_text)
        if bound is None:
            return None
        cmp = _compare(parsed, bound)
        satisfied = {
            "<": cmp < 0,
            "<=": cmp <= 0,
            ">": cmp > 0,
            ">=": cmp >= 0,
            "=": cmp == 0,
            "==": cmp == 0,
        }[operator]
        if not satisfied:
            return False
    return True


# ── per-format extractors: return list of versions found, or None ──────────
def _versions_package_lock(text: str, package: str) -> Optional[list[str]]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    versions: list[str] = []
    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfile v2/v3
        for path, meta in packages.items():
            if not isinstance(meta, dict):
                continue
            if path == f"node_modules/{package}" or path.endswith(
                f"/node_modules/{package}"
            ):
                version = meta.get("version")
                if version:
                    versions.append(str(version))

    def _walk_v1(deps: dict) -> None:
        for name, meta in deps.items():
            if not isinstance(meta, dict):
                continue
            if name == package and meta.get("version"):
                versions.append(str(meta["version"]))
            if isinstance(meta.get("dependencies"), dict):
                _walk_v1(meta["dependencies"])

    if isinstance(data.get("dependencies"), dict):
        _walk_v1(data["dependencies"])
    return versions


def _versions_yarn_lock(text: str, package: str) -> Optional[list[str]]:
    versions: list[str] = []
    block_header = re.compile(
        r'^"?' + re.escape(package) + r'@[^\n]*:\s*$', re.MULTILINE
    )
    for match in block_header.finditer(text):
        block = text[match.end() : match.end() + 500]
        version_match = re.search(r'version\s+"([^"]+)"', block)
        if version_match:
            versions.append(version_match.group(1))
    return versions


def _versions_requirements(text: str, package: str) -> Optional[list[str]]:
    versions: list[str] = []
    pattern = re.compile(
        r"^\s*" + re.escape(package) + r"\s*==\s*([A-Za-z0-9.\-_]+)",
        re.IGNORECASE | re.MULTILINE,
    )
    loose = re.compile(
        r"^\s*" + re.escape(package) + r"\s*[<>~!]", re.IGNORECASE | re.MULTILINE
    )
    for match in pattern.finditer(text):
        versions.append(match.group(1))
    if not versions and loose.search(text):
        return None  # range pin: present but version not determinable
    return versions


def _versions_pipfile_lock(text: str, package: str) -> Optional[list[str]]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    versions: list[str] = []
    for section in ("default", "develop"):
        meta = (data.get(section) or {}).get(package)
        if isinstance(meta, dict) and isinstance(meta.get("version"), str):
            versions.append(meta["version"].lstrip("="))
    return versions


def _versions_gemfile_lock(text: str, package: str) -> Optional[list[str]]:
    pattern = re.compile(
        r"^\s{4}" + re.escape(package) + r"\s+\(([^)]+)\)\s*$", re.MULTILINE
    )
    return [m.group(1) for m in pattern.finditer(text)]


def _versions_cargo_lock(text: str, package: str) -> Optional[list[str]]:
    versions: list[str] = []
    pattern = re.compile(
        r'name\s*=\s*"' + re.escape(package) + r'"\s*\nversion\s*=\s*"([^"]+)"'
    )
    for match in pattern.finditer(text):
        versions.append(match.group(1))
    return versions


def _versions_composer_lock(text: str, package: str) -> Optional[list[str]]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    versions: list[str] = []
    for section in ("packages", "packages-dev"):
        for meta in data.get(section) or []:
            if isinstance(meta, dict) and meta.get("name") == package:
                version = meta.get("version")
                if version:
                    versions.append(str(version))
    return versions


_PARSERS = {
    "package-lock.json": _versions_package_lock,
    "yarn.lock": _versions_yarn_lock,
    "pipfile.lock": _versions_pipfile_lock,
    "gemfile.lock": _versions_gemfile_lock,
    "cargo.lock": _versions_cargo_lock,
    "composer.lock": _versions_composer_lock,
}


def _parser_for(manifest_path: str):
    name = manifest_path.rsplit("/", 1)[-1].lower()
    if name in _PARSERS:
        return _PARSERS[name]
    if name.startswith("requirements") and name.endswith(".txt"):
        return _versions_requirements
    return None


def verify_manifest(
    manifest_text: str,
    manifest_path: str,
    package: str,
    vulnerable_range: str,
) -> tuple[Optional[bool], str]:
    """Independent check that ``package``'s vulnerable range left the manifest.

    Returns (verdict, note):
      True   vulnerable range confirmed absent
      False  a version inside the vulnerable range is still present
      None   could not verify with certainty (fails closed)
    """
    parser = _parser_for(manifest_path)
    if parser is None:
        return None, f"manifest format not supported for verification: {manifest_path}"
    if not vulnerable_range:
        return None, "no vulnerable version range recorded on the alert"
    versions = parser(manifest_text, package)
    if versions is None:
        return None, f"could not parse {manifest_path} with certainty"
    if not versions:
        return True, f"package '{package}' is no longer present in {manifest_path}"

    any_uncertain = False
    for version in versions:
        in_range = version_in_range(version, vulnerable_range)
        if in_range is True:
            return False, (
                f"version {version} of '{package}' in {manifest_path} is still "
                f"inside the vulnerable range '{vulnerable_range}'"
            )
        if in_range is None:
            any_uncertain = True
    if any_uncertain:
        return None, (
            f"found '{package}' in {manifest_path} but could not compare "
            f"version(s) {versions} against range '{vulnerable_range}' with certainty"
        )
    return True, (
        f"all present versions of '{package}' in {manifest_path} "
        f"({', '.join(versions)}) are outside the vulnerable range "
        f"'{vulnerable_range}'"
    )
