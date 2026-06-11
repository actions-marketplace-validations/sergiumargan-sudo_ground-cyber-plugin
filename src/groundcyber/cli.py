"""groundcyber command-line interface.

Commands:
    groundcyber audit github   run a closure audit (read-only)
    groundcyber init           write a sample .groundcyber.yml
    groundcyber doctor         check token, connectivity, and API access
    groundcyber version        print version and build info

Exit codes:
    0  success
    1  --fail-on-gcs3 / --fail-on-gcs4 threshold hit
    2  configuration or usage error
    3  authentication or API error
"""

from __future__ import annotations

import argparse
import os
import platform
import sys

from . import __version__
from .audit import describe_scope, run_audit
from .config import (
    Config,
    ConfigError,
    load_config,
    write_sample_config,
)
from .github_client import GitHubClient, GitHubError
from .models import GCS
from .redact import redact_text
from .report import summary_block, write_reports

EXIT_OK = 0
EXIT_FAIL_ON = 1
EXIT_CONFIG = 2
EXIT_API = 3


def _say(message: str, *, verbose_only: bool = False, verbose: bool = False) -> None:
    if verbose_only and not verbose:
        return
    print(redact_text(message))


def _token() -> str:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="groundcyber",
        description=(
            "False-closure verification for GitHub Secret Scanning alerts. "
            "Closed is a status. Revoked is evidence."
        ),
    )
    sub = parser.add_subparsers(dest="command")

    audit = sub.add_parser("audit", help="run a closure audit")
    audit_sub = audit.add_subparsers(dest="target")
    gh = audit_sub.add_parser("github", help="audit GitHub Secret Scanning alerts")
    gh.add_argument("--org", default="", help="GitHub organization to audit")
    gh.add_argument(
        "--repo",
        action="append",
        default=[],
        metavar="OWNER/NAME",
        help="repository to audit (repeatable)",
    )
    gh.add_argument(
        "--include-repo",
        action="append",
        default=[],
        metavar="GLOB",
        help="only audit repos matching this glob (repeatable)",
    )
    gh.add_argument(
        "--exclude-repo",
        action="append",
        default=[],
        metavar="GLOB",
        help="skip repos matching this glob (repeatable)",
    )
    gh.add_argument("--config", default="", help="path to .groundcyber.yml")
    gh.add_argument(
        "--alerts",
        default="",
        help=(
            "comma-separated alert families: "
            "secret-scanning,dependabot,code-scanning (default: config)"
        ),
    )
    gh.add_argument(
        "--output",
        default="",
        help="comma-separated formats: markdown,json,html",
    )
    gh.add_argument("--out-dir", default="", help="report output directory")
    gh.add_argument(
        "--redact-repo-names",
        action="store_true",
        help="replace repository names with stable pseudonyms in reports",
    )
    gh.add_argument(
        "--fail-on-gcs3",
        action="store_true",
        help="exit 1 if any GCS-3 (false-closure risk) finding exists",
    )
    gh.add_argument(
        "--fail-on-gcs4",
        action="store_true",
        help="exit 1 if any GCS-4 (active risk) finding exists",
    )
    gh.add_argument(
        "--dry-run",
        action="store_true",
        help="print the audit plan without making any API calls",
    )
    gh.add_argument("--verbose", action="store_true")

    init = sub.add_parser("init", help="create a sample .groundcyber.yml")
    init.add_argument("--path", default=".groundcyber.yml")
    init.add_argument("--force", action="store_true", help="overwrite if present")

    sub.add_parser("version", help="print version and build info")

    doctor = sub.add_parser(
        "doctor", help="check token permissions and API connectivity"
    )
    doctor.add_argument("--org", default="", help="org to probe for alert access")
    doctor.add_argument("--repo", default="", help="owner/name to probe for alert access")
    doctor.add_argument("--config", default="", help="path to .groundcyber.yml")

    return parser


def _merge_cli_into_config(config: Config, args: argparse.Namespace) -> Config:
    if args.org:
        config.org = args.org
    if args.repo:
        config.repos = list(dict.fromkeys(config.repos + args.repo))
    if args.include_repo:
        config.include_repos = list(
            dict.fromkeys(config.include_repos + args.include_repo)
        )
    if args.exclude_repo:
        config.exclude_repos = list(
            dict.fromkeys(config.exclude_repos + args.exclude_repo)
        )
    if args.output:
        outputs = [o.strip() for o in args.output.split(",") if o.strip()]
        for out in outputs:
            if out not in ("markdown", "json", "html"):
                raise ConfigError(f"unknown output format {out!r}")
        config.outputs = outputs
    if args.out_dir:
        config.out_dir = args.out_dir
    if getattr(args, "alerts", ""):
        mapping = {
            "secret-scanning": "secret_scanning",
            "secret_scanning": "secret_scanning",
            "dependabot": "dependabot",
            "code-scanning": "code_scanning",
            "code_scanning": "code_scanning",
        }
        families = []
        for name in args.alerts.split(","):
            name = name.strip()
            if not name:
                continue
            if name not in mapping:
                raise ConfigError(f"unknown alert family {name!r}")
            if mapping[name] not in families:
                families.append(mapping[name])
        if families:
            config.families = families
    if args.redact_repo_names:
        config.redact_repo_names = True
    return config


def cmd_audit_github(args: argparse.Namespace) -> int:
    try:
        config = load_config(args.config or None)
        config = _merge_cli_into_config(config, args)
    except ConfigError as exc:
        _say(f"config error: {exc}")
        return EXIT_CONFIG

    if not config.org and not config.repos:
        _say(
            "error: no scope. Provide --org and/or --repo, or set scope in "
            ".groundcyber.yml"
        )
        return EXIT_CONFIG

    if args.dry_run:
        _say("Dry run — no API calls will be made.")
        _say(f"Scope: {describe_scope(config)}")
        _say(f"Outputs: {', '.join(config.outputs)} -> {config.out_dir}")
        _say(
            "Requests that would be issued (all GET):"
        )
        suffixes = {
            "secret_scanning": "secret-scanning/alerts",
            "dependabot": "dependabot/alerts",
            "code_scanning": "code-scanning/alerts",
        }
        for family in config.families:
            suffix = suffixes[family]
            if config.org:
                _say(f"  GET /orgs/{config.org}/{suffix}")
            for repo in config.repos:
                _say(f"  GET /repos/{repo}/{suffix}")
        _say(
            "  (plus read-only manifest/analyses GETs for evidence "
            "verification of fixed alerts)"
        )
        return EXIT_OK

    token = _token()
    if not token:
        _say(
            "error: no GitHub token. Set GITHUB_TOKEN or GH_TOKEN in the "
            "environment (the tool never prompts for secrets)."
        )
        return EXIT_API

    client = GitHubClient(token)
    _say(f"Scope: {describe_scope(config)}", verbose_only=True, verbose=args.verbose)

    try:
        result = run_audit(client, config)
    except GitHubError as exc:
        _say(f"API error: {exc}")
        _say("No report was produced. Absence of data is not evidence of safety.")
        return EXIT_API

    written = write_reports(result, config, config.out_dir)

    _say(summary_block(result))
    _say("")
    for path in written:
        _say(f"Wrote {path}")
    for error in result.errors:
        _say(f"warning: {error}")

    if args.fail_on_gcs4 and result.count(GCS.ACTIVE_RISK) > 0:
        _say("FAIL: GCS-4 (active risk) findings present and --fail-on-gcs4 set.")
        return EXIT_FAIL_ON
    if args.fail_on_gcs3 and result.count(GCS.FALSE_CLOSURE_RISK) > 0:
        _say("FAIL: GCS-3 (false-closure risk) findings present and --fail-on-gcs3 set.")
        return EXIT_FAIL_ON
    return EXIT_OK


def cmd_init(args: argparse.Namespace) -> int:
    try:
        path = write_sample_config(args.path, force=args.force)
    except ConfigError as exc:
        _say(f"error: {exc}")
        return EXIT_CONFIG
    _say(f"Wrote sample configuration to {path}")
    _say("Edit the scope section, then run: groundcyber audit github")
    return EXIT_OK


def cmd_version(_: argparse.Namespace) -> int:
    _say(f"groundcyber {__version__}")
    _say(f"python {platform.python_version()} on {platform.system().lower()}")
    _say("mode: read-only · local-first · deterministic scoring (no AI)")
    return EXIT_OK


def cmd_doctor(args: argparse.Namespace) -> int:
    ok = True

    token = _token()
    if token:
        _say("[ok] token found in GITHUB_TOKEN/GH_TOKEN")
    else:
        _say("[fail] no token: set GITHUB_TOKEN or GH_TOKEN")
        return EXIT_API

    client = GitHubClient(token)
    try:
        client.rate_limit()
        _say("[ok] GitHub API reachable")
    except GitHubError as exc:
        _say(f"[fail] GitHub API unreachable: {exc}")
        return EXIT_API

    scopes = ""
    try:
        user, headers = client.current_user()
        scopes = headers.get("x-oauth-scopes", "")
        login = user.get("login", "unknown") if isinstance(user, dict) else "unknown"
        _say(f"[ok] authenticated as {login}")
        if scopes:
            _say(f"[ok] token scopes: {scopes}")
        else:
            _say(
                "[info] no classic scopes reported (fine-grained PAT or app "
                "token); ensure it grants secret-scanning read access"
            )
    except GitHubError as exc:
        _say(f"[warn] could not identify token ({exc}); continuing")

    org = args.org
    repo = args.repo
    if args.config or (not org and not repo):
        try:
            config = load_config(args.config or None)
            org = org or config.org
            repo = repo or (config.repos[0] if config.repos else "")
        except ConfigError as exc:
            _say(f"[warn] config not loaded: {exc}")

    if org or repo:
        target = f"org '{org}'" if org else f"repo '{repo}'"
        labels = {
            "secret_scanning": "secret-scanning",
            "dependabot": "Dependabot",
            "code_scanning": "code-scanning",
        }
        for family, label in labels.items():
            reachable, detail = client.probe_alert_family(family, org=org, repo=repo)
            if reachable:
                _say(f"[ok] {label} alert API accessible for {target}")
            else:
                ok = False
                _say(f"[fail] {label} alert API not accessible for {target}: {detail}")
        if not ok:
            _say(
                "       Org-level access usually needs a PAT or GitHub App "
                "token with the relevant alert read permissions; the default "
                "Actions GITHUB_TOKEN is repository-scoped."
            )
    else:
        _say("[info] no org/repo provided; skipped alert API access probes")

    _say("[ok] doctor performed GET requests only and fetched no secret values")
    return EXIT_OK if ok else EXIT_API


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "audit":
        if getattr(args, "target", None) != "github":
            parser.parse_args(["audit", "--help"])
            return EXIT_CONFIG
        return cmd_audit_github(args)
    if args.command == "init":
        return cmd_init(args)
    if args.command == "version":
        return cmd_version(args)
    if args.command == "doctor":
        return cmd_doctor(args)
    parser.print_help()
    return EXIT_CONFIG


if __name__ == "__main__":
    sys.exit(main())
