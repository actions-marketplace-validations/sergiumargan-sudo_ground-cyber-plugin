# Ground Cyber

**False-closure verification for GitHub security alerts: secret scanning,
Dependabot, and code scanning.**

> Closed is a status. Revoked is evidence.

Ground Cyber does not ask whether an alert was marked resolved. It asks
whether the underlying risk is actually proven closed — and it requires a
different evidence chain for each alert family. It answers one question
across your repos or organization:

> **Which of my closed GitHub security alerts are not verifiably closed?**

Ground Cyber does not modify alerts. It verifies whether closure evidence
exists.

## What Ground Cyber does

- Fetches GitHub secret scanning, Dependabot, and code scanning alerts
  (read-only, GET requests only).
- Scores every alert with a deterministic rule table — no AI is involved in
  any closure decision.
- Builds an explicit **evidence chain** per alert and separates alerts that
  are **verifiably closed** from alerts that are merely **marked** closed.
- Distinguishes verified closure, platform-reported fixes, administrative
  dismissal, risk acceptance, scanner drift, and evidence gaps.
- Produces a local closure-risk report in Markdown, JSON, and HTML.
- Runs locally or as a GitHub Action. Nothing is uploaded anywhere.

## Why "closed" does not mean "safe"

GitHub lets anyone with write access resolve a secret alert with a label:
`revoked`, `used_in_tests`, `false_positive`, `wont_fix`, `pattern_deleted`.
None of those labels prove anything about the credential. A key resolved as
"revoked" can still be live. A key resolved as "used in tests" can still
authenticate against production.

GitHub also runs **validity checks** for many secret types and records
whether the credential is `active`, `inactive`, or `unknown`. That field is
evidence. The label is not.

The same failure pattern exists in every alert family: Dependabot alerts
dismissed as "no bandwidth" while the vulnerable package sits in the
lockfile; code scanning findings that "disappeared" because the scanner
stopped running, not because anyone fixed the code.

Ground Cyber's closure rule, which configuration cannot weaken — GCS-0
(verified closed) requires a defensible evidence chain per family:

| Family | GCS-0 requires | Platform state alone gets |
|---|---|---|
| Secret scanning | Provider-side validity = `inactive` | resolved + label → GCS-3 |
| Dependabot | State `fixed` **and** independent read-only manifest/lockfile inspection confirming the vulnerable range is gone | `fixed` alone → GCS-1 (moderate evidence) |
| Code scanning | State `fixed` **and** scan continuity: the same tool kept uploading analyses after the fix | `fixed` alone → GCS-2; scanner went quiet → GCS-3 (drift) |

- A resolution label or dismissal never produces GCS-0 in any family.
- **Unknown validity is not safe.** Dismissal is risk acceptance.
- If evidence is unavailable (API failure, unreadable manifest, missing
  analyses), the alert fails **closed** to a non-safe state — never to
  "fine".
- Every finding records `closure_claim`, `evidence_chain`,
  `evidence_strength`, `proof_grade`, `why_not_gcs0`, and
  `recommended_next_evidence`, so the report can say precisely things like:
  *"GitHub reports this alert as fixed, but Ground Cyber cannot verify
  closure because the dependency file was unavailable."*

## Relocation / migration detection

Closing a risk in one place does not always kill it — sometimes it just
moves. The same leaked credential appears in another repo; a dependency is
patched in one lockfile but still vulnerable via another path; a code-scanning
rule is dismissed in one location while the same rule fires elsewhere.

Ground Cyber detects this **from observed alerts only**: it flags a relocation
when a risk is closed at one location (the origin) while the *same causal
class* — same secret SHA-256 hash, same advisory, or same rule — is still live
at a different location in scope. A single alert never produces a relocation
finding; both ends must be seen, never assumed. Where a live location was first
detected after the origin was closed, the report records the real
post-closure interval from GitHub's own timestamps.

This is observed within audited scope only — it cannot see forks, logs, CI
systems, or repositories outside the scan. Absence of a relocation finding is
not proof the risk did not move; it is proof it did not move *where the audit
could see*.

## GCS scoring model

| State | Name | Meaning | How it is produced |
|---|---|---|---|
| GCS-0 | Verified closed | Risk proven closed | Family-specific evidence chain (see closure rule table above). The only path. |
| GCS-1 | Low residual risk | Mostly closed, minor gap | Platform-verified fix awaiting independent verification (Dependabot); inactive credential on a still-open alert; delayed re-check pending |
| GCS-2 | Provisional / unknown | Evidence incomplete or unavailable | Unknown validity; unestablishable scan continuity; any alert whose evidence could not be fetched; lower-severity open findings |
| GCS-3 | False-closure risk | Closed on paper, not in fact | Administrative labels without evidence; dismissals and auto-dismissals (risk acceptance); scanner drift |
| GCS-4 | Active risk | Exploitable now | Active credential (even if resolved); publicly leaked secret; open critical/high vulnerability; "fixed" contradicted by the manifest; duplicate active exposure |

`closure_confirmed: true` appears only on GCS-0 findings.

## Quick start: CLI

Requires Python 3.10+.

```bash
pip install git+https://github.com/sergiumargan-sudo/ground-cyber-plugin.git

export GITHUB_TOKEN=ghp_...        # or GH_TOKEN; never passed as a flag

groundcyber init                   # writes .groundcyber.yml
groundcyber doctor --repo owner/repo   # checks token + API access, fetches no secrets
groundcyber audit github --repo owner/repo --output markdown,json
```

Reports land in `./groundcyber-report/`. Audit an organization:

```bash
groundcyber audit github --org example-org \
  --exclude-repo "example-org/sandbox-*" \
  --output markdown,json,html
```

Useful flags: `--alerts secret-scanning,dependabot,code-scanning` (pick
alert families; default all), `--include-repo` / `--exclude-repo` (glob
patterns, repeatable), `--config`, `--out-dir`, `--redact-repo-names`,
`--fail-on-gcs3`, `--fail-on-gcs4`, `--dry-run` (prints the plan, makes zero
API calls), `--verbose`.

Exit codes: `0` success · `1` fail-on threshold hit · `2` config/usage
error · `3` auth/API error.

## Quick start: GitHub Action

```yaml
name: Ground Cyber Closure Audit

on:
  workflow_dispatch:
  schedule:
    - cron: "0 9 * * 1"

permissions:
  contents: read
  security-events: read

jobs:
  closure-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Ground Cyber
        uses: sergiumargan-sudo/ground-cyber-plugin@main
        with:
          output: "markdown,json"
          fail-on-gcs3: "false"
          fail-on-gcs4: "true"
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

The action runs the audit read-only, appends the Markdown report to the job
summary, uploads the report directory as an artifact, and (optionally) fails
the workflow when GCS-3 or GCS-4 findings exist. It never prints raw secret
values and never modifies alerts. See
[`examples/workflows/closure-audit.yml`](examples/workflows/closure-audit.yml).

## Permissions required

| Scenario | Token | Permissions |
|---|---|---|
| Single repository in Actions | fine-grained PAT stored as an Actions secret | the default `GITHUB_TOKEN` gets 403 from the secret-scanning and Dependabot alert APIs even with `security-events: read`; create a PAT with the alert read permissions and pass it as `GITHUB_TOKEN` to the action |
| Single repository, local CLI | fine-grained PAT | repository permissions **Secret scanning alerts: read**, **Dependabot alerts: read**, **Code scanning alerts: read**, **Contents: read** (manifest verification) |
| Organization-wide audit | fine-grained PAT or GitHub App token | the same alert read permissions, organization-wide |
| Classic PAT alternative | classic PAT | `repo` + `security_events` scopes |

**Limitation of the default `GITHUB_TOKEN`:** it cannot read secret-scanning
or Dependabot alerts at all (the API returns `403: Resource not accessible
by integration`), and it is scoped to the workflow's repository. For any
audit, create a fine-grained PAT with the alert read permissions (repo- or
org-wide as needed), store it as an Actions secret, and pass it as
`GITHUB_TOKEN` to the action. If the token cannot retrieve anything, the
audit exits with an error rather than reporting a clean result.

`groundcyber doctor` checks all of this before you run a real audit.

## Privacy and security model

- **Local-first.** The audit runs on your machine or your runner. There is
  no Ground Cyber server, no telemetry, no upload. The
  `upload_to_ground_dashboard` config key exists as a placeholder and must
  remain `false`.
- **Read-only.** The tool issues GitHub GET requests only; the HTTP client
  refuses any other method. It never modifies alerts, repositories, files,
  issues, or settings.
- **No raw secret storage.** If the API exposes a secret value, it is hashed
  with SHA-256 the moment the response is parsed and the raw value is
  discarded. Hashes are used only to detect the same credential appearing in
  multiple alerts.
- **No raw secret printing.** Every string written to the terminal or a
  report passes through a redaction filter that replaces secret-shaped
  content with `[REDACTED-SECRET:sha256:…]` markers.
- **No AI in closure decisions.** Scoring is a deterministic rule table;
  the same inputs always produce the same verdict.
- **Fail closed.** Unavailable, ambiguous, or stale evidence produces a
  provisional or risk state, never a safe one.
- Optional `--redact-repo-names` replaces repository names with stable
  pseudonyms for reports you need to share.

These guarantees are enforced by the test suite, and the corresponding
configuration keys (`read_only`, `store_raw_secrets`, `print_raw_secrets`,
`require_provider_inactive_for_gcs0`, …) are validated: trying to weaken
them is a configuration error.

## Example output

```text
Ground Cyber Closure Report

Total alerts scanned: 9 (secret scanning: 3, dependabot: 3, code scanning: 3)
Verified closed: 3
Low residual risk: 1
Provisional / unknown: 0
False-closure risk: 4
Active risk: 1

Highest-risk finding:
Alert #233 (GCS-4 Active risk): Provider validity is 'active': the
credential is usable right now and the alert is open.
```

Each finding records the alert number, family, repo (redacted if
configured), finding type, alert state, resolution/dismissal reason,
validity (secrets), severity, GCS score, `closure_confirmed`, the full
evidence chain with strength and proof grade, why GCS-0 was not granted,
closure blockers, the next evidence needed, a recommended action, and
timestamps. Full sample reports:
[Markdown](docs/sample-report/groundcyber-report.md) ·
[JSON](docs/sample-report/groundcyber-report.json) ·
[HTML](docs/sample-report/groundcyber-report.html)

## Configuration

`groundcyber init` writes a commented `.groundcyber.yml` covering scope
(org/repos/include/exclude), closure policy (`treat_unknown_validity_as`,
`stale_resolved_days`, `require_delayed_recheck`, extra non-closing labels),
privacy, and report outputs. CLI flags override the file.

## Limitations

- GitHub runs validity checks only for supported secret types from
  participating providers. Secret types without validity checks can never
  reach GCS-0 through this tool — they surface as provisional or
  false-closure risk. That is deliberate: unknown validity is not safe.
- Dependabot manifest verification supports common lockfiles with exact
  pinned versions (package-lock.json, yarn.lock, requirements.txt,
  Pipfile.lock, Gemfile.lock, Cargo.lock, composer.lock). Anything it
  cannot parse with certainty stays unverified — GCS-1 at best.
- Code-scanning continuity is verified at tool level. Rule-level drift (a
  disabled rule or excluded path inside a still-running scanner) is not
  detectable via the API and remains a documented residual risk.
- Validity reflects GitHub's most recent check and may lag a very recent
  revocation or reactivation.
- GCS-0 means the credential is dead **now**; it says nothing about whether
  the credential was abused during its exposure window.
- Resolving an alert does not rewrite git history; the secret string remains
  in history until rotated and scrubbed.
- Secrets GitHub never detected (unsupported types, missing custom
  patterns) are invisible to this audit.
- Org-level audits need org-level token permissions (see above).

## FAQ

**Does it ever change anything in my GitHub account?**
No. Only GET requests are made. There is no code path that writes.

**Does it send my data anywhere?**
No. Reports are written to a local directory. There is no upload endpoint.

**Why is my alert "false-closure risk" when we really did revoke the key?**
Because no provider-side evidence confirms it. If GitHub's validity check
shows `inactive`, the alert becomes GCS-0 on the next audit. If the secret
type has no validity check, Ground Cyber will not take the label's word for
it — verify revocation at the issuing provider and keep the audit finding as
a record of the evidence gap.

**Can I make unknown validity count as safe?**
No. `treat_unknown_validity_as` accepts `provisional` or `active_risk` only.

**Does it use AI?**
No. Scoring is a deterministic rule table; the same inputs always produce
the same verdict.

**What does exit code 1 mean in CI?**
You enabled `fail-on-gcs3` or `fail-on-gcs4` and the audit found findings at
that level. The report artifact tells you which.

## Design partners

Ground Cyber is self-serve: everything above works without contacting
anyone. If you want a hands-on closure audit of a larger estate, or want to
shape where the tool goes next, open an issue on this repository.
