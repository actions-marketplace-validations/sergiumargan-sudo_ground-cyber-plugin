# Ground Cyber Closure Report
> Closed is a status. Revoked is evidence. Unknown validity is not safe.
## Executive summary
```text
Ground Cyber Closure Report

Total alerts scanned: 9 (secret scanning: 3, dependabot: 3, code scanning: 3)
Verified closed: 3
Low residual risk: 1
Provisional / unknown: 0
False-closure risk: 4
Active risk: 1

Highest-risk finding:
Alert #233 (GCS-4 Active risk): Provider validity is 'active': the credential is usable right now and the alert is open.
```
## Scope
GitHub alerts (Secret scanning, Dependabot, Code scanning) — organization 'example-org'
Generated at: 2026-06-11T09:00:00Z · groundcyber v0.4.0
## Methodology
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

## Security and privacy model
- Local-first: the audit runs where you invoke it; nothing is uploaded.
- Read-only: only GitHub GET requests are issued. Alerts, repositories,
  issues, and settings are never modified.
- No raw secret storage: secret values are hashed with SHA-256 on receipt
  and discarded.
- No raw secret printing: all report text passes through a redaction
  filter that replaces secret-shaped strings with hashed markers.
- Human overrides and dismissals are treated as risk acceptance, not as
  verified closure.

## Closure summary
| State | Meaning | Count |
|---|---|---|
| GCS-4 | Active risk | 1 |
| GCS-3 | False-closure risk | 4 |
| GCS-2 | Provisional / unknown | 0 |
| GCS-1 | Low residual risk | 1 |
| GCS-0 | Verified closed | 3 |

## Findings
| Alert | Family | Repo | Finding | State | Resolution/Reason | Evidence | GCS | Closure confirmed |
|---|---|---|---|---|---|---|---|---|
| #233 | Secret scanning | example-org/infra-terraform | Stripe API Key | open | — | strong | GCS-4 | no |
| #15 | Code scanning | example-org/infra-terraform | tf/open-security-group (medium) | fixed | — | unavailable | GCS-3 | no |
| #18 | Code scanning | example-org/mobile-app | java/path-injection (high) | dismissed | false positive | unavailable | GCS-3 | no |
| #64 | Dependabot | example-org/mobile-app | axios (high) | dismissed | no_bandwidth | unavailable | GCS-3 | no |
| #1842 | Secret scanning | example-org/payments-api | AWS Access Key ID | resolved | used_in_tests | unavailable | GCS-3 | no |
| #70 | Dependabot | example-org/data-pipeline | urllib3 (medium) | fixed | — | moderate | GCS-1 | no |
| #12 | Code scanning | example-org/payments-api | js/sql-injection (high) | fixed | — | strong | GCS-0 | yes |
| #61 | Dependabot | example-org/payments-api | lodash (critical) | fixed | — | strong | GCS-0 | yes |
| #1901 | Secret scanning | example-org/payments-api | GitHub Personal Access Token | resolved | revoked | strong | GCS-0 | yes |

## Per-alert reasoning
### Alert #233 — example-org/infra-terraform (GCS-4: Active risk)
- **Family / finding:** Secret scanning / Stripe API Key
- **State / resolution:** open / — / validity: active
- **Created:** 2026-06-01T11:22:00Z
- **Closure confirmed:** false
- **Basis:** Provider validity is 'active': the credential is usable right now and the alert is open.
- **Closure claim:** Alert open; provider validity: 'active'
- **Evidence chain:**
  - Provider validity check: credential ACTIVE.
- **Evidence strength / proof grade:** strong / provider_validity
- **Why not GCS-0:** The credential is active; closure is contradicted.
- **Next evidence needed:** Provider validity flipping to 'inactive' after revocation.
- **Closure blockers:**
  - Provider-side validity check reports the credential is ACTIVE.
- **Recommended next action:** Revoke or rotate the credential at the issuing provider immediately, then confirm validity flips to 'inactive'.

### Alert #15 — example-org/infra-terraform (GCS-3: False-closure risk)
- **Family / finding:** Code scanning / tf/open-security-group (medium)
- **State / resolution:** fixed / —
- **Closure confirmed:** false
- **Basis:** The alert is marked fixed, but the scanner demonstrably stopped analyzing the repository afterwards. A finding that vanished because scanning stopped is scanner drift, not closure.
- **Closure claim:** Code scanning state: 'fixed' for tf/open-security-group (tfsec)
- **Evidence chain:**
  - tfsec re-scanned and no longer reports tf/open-security-group at this location (state 'fixed' at 2026-04-02T00:00:00Z).
  - Scan continuity FAILED: no tfsec analysis since 2026-03-28T00:00:00Z, which predates the fix; the scanner may have stopped running
- **Evidence strength / proof grade:** unavailable / platform_state
- **Why not GCS-0:** The disappearance coincides with scanning stopping; closure cannot be distinguished from drift.
- **Next evidence needed:** A fresh analysis by the same tool showing the finding absent.
- **Closure blockers:**
  - Scanner drift: no tfsec analysis since 2026-03-28T00:00:00Z, which predates the fix; the scanner may have stopped running
- **Recommended next action:** Restore tfsec analysis uploads for this repository, then re-run the audit to confirm the finding stays gone.

### Alert #18 — example-org/mobile-app (GCS-3: False-closure risk)
- **Family / finding:** Code scanning / java/path-injection (high)
- **State / resolution:** dismissed / false positive
- **Created:** 2026-03-15T00:00:00Z
- **Closure confirmed:** false
- **Basis:** Alert was dismissed as 'false positive' with no dismissal comment. Treat as risk acceptance, not verified closure.
- **Closure claim:** Code scanning state: 'dismissed' for java/path-injection (CodeQL)
- **Evidence chain:**
  - Dismissed with reason 'false positive': an administrative statement.
  - No subsequent scan evidence shows the finding absent.
  - No dismissal comment was recorded.
- **Evidence strength / proof grade:** unavailable / administrative
- **Why not GCS-0:** Dismissal is risk acceptance, not closure evidence.
- **Next evidence needed:** A subsequent scan by the same tool showing the finding fixed, with scan continuity.
- **Closure blockers:**
  - Dismissal reason 'false positive' is an assertion, not scan evidence.
- **Recommended next action:** Either fix the finding so a subsequent scan closes it, or record the dismissal as accepted risk with justification, owner, and review date.

### Alert #64 — example-org/mobile-app (GCS-3: False-closure risk)
- **Family / finding:** Dependabot / axios (high)
- **State / resolution:** dismissed / no_bandwidth
- **Created:** 2026-02-10T00:00:00Z
- **Resolved:** 2026-02-12T00:00:00Z
- **Closure confirmed:** false
- **Basis:** Alert was dismissed ('no_bandwidth') without fix evidence. Dismissal is risk acceptance, not verified closure.
- **Closure claim:** Dependabot state: 'dismissed' for axios (< 1.6.0)
- **Evidence chain:**
  - Dismissed with reason 'no_bandwidth': an administrative statement, not remediation evidence.
  - Vulnerable range '< 1.6.0' for axios was never shown to be removed.
- **Evidence strength / proof grade:** unavailable / administrative
- **Why not GCS-0:** Dismissal is risk acceptance, not closure evidence.
- **Next evidence needed:** State 'fixed' plus manifest confirmation that the vulnerable range is gone.
- **Closure blockers:**
  - Dismissal reason 'no_bandwidth' is an assertion, not evidence.
  - No dependency-graph or manifest evidence that the vulnerable range was removed.
- **Recommended next action:** Either fix the dependency (upgrade to 1.6.0) or record the dismissal explicitly as accepted risk with an owner and review date.

### Alert #1842 — example-org/payments-api (GCS-3: False-closure risk)
- **Family / finding:** Secret scanning / AWS Access Key ID
- **State / resolution:** resolved / used_in_tests / validity: unknown
- **Created:** 2026-03-02T09:14:00Z
- **Resolved:** 2026-03-02T10:01:00Z
- **Closure confirmed:** false
- **Basis:** Alert was closed as 'used_in_tests', but no provider-side inactive-validity evidence exists. A label is a status, not proof the credential is dead.
- **Closure claim:** Alert resolved as 'used_in_tests'; provider validity: 'unknown'
- **Evidence chain:**
  - Resolution label 'used_in_tests': administrative statement only.
  - Provider validity: 'unknown' — no closure evidence.
- **Evidence strength / proof grade:** unavailable / administrative
- **Why not GCS-0:** No provider-side inactive-validity evidence; a resolution label is not proof.
- **Next evidence needed:** Provider validity reading of 'inactive', or provider-side revocation confirmation after rotation.
- **Closure blockers:**
  - Resolution label 'used_in_tests' is an administrative statement, not closure evidence.
  - No provider-side inactive-validity evidence was found (validity: 'unknown').
  - Resolution is older than 30 days and the evidence gap was never closed.
- **Recommended next action:** Verify at the issuing provider that the credential is revoked; if it cannot be proven dead, rotate it and re-check validity.

### Alert #70 — example-org/data-pipeline (GCS-1: Low residual risk)
- **Family / finding:** Dependabot / urllib3 (medium)
- **State / resolution:** fixed / —
- **Closure confirmed:** false
- **Basis:** GitHub reports this alert as fixed (dependency-graph evidence), but Ground Cyber could not independently verify the manifest: manifest requirements.txt could not be read (missing, moved, too large, or insufficient permissions).
- **Closure claim:** Dependabot state: 'fixed' for urllib3 (< 2.0.7)
- **Evidence chain:**
  - GitHub dependency graph no longer resolves the vulnerable version (state 'fixed' at 2026-05-30T00:00:00Z).
  - Independent verification: unavailable — manifest requirements.txt could not be read (missing, moved, too large, or insufficient permissions).
- **Evidence strength / proof grade:** moderate / platform_state
- **Why not GCS-0:** Platform-reported fixed; independent manifest verification unavailable. Platform status alone is not verified closure.
- **Next evidence needed:** Read-only manifest inspection confirming the vulnerable range is absent.
- **Closure blockers:**
  - Independent verification unavailable: manifest requirements.txt could not be read (missing, moved, too large, or insufficient permissions).
- **Recommended next action:** Confirm the lockfile/manifest no longer resolves the vulnerable range '< 2.0.7', or re-run where the manifest is readable.

### Alert #12 — example-org/payments-api (GCS-0: Verified closed)
- **Family / finding:** Code scanning / js/sql-injection (high)
- **State / resolution:** fixed / —
- **Created:** 2026-04-01T00:00:00Z
- **Closure confirmed:** true
- **Basis:** The finding was fixed according to a subsequent scan by the same tool, and scan continuity is confirmed: the tool kept analyzing the repository after the fix.
- **Closure claim:** Code scanning state: 'fixed' for js/sql-injection (CodeQL)
- **Evidence chain:**
  - CodeQL re-scanned and no longer reports js/sql-injection at this location (state 'fixed' at 2026-05-15T00:00:00Z).
  - Scan continuity: CodeQL uploaded an analysis at 2026-06-10T03:00:00Z, after the alert was fixed
- **Evidence strength / proof grade:** strong / scanner_verified
- **Next evidence needed:** None required.
- **Recommended next action:** None. Closure is scanner-verified.

### Alert #61 — example-org/payments-api (GCS-0: Verified closed)
- **Family / finding:** Dependabot / lodash (critical)
- **State / resolution:** fixed / —
- **Created:** 2026-05-01T00:00:00Z
- **Closure confirmed:** true
- **Basis:** Platform reports the alert fixed AND independent read-only inspection of the manifest confirms the vulnerable range is gone.
- **Closure claim:** Dependabot state: 'fixed' for lodash (< 4.17.21)
- **Evidence chain:**
  - GitHub dependency graph no longer resolves the vulnerable version (state 'fixed' at 2026-05-20T08:00:00Z).
  - Independent verification: all present versions of 'lodash' in package-lock.json (4.17.21) are outside the vulnerable range '< 4.17.21'
- **Evidence strength / proof grade:** strong / independent_verification
- **Next evidence needed:** None required.
- **Recommended next action:** None. Closure evidence is strong.

### Alert #1901 — example-org/payments-api (GCS-0: Verified closed)
- **Family / finding:** Secret scanning / GitHub Personal Access Token
- **State / resolution:** resolved / revoked / validity: inactive
- **Created:** 2026-04-11T16:40:00Z
- **Resolved:** 2026-04-11T17:05:00Z
- **Closure confirmed:** true
- **Basis:** Provider-side validity check confirms the credential is inactive. This is closure evidence, independent of the resolution label ('revoked').
- **Closure claim:** Alert resolved as 'revoked'; provider validity: 'inactive'
- **Evidence chain:**
  - Alert resolved as 'revoked' (administrative statement).
  - Provider validity check: credential INACTIVE (closure evidence).
- **Evidence strength / proof grade:** strong / provider_validity
- **Next evidence needed:** None required.
- **Recommended next action:** None. Closure is verified by provider evidence.

## Recommended remediation order
1. GCS-4 first: revoke/rotate active credentials at the issuing provider.
2. GCS-3 next: produce provider-side proof of revocation for administratively closed alerts, or rotate.
3. GCS-2: obtain validity evidence; treat as live until proven otherwise.
4. GCS-1: finish the closure workflow (resolve open alerts whose credentials are already inactive, or re-check after the delay window).

## Limitations
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

## Evidence appendix
Evidence per alert is limited to: GitHub alert metadata (state, resolution, timestamps), the provider validity field, and SHA-256 fingerprints of secret values where the API exposed them. Raw secret values are never stored or reproduced.
