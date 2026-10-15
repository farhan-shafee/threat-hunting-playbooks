# Engineering Audit and Upgrade Roadmap

**Audited baseline:** `main` at `6d8e7f53ddc1633fa5e4fd1ad84943afe8d60bcd` (April 29, 2026).

## Current release context and Phase 2 implementation

PR #2 was merged as commit `26d35f5330f9b0587da39d4215e9cb3f8ea85b48` after 94 tests and Windows/Linux CI passed. The previously noted administrative **main-branch protection gap is now resolved**: four named matrix checks are required, strict up-to-date branch checking is enabled, discussion resolution is required, administrators are subject to the rules, and force pushes/deletions are disabled. Statements further below about missing protection are historical audit findings, **not current repository status**.

Phase 2 adds four bounded, synthetic, deterministic evidence hunts on a new feature branch: strictly ordered connection→logon→execution correlation; unapproved persistence changes and deletion/recreation; completed cloud-admin/access-key changes; and observed outbound bytes with conservative cumulative/delta accounting. Input-only SHA-256, structured candidate evidence, duplicate-ID suppression and explicit unknown-counter warnings are recorded. See [PHASE2_HUNTS.md](PHASE2_HUNTS.md) for the schemas, confirmed behavior, negative controls, and limitations.

**Independent PR #3 review and correction:** Codex identified two evidence-semantics issues: tied persistence changes could consume deletions according to CSV order, and cumulative byte increments were attributed wholly to the later timestamp even if measured across more than an hour. The focused correction groups persistence actions by timestamp, enforces strictly later updates, and accounts for the *entire* cumulative observation interval in each rolling hour using an earliest-start-time heap. Both affected rule versions advance to `1.0.1`. Independent adversarial regression tests cover order permutations, inclusive microsecond boundaries, interleaved sessions and overlong gaps. Preserve the generated reports and require GitHub CI plus review-thread resolution before merge.

**Not yet established:** KQL compilation or equivalence, real sensor coverage, measured production detection efficacy, true unauthorized-change validation, forensic chain of custody, or actual incident-response operations. The expanded offline scope is not evidence of those capabilities.

## Baseline findings (before this feature branch)

| Priority | Finding | Why it mattered | Disposition in this branch |
|---|---|---|---|
| P0 | Six core hunt Markdown files had a headings/fence validator but no actual hunt evaluation | CI green was not proof of detection behavior | Added an offline engine, synthetic test vectors, reproducible reports, regression suite |
| P0 | Multiple historical examples used bare `kql`/`sql` text outside code fences | Readers could mistake prose for portable runnable code | Formatted historical files and explicitly labeled them unverified |
| P0 | Sentinel/Defender table schemas were mixed (`DeviceNetworkEvents.SentBytes`, unsupported JA3/HTTP fields, AWS `CloudTrail` naming) | Non-working or misleading paste-and-run examples | Replaced main affected snippets; added vendor compatibility contract |
| P0 | Identity impossible-travel example used `prev()` without ordered, serialized user partition | Could produce nonsense correlations | Reworked as **rapid country-change candidate**, explicitly not impossible travel |
| P0 | Token replay and mailbox access were inferred from unrelated fields/events | Unsupported attribution claims | Reframed as investigative pivots, not proof of token theft or mailbox reading |
| P1 | Legacy ATT&CK IDs included T1075/T1035 | Stale technique references | Corrected in SMB playbook |
| P1 | Three old sample narrative reports have counts inconsistent with included CSVs | Weak evidence lineage | Preserved as historical illustrative examples; created separate reports tied to committed synthetic fixtures |
| P1 | Original Python validator depended on working directory | Running it from elsewhere falsely failed | Paths now derive from the script's repository root |
| P1 | CI ran on one environment and checked headings only | Cross-platform behavior and drift not verified | Added Windows+Linux unit tests, compile check and deterministic reports check |

## Implemented: Milestone 1 — Offline evidence foundation

- `huntlab/engine.py` — standard-library CSV parsing, bounded input size, UTC normalization, stable results, normalized source hash.
- Authentication: source IP spray plus per-user failure→success rules, with distinct users and bounded windows.
- PowerShell: encoded/inline execution markers, risky Office/script parent context, high/medium prioritization.
- Synthetic reference fixtures, generated reports and regression tests with false-positive and malformed-input controls.
- CI checks Markdown structure, Python compilation, tests and generated report drift. GitHub merge enforcement is a separate owner configuration.

### What these tests do **not** prove
They cannot measure real-world false-positive rate, bypass resistance, attacker coverage, tenant compatibility, or detection effectiveness under adversarial conditions. A high severity in this demo means **prioritize review**, not “compromised”.

## Next acceptance gates (not implemented in this milestone)

**Milestone 2 — Sensor-specific hardening:** Treat all remaining Windows/network/cloud historical examples as unverified until their table schema and ATT&CK claims are reviewed. Supply source-specific corpus, query contracts, operator semantics tests, and fixture-backed analyst outcomes. Do not call markdown rendering a live KQL test.

**Milestone 3 — Four more reproducible hunts:** Add lateral movement, persistence, network egress, and cloud administrative-change cases with a normalized schema, positive/negative controls, missing-telemetry tests, and content-addressed reports.

**Milestone 4 — Workflow handoff:** Add explicit triage → incident-response decision gates, deduplication, evidence integrity, and references to the separate Incident Response Playbooks project. Do not imply real-world containment or run remote response commands.

**Milestone 5 — Reviewer demo:** A 5-minute, zero-secret walkthrough: hypothesis → input → rule → finding → suppressed/benign example → rationale → reproducibility and limitations, with linked GitHub CI.

## Phase 3 — Canonical KQL schema review

Seven read-only query candidates were authored for six core hunts: two on Sentinel `SigninLogs`, two on Defender `DeviceProcessEvents`, one on Defender `DeviceRegistryEvents`, one on Sentinel `AuditLogs` and one on Sentinel `CommonSecurityLog`. Vendor-field subsets are explicitly listed in `queries/schema-reviewed/manifest.json`. Local Microsoft `Kusto.Language` 12.4.1 syntax and curated-schema semantic analysis reports zero diagnostics for all seven, and CI now enforces this alongside exact Markdown snippet synchronization. This is a **static source review only**, not a Microsoft tenant execution. Query performance, source/connector presence, actual field population, rule/Python behavioral parity, real-world false positives, and operational authorization remain unverified; see `docs/KQL_STATIC_VALIDATION.md` and `docs/LIVE_KQL_VALIDATION_GATE.md`. Legacy non-core KQL examples are excluded from the seven-query acceptance set.

## Release gate
Merge only after all unit tests, report reproduction checks, Markdown validation and Python compilation pass on Windows and Linux. Preserve committed evidence and note all unresolved doc-only/live-SIEM blockers.

## Focused PR #2 correction pass

The independent review examined feature commit `4af7f9a2cd2a4d9cabcea790ed922966cc49e595`. This correction keeps the same two supported hunts and unchanged synthetic CSV inputs.

- Failure-before-success claims now require strictly earlier failure timestamps. Timestamp groups remove CSV-order inference; the 15-minute lookback remains inclusive. Tied failures are discarded at success, and unrelated outcomes reset conservatively.
- Fractional UTC timestamps retain microsecond precision, with chronological finding ordering and whole-second fixture compatibility.
- CSV header errors and UTC overflows become controlled input errors. All declared columns have enforced row width; optional blank values remain allowed. Reads and record counts have explicit inclusive limits.
- JSON output rejects input aliases and uses same-directory atomic replacement. Failure tests protect existing input/output bytes and verify temporary-file cleanup. Markdown treats telemetry as literal text.
- Schema version, rule versions and effective parameters accompany complete candidate intervals, signals, evidence references and review disposition in JSON and Markdown.
- Independently hand-authored expected JSON protects the full evidence contract. Generated Markdown is reproduced from unchanged CSVs; its expanded provenance and rationale explain the legitimate report changes.
- Validation checks 31 Markdown documents, not 32. This is a structure check, not live KQL validation. No new dependencies, credentials, hunts or containment capabilities were added.

Known KQL issues remain outside this correction: undeclared DNS aliases, unsupported default software-change table assumptions, incomplete role-operation selectors, fixed-bin authentication aggregation and case-sensitive parent lists. All remain unverified reference material; offline tests do not promote them to executable detections.

## Release safeguards (owner action)

Read-only GitHub inspection found `main` unprotected, no required status checks and no effective ruleset. No repository-wide settings were changed. Passing workflow runs alone do not enforce the release gate.

The smallest proposed branch protection for `main` requires these exact GitHub Actions contexts:

- `Offline evidence (Windows/Linux, Python matrix) (ubuntu-latest, 3.11)`
- `Offline evidence (Windows/Linux, Python matrix) (ubuntu-latest, 3.13)`
- `Offline evidence (Windows/Linux, Python matrix) (windows-latest, 3.11)`
- `Offline evidence (Windows/Linux, Python matrix) (windows-latest, 3.13)`

Require up-to-date branches (`strict: true`), conversation resolution (`required_conversation_resolution: true`) and apply checks to administrators (`enforce_admins: true`). Keep force pushes and deletions disabled. An equivalent active ruleset can require pull requests, these checks and resolved review threads. Additional mandatory human approval is a separate owner policy, not necessary to the minimum CI gate.

Owner authorization and administrative access are needed to apply and verify this configuration. Until enforced, the release safeguard remains an owner-action blocker even when the correction's technical checks pass. This PR must not be merged automatically.

Action runtime deprecation warnings and mutable action tags remain maintenance items; private vulnerability reporting is disabled and needs an owner-selected reporting route. None of these observations changes the synthetic/offline scope.
