# Engineering Audit and Upgrade Roadmap

**Audited baseline:** `main` at `6d8e7f53ddc1633fa5e4fd1ad84943afe8d60bcd` (April 29, 2026).

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
- Fail-closed CI: Markdown structure, Python compilation, tests, generated report drift.

### What these tests do **not** prove
They cannot measure real-world false-positive rate, bypass resistance, attacker coverage, tenant compatibility, or detection effectiveness under adversarial conditions. A high severity in this demo means **prioritize review**, not “compromised”.

## Next acceptance gates (not implemented in this milestone)

**Milestone 2 — Sensor-specific hardening:** Treat all remaining Windows/network/cloud historical examples as unverified until their table schema and ATT&CK claims are reviewed. Supply source-specific corpus, query contracts, operator semantics tests, and fixture-backed analyst outcomes. Do not call markdown rendering a live KQL test.

**Milestone 3 — Four more reproducible hunts:** Add lateral movement, persistence, network egress, and cloud administrative-change cases with a normalized schema, positive/negative controls, missing-telemetry tests, and content-addressed reports.

**Milestone 4 — Workflow handoff:** Add explicit triage → incident-response decision gates, deduplication, evidence integrity, and references to the separate Incident Response Playbooks project. Do not imply real-world containment or run remote response commands.

**Milestone 5 — Reviewer demo:** A 5-minute, zero-secret walkthrough: hypothesis → input → rule → finding → suppressed/benign example → rationale → reproducibility and limitations, with linked GitHub CI.

## Release gate
Merge only after all unit tests, report reproduction checks, Markdown validation and Python compilation pass on Windows and Linux. Preserve committed evidence and note all unresolved doc-only/live-SIEM blockers.
