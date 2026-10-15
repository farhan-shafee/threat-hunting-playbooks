# Threat Hunting Playbooks — Offline Evidence Lab

> An **educational security engineering portfolio project**, not a production SOC system. All included telemetry is synthetic. No customer environments, live security alerts, or actual compromises are claimed.

This repo shows how to move from a behavior hypothesis to an **auditable finding**: input telemetry, deterministic evaluation, negative controls, decision rationale, evidence record references, and reproducible reports.

## What is actually implemented?

| Track | State | Evidence |
|---|---|---|
| Entra-style identity hunting (spray + failures followed by success) | **Offline implemented and tested** | [auth report](samples/reports/reproduced/auth-v1.md) |
| Defender-style suspicious PowerShell activity | **Offline implemented and tested** | [PowerShell report](samples/reports/reproduced/powershell-v1.md) |
| Lateral movement | **Documented hunt; not exercised with an offline fixture** | [playbook](hunts/lateral-movement.md) |
| Data exfiltration | **Documented; schema-reviewed Sentinel proxy example only** | [playbook](hunts/data-exfiltration-indicators.md) |
| Cloud compromise | **Documented; tenant and connector verification pending** | [playbook](hunts/cloud-account-compromise.md) |
| Persistence | **Documented; offline evaluation pending** | [playbook](hunts/persistence-mechanisms.md) |
| Additional Windows/network/cloud examples | **Illustrative only; not live-tested** | [query limitations](docs/query-contract.md) |

**Important:** The Python evaluator is **not** a KQL parser or a Microsoft Defender/Sentinel connector. Offline findings do not prove that the Markdown KQL returns identical records, compiles against a live tenant, or has measured sensitivity/precision.

## Run it on Windows (Codex Desktop / PowerShell)

From the cloned repository root:

```powershell
python scripts/validate_playbooks.py
python -m unittest discover -s tests -v
python scripts/run_hunt.py --hunt auth --input samples/logs/auth-lab-v1.csv
python scripts/run_hunt.py --hunt powershell --input samples/logs/powershell-lab-v1.csv
python scripts/render_reports.py --check
```

On macOS/Linux, run the same Python commands; `make validate` is an optional wrapper.

No Docker, SIEM tenant, paid API, log collection agent, cloud subscription, or third-party Python packages are required for these **offline** examples.

## What the evaluator does

**Authentication:** From a synthetic `SigninLogs`-style CSV, distinguish invalid-password error `50126` from unrelated auth errors. Find (a) six or more failures spanning at least three identities from one IP in a 15-minute window and (b) five or more failures followed by success for one identity/IP within 15 minutes. Time order is enforced; success resets the sequence.

**PowerShell:** From `DeviceProcessEvents`-style CSV, examine executable, command-line indicators, and process parent; prioritize encoded/obfuscated execution when launched from an Office/script-host parent. Approved automation could still generate a review candidate.

The evaluator refuses missing/duplicate columns, malformed rows, naive timestamps, oversized inputs, and unknown hunts. Reports omit raw command lines, record normalized input SHA-256, and use stable ordering. It does not decode or execute payloads.

## Evidence and integrity

- [Synthetic identity fixture](samples/logs/auth-lab-v1.csv) → [generated identity review](samples/reports/reproduced/auth-v1.md)
- [Synthetic PowerShell fixture](samples/logs/powershell-lab-v1.csv) → [generated PowerShell review](samples/reports/reproduced/powershell-v1.md)
- [Regression tests](tests/test_engine.py) test positive cases, benign noise, time boundaries, sorting, and schema failures.
- [GitHub CI](.github/workflows/ci.yml) checks Python, Markdown, tests, and committed report reproducibility on Windows and Linux.
- [Audit and engineering roadmap](docs/engineering-audit.md) records what is real, what is unverified, and next acceptance gates.
- [Telemetry/query contract](docs/query-contract.md) explains vendor-specific schema assumptions.

Older sample summaries in `samples/reports/` were **illustrative narratives** prepared before this reproducible evaluator; do not equate their counts with either new fixture. The `reproduced/` reports alone have automated input lineage.

## Hunt methodology

1. Make a falsifiable hypothesis, identify the ATT&CK behavior, and define *how it could be wrong*.
2. Prove necessary telemetry exists, check UTC/source timestamps, retention and gaps.
3. Run a scoped query or offline evaluator; retain input hashes and time windows.
4. Triage with independent evidence (process tree, authorization, identity, destination).
5. Test expected suspicious and benign cases, plus boundary/negative controls.
6. Escalate only after evidence meets a documented criterion. No automated containment here.
7. Tune with a measured false-positive review and reproduce results.

See [methodology](docs/threat-hunting-methodology.md).

## Repository map

```text
huntlab/                  Python offline evaluator (2 implemented hunts)
tests/                    Regression/negative test cases
samples/logs/*-lab-v1.csv Synthetic example inputs for implemented hunts
samples/reports/reproduced/ Generated evidence, checked for reproducibility
hunts/                    6 primary Markdown hunt playbooks
cloud/ network/ windows/  Additional illustrative scenarios
queries/                  KQL reference collection (not live-validated)
docs/                     Methodology, audit, query limitations
scripts/                  CLI, reports, validation, formatter
.github/workflows/        CI on push and pull requests
```

## Boundaries

- Only run this repository on synthetic or explicitly authorized sanitized telemetry; it is not configured to ingest real tenant data.
- Do not introduce customer identifiers, credentials, access tokens, proprietary incident logs, or high-risk payloads into public fixtures or reports.
- The examples provide **review candidates**, never a determination of compromise.
- No alert-quality, enterprise coverage, time-to-detect, or production deployment claims are made.
- Any KQL deployment needs separately documented connector, licensing, table schema, testing, threshold tuning, and approval.

Contribution and vulnerability reporting guidance: [CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md).
