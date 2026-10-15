# Threat Hunting Playbooks — Six Offline Evidence Hunts

**Security engineering portfolio lab** that turns six hypothesis-driven hunts into repeatable synthetic telemetry evaluations, independent expected outcomes, and auditable reports.

> **Scope is synthetic and non-destructive.** The six Python detectors run only on local synthetic CSVs and are **not** SIEM/EDR integrations or evidence of real-world detection efficacy. The separate Azure Data Explorer KQL validation described below used temporary synthetic data, **not** Microsoft Sentinel/Defender tenant telemetry. No customer investigations, real incident claims, credential collection, malware execution, or containment operations are involved.

## Capability and evidence matrix

| Hunt | Executable offline scenario | Evidence |
|---|---|---|
| **Authentication** | Failure→success correlation and multi-identity password spraying with strict temporal ordering | [Reproduced auth report](samples/reports/reproduced/auth-v1.md) |
| **PowerShell** | Encoded/obfuscated-command text signals and parent-process context | [Reproduced PowerShell report](samples/reports/reproduced/powershell-v1.md) |
| **Lateral movement** | Successful TCP/445 connection → target network logon → service/WMI execution in strictly ordered 10-minute chain | [Reproduced lateral report](samples/reports/reproduced/lateral-v1.md) |
| **Persistence** | Unapproved registry/task/service artifact changes and deletion/recreation in a 60-minute window | [Reproduced persistence report](samples/reports/reproduced/persistence-v1.md) |
| **Cloud compromise** | Successful unapproved privileged changes and access-key creation, excluding failed and pending operations | [Reproduced cloud report](samples/reports/reproduced/cloud-v1.md) |
| **Network egress** | Deduplicated high-volume outbound transfers, controlled byte-counter semantics, 60-minute rolling window | [Reproduced egress report](samples/reports/reproduced/egress-v1.md) |

**Evidence status:** All six Python algorithms operate on synthetic CSV fixtures with regression tests. Separately, **seven canonical KQL candidates passed Microsoft's Kusto.Language syntax and static semantic checks against curated vendor schemas**. All seven were also **executed successfully against temporary `datatable` fixtures in an Azure Data Explorer free cluster on October 15, 2026**, with observed results captured in a clearly labeled, human-transcribed [synthetic-execution receipt](evidence/adx-free-2026-10-15/receipt.json). A separate [replay harness](docs/ADX_SYNTHETIC_EXECUTION.md) generates fresh-time queries and PASS/FAIL checks. **All seven corrected assertions were executed in Azure Data Explorer and returned PASS; a deliberately incorrect event identity returned FAIL**. The exact generated query hashes and manually observed results are recorded in the [assertion runtime receipt](evidence/adx-free-2026-10-15/assertion-runtime-receipt.json). **No Sentinel/Defender tenant-side query execution or real-world detection effectiveness has been established**, and these KQL pivots are not equivalent to the offline Python detectors. See [KQL static validation](docs/KQL_STATIC_VALIDATION.md) and the [live tenant gate](docs/LIVE_KQL_VALIDATION_GATE.md).

## Reproduce all six offline cases

The offline Python hunts require only **Python 3.11+** and a local repository clone. These commands work in PowerShell, CMD, Linux shells, and macOS shells. The separate KQL static check requires PowerShell 7 and a hash-pinned Microsoft parser NuGet package:

```bash
python -B scripts/demo_hunts.py
python -B -m unittest discover -s tests -v
python -B scripts/validate_playbooks.py
python -B scripts/render_reports.py --check
python -B scripts/sync_kql_examples.py --check
python -B scripts/build_adx_synthetic_queries.py --check
```

Run the additional Microsoft vendor-parser check with `pwsh -NoProfile -File scripts/validate_kql_schemas.ps1`. This uses only local KQL source files and curated official schema definitions; it does not authenticate to a tenant.

For one hunt and its complete JSON provenance:

```bash
python -B scripts/run_hunt.py --hunt lateral --input samples/logs/lateral-lab-v1.csv
python -B scripts/run_hunt.py --hunt persistence --input samples/logs/persistence-lab-v1.csv
python -B scripts/run_hunt.py --hunt cloud --input samples/logs/cloud-lab-v1.csv
python -B scripts/run_hunt.py --hunt egress --input samples/logs/egress-lab-v1.csv
```

Also supported: `--hunt auth` and `--hunt powershell` with their corresponding `*-lab-v1.csv` sources. Add `--output PATH.json` to the runner to write JSON atomically without overwriting the input.

To regenerate committed Markdown for all six:

```bash
python -B scripts/render_reports.py
python -B scripts/render_reports.py --check
```

CI runs tests on **Windows and Linux with Python 3.11 and 3.13**, compiles code, validates Markdown structure, checks canonical KQL synchronization, verifies all seven exact Azure Data Explorer execution-capture hashes, reproduces seven fresh-time synthetic queries and seven assertion queries, statically analyzes all 21 KQL files with Microsoft Kusto.Language 12.4.1, and checks the six offline evidence reports. The parser package is fetched with a pinned SHA-256 and never runs real tenant queries. Branch protection requires the existing four matrix checks and resolved review threads before merging.

## What the evaluator actually records

- Synthetic input content SHA-256 after documented UTF-8/BOM/newline normalization
- UTC event timestamps (including microseconds), candidate start/end, CSV record ordinals
- Rule identifiers and versions, effective thresholds/parameters, evaluated signals
- Consistent `review required; not confirmed compromise` disposition
- For the four Phase 2 hunts: unique/duplicate event counts and explicit data-quality warnings
- Hand-authored expected outcome manifest for the new four hunts, alongside earlier independently authored JSON expectations for authentication/PowerShell

**Never treat a high-priority review candidate as a confirmed attacker action.** `Approved` is a synthetic scenario annotation rather than proven change-control evidence; host/pair joins may misassociate unrelated activity. Missing data, malformed schemas and uncertain counter semantics require conservative handling.

## Repository map

| Location | Purpose |
|---|---|
| [`huntlab/engine.py`](huntlab/engine.py) | Original auth/PowerShell implementations, strict CSV and deterministic output contract |
| [`huntlab/extended.py`](huntlab/extended.py) | Four additional synthetic rule families with explicit sensor/field constraints |
| [`samples/logs/`](samples/logs/) | Synthetic scenario logs and adversarial control fixtures |
| [`samples/reports/reproduced/`](samples/reports/reproduced/) | Six deterministic evidence reports |
| [`tests/`](tests/) | Regression, negative, boundary, provenance, and malformed-input tests |
| [`tests/expected/`](tests/expected/) | Independently authored expected outcomes, not generated by the runtime |
| [`hunts/`](hunts/) | Six hypothesis/analyst playbooks containing source-reviewed but tenant-unexecuted KQL candidates |
| [`queries/schema-reviewed/`](queries/schema-reviewed/) | Seven canonical KQL queries and native Microsoft table-schema manifest |
| [`queries/adx-validation/generated/`](queries/adx-validation/generated/) | Seven timestamp-reanchored synthetic KQL replays and seven PASS/FAIL assertion queries |
| [`evidence/adx-free-2026-10-15/`](evidence/adx-free-2026-10-15/) | Exact seven executed synthetic KQL snapshots and manually transcribed outcome receipt |
| [`docs/ADX_SYNTHETIC_EXECUTION.md`](docs/ADX_SYNTHETIC_EXECUTION.md) | Reproduce the Azure Data Explorer synthetic execution and understand evidence limits |
| [`docs/KQL_STATIC_VALIDATION.md`](docs/KQL_STATIC_VALIDATION.md) | Microsoft Kusto.Language static syntax/semantic review evidence and scope |
| [`docs/LIVE_KQL_VALIDATION_GATE.md`](docs/LIVE_KQL_VALIDATION_GATE.md) | The remaining read-only authorized tenant/connector execution requirements |
| [`cloud/`](cloud/), [`windows/`](windows/), [`network/`](network/), [`queries/`](queries/) | Additional historical, illustrative query references |
| [`docs/PHASE2_HUNTS.md`](docs/PHASE2_HUNTS.md) | Detailed Phase 2 schema, rules, limits, and response-handoff conditions |
| [`docs/OFFLINE_LAB.md`](docs/OFFLINE_LAB.md) | Phase 1 contract and original rule behavior |
| [`docs/query-contract.md`](docs/query-contract.md) | Why simulated evaluators do not prove KQL/SIEM compatibility |
| [`docs/engineering-audit.md`](docs/engineering-audit.md) | Prior audit, corrections, and remaining roadmap |

## Five-minute reviewer walkthrough

1. Pick lateral movement or egress from the capability matrix; read its falsifiable hypothesis.
2. Inspect the input CSV, including benign controls, duplicate events, missing evidence, or failed operations.
3. Run `python -B scripts/run_hunt.py ...` to see candidate intervals, exact evidence ordinals and rule parameters.
4. Run the independent regression suite to demonstrate negative and boundary behavior.
5. Check the associated reproduced report and CI provenance.
6. Explain one **known blind spot** and what actual sensor/tenant evidence would be needed for promotion to a validated detection.

For the adjacent [Incident Response Playbooks](https://github.com/farhan-shafee/incident-response-playbooks) project, a candidate can be a **proposed handoff for human triage**, not a confirmed incident or permission to execute containment. No cross-repository production integration is implied.

## Integrity boundaries

All provided values are invented lab data and use example-only identities/IP ranges. Do not commit actual secrets, customer information, or proprietary logs. The offline engine performs no network requests, payload execution or destructive operations. Incident response decisions and live KQL verification must be completed separately in authorized environments.

[Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [Methodology](docs/threat-hunting-methodology.md) · [MITRE ATT&CK](https://attack.mitre.org/)
