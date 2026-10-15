# Azure Data Explorer: reproducible synthetic KQL validation

**Observation:** On October 15, 2026, all seven reviewed KQL examples were executed against **temporary, inline synthetic `datatable` fixtures** in the user's Azure Data Explorer (ADX) free cluster. All seven result grids showed the expected counts and synthetic positive/negative control behavior.

**Evidence limitation:** Results were **visually inspected and transcribed** during the interactive Firefox session. This is not an API-exported, platform-signed, independently audited, or real-tenant security log. The signed-in browser screenshots are intentionally not published.

- ADX free cluster label: `ThreatHuntingLab`; database label: `SecurityLab`
- No tables created, logs ingested, paid resources activated, or credentials collected
- Source-table names were **shadowed** with `let Table = datatable(...)`; native Sentinel/Defender tables were not queried
- Native Sentinel / Defender XDR production execution is **NOT RUN**

## Observed synthetic outcomes

| Canonical source KQL | Fixture records | Result records | Observed evaluation |
|---|---:|---:|---|
| `auth-failure-success.kql` | 13 | 1 | Alice: 5 earlier invalid-password failures, then success; duplicate deduplicated; reversed Bob sequence excluded |
| `auth-spray.kql` | 12 | 1 | 6 unique failures against 3 identities from one IP in a fixed 15-minute bin |
| `powershell-execution.kql` | 4 | 2 | Office-parent encoded PowerShell high; pwsh medium; two benign/unrelated controls excluded |
| `lateral-execution-pivot.kql` | 4 | 2 | PsExec and WMIC process pivots; no claim of an observed lateral movement chain |
| `persistence-autoruns.kql` | 3 | 2 | Registry Run direct executable and TaskCache entry; unrelated registry key excluded |
| `cloud-entra-changes.kql` | 5 | 3 | Completed role/PIM grant and app consent included; failure/request-only controls excluded |
| `egress-byte-volume.kql` | 4 | 1 | 550,000,000 synthetic bytes in one calendar hour across two records; lower/negative controls excluded |

The [exact KQL submitted](../evidence/adx-free-2026-10-15/executed/) is retained as seven read-only text files, with SHA-256 hashes verified against the [manual observation receipt](../evidence/adx-free-2026-10-15/receipt.json). Captures also must retain the canonical KQL suffix from `queries/schema-reviewed/`.

## Rerun without stale October 2026 timestamps

The original captures contain literal dates and `ago(...)` filters. They will produce zero rows when replayed long after October 2026. The deterministic [replay generator](../scripts/build_adx_synthetic_queries.py) preserves the canonical query text and relative fixture event gaps while rebasing only temporary test timestamps to a current bounded UTC interval.

It creates **14 KQL files** under [queries/adx-validation/generated/](../queries/adx-validation/generated/):

- Seven `<query>.kql` files return the original synthetic candidate rows
- Seven `<query>.assert.kql` files return one `Scenario / Expected / Observed / Matched / IdentityMatch / Verdict` row, reporting `PASS` only when the result count, row attributes **and full set of expected event identities** match

Run from repository root:

```powershell
python -B scripts/build_adx_synthetic_queries.py --check
python -B -m unittest discover -s tests -v
pwsh -NoProfile -File scripts/validate_kql_schemas.ps1
```

`--check` is strictly read-only. `--write` regenerates only derived KQL files; it does not modify the original captures, observation receipt or canonical query sources. GitHub CI checks deterministic outputs and invokes Microsoft's pinned Kusto.Language parser for static syntax and curated-schema semantics across **7 original + 14 generated KQL files**. CI does **not** call Azure.

## October 15 — runtime verification of all seven generated assertions

After the original seven canonical-query exercises, all seven **corrected generated assertion variants were also executed** against temporary synthetic `datatable` rows in your Azure Data Explorer free cluster. All seven returned `PASS` with equal expected, observed and matched counts and `IdentityMatch=true`.

| Assertion KQL | Expected / observed / matched | Identity matched | Verdict |
|---|---|---|---|
| `auth-failure-success.assert.kql` | 1 / 1 / 1 | true | PASS |
| `auth-spray.assert.kql` | 1 / 1 / 1 | true | PASS |
| `powershell-execution.assert.kql` | 2 / 2 / 2 | true | PASS |
| `lateral-execution-pivot.assert.kql` | 2 / 2 / 2 | true | PASS |
| `persistence-autoruns.assert.kql` | 2 / 2 / 2 | true | PASS |
| `cloud-entra-changes.assert.kql` | 3 / 3 / 3 | true | PASS |
| `egress-byte-volume.assert.kql` | 1 / 1 / 1 | true | PASS |

A separate deliberately incorrect expected identity for the authentication assertion yielded `IdentityMatch=false` and `Verdict=FAIL` even while its event count matched. This verifies that count-only passing isn't enough.

The first cloud-side run exposed **two runtime defects that local static analysis had missed**: an unsupported `set_equals()` call and invalid generated names starting with `__`. The corrected assertions use **two supported directional `set_difference()` checks**, each empty, and `Lab...` variable names. Regression tests prevent those defects from recurring.

The exact corrected KQL files are bound by SHA-256 to the [human-observed assertion execution receipt](../evidence/adx-free-2026-10-15/assertion-runtime-receipt.json). The receipt is a manual transcription from ADX result grids, **not an API export, signed forensic record, or native Microsoft Sentinel/Defender execution**. Screenshots from an authenticated browser session were not committed.

## Repeat the synthetic assertion runs

Sign in yourself to [Azure Data Explorer](https://dataexplorer.azure.com/). In a blank query editor, paste the entire contents of one generated `.assert.kql` file and execute it using the free cluster. It is a self-contained, read-only, in-memory fixture. Verify one result row with `Verdict=PASS`, `IdentityMatch=true` and the recorded `Expected=Observed=Matched` values. Repeat for other scenarios.

The **corrected** assertion variants were all executed later on October 15 and returned PASS, as recorded above. Any **subsequent edited revision** requires its own new runtime evidence; matching static tests alone cannot justify inheriting the earlier PASS. Future ADX runs should verify their assertion verdicts independently, and failures must be investigated.

## Remaining qualification gates

- Real Microsoft Sentinel/Defender deployment, connector availability, source-field population and RBAC are untested.
- Synthetic tests cannot establish real-world detection effectiveness, false-positive rates or incident response readiness.
- KQL pivots intentionally differ from the six Python hunt detectors (notably fixed-bin auth spray, command-only lateral pivot and calendar-hour firewall aggregation).
- Manual execution receipts and content hashes are not forensic custody, a signed Azure service receipt or an independent audit.

To promote against actual security telemetry, follow [native live validation](LIVE_KQL_VALIDATION_GATE.md).

**Statuses:** `ADX_CANONICAL_SYNTHETIC_EXECUTED_7_OF_7` / `ADX_ASSERTIONS_GUI_EXECUTED_7_PASS_NEGATIVE_FAIL` / `NATIVE_SENTINEL_DEFENDER_NOT_RUN`.
