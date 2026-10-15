# KQL source-schema validation: seven read-only candidate queries

**Validation class:** Microsoft vendor-schema-reviewed STATIC syntax and semantic checking, **not live Sentinel or Defender XDR execution**. A local KQL parser can reject invalid field references without tenant access, but cannot establish deployed connectors, data quality, query cost, production false-positive rate, or query behavior.

## Reproducible validation receipt

- Baseline: merged Threat Hunting Phase 2 `main` at `c5e9ea51328855d1fa2b6ae4250b084954bb8d4e`.
- Parser: `Microsoft.Azure.Kusto.Language` version **12.4.1**, retrieved to the operating-system temp folder from Microsoft NuGet, SHA-256 verified against the exact digest pinned in `queries/schema-reviewed/manifest.json`. No binary is committed.
- Source contract: five manually curated minimal native table schemas from official Microsoft Learn documentation.
- Analysis: `KustoCode.ParseAndAnalyze(query, globals)` with in-memory `DatabaseSymbol` and `TableSymbol` objects. `GetDiagnostics()` is checked for errors.
- Result: **seven queries with zero syntax or static-semantic diagnostics**, using only the curated field subsets. The protected CI matrix repeats these checks.
- Companion check: `python -B scripts/sync_kql_examples.py --check` verifies that all six Markdown playbooks contain the canonical query text exactly.
- **Tenant execution: NOT RUN.** No authorized Sentinel workspace, Defender XDR tenant, connector and permission review, or actual query-output receipt has been provided. Passing CI must not be interpreted as live validation.

## Query-by-query scope

| Canonical KQL source | Microsoft table | Important limitation |
|---|---|---|
| `auth-failure-success.kql` | Sentinel `SigninLogs` | Same user/IP, strictly earlier interactive 50126 failures before success within 15m; not offline state-reset parity |
| `auth-spray.kql` | Sentinel `SigninLogs` | Multi-user failures in **fixed** 15m bins; misses some boundary-spanning sprays |
| `powershell-execution.kql` | Defender XDR `DeviceProcessEvents` | PowerShell and pwsh text/parent pivots; no actual decoded payload or signer verdict |
| `lateral-execution-pivot.kql` | Defender XDR `DeviceProcessEvents` | Remote-tool command pivot only, NOT the Python three-sensor host/logon/execution correlation |
| `persistence-autoruns.kql` | Defender XDR `DeviceRegistryEvents` | Registry Run/RunOnce/TaskCache entries, including direct executables; not service/task creation coverage |
| `cloud-entra-changes.kql` | Sentinel `AuditLogs` | Successful high-interest privilege, consent and credential changes; approval and maliciousness unverified |
| `egress-byte-volume.kql` | Sentinel `CommonSecurityLog` | Calendar-hour connector sent-byte volume; no sliding-hour, session dedup, counter, direction, or destination guarantee |

The canonical sources are in `queries/schema-reviewed/` and the explicit table/column manifest is `manifest.json`. These source-specific KQL fragments are NOT generated from, tested by, or asserted equivalent to the six Python hunt detectors.

## Official Microsoft references

- [SigninLogs table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
- [AuditLogs table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs)
- [Entra directory and PIM activity names](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities)
- [Defender DeviceProcessEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
- [Defender DeviceRegistryEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table)
- [CommonSecurityLog](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/commonsecuritylog)
- [Kusto.Language parser and semantic analysis](https://learn.microsoft.com/en-us/kusto/api/netfx/kusto-language-parse-queries)
- [Kusto substring versus term matching](https://learn.microsoft.com/en-us/kusto/query/contains-operator)

## Repeat the static checks

```powershell
python -B scripts/sync_kql_examples.py --check
python -B -m unittest discover -s tests -v
pwsh -NoProfile -File scripts/validate_kql_schemas.ps1
```

The PowerShell verifier retrieves the SHA-256-verified Microsoft NuGet package (or accepts `-PackageArchivePath`), creates source table schemas in memory, parses and statically analyzes all seven queries, and fails on diagnostics or missing required fields. It never authenticates to Sentinel/Defender.

## What remains blocked

See [LIVE_KQL_VALIDATION_GATE.md](LIVE_KQL_VALIDATION_GATE.md). The current status is:

**STATIC_SOURCE_REVIEW_PASS / TENANT_EXECUTION_NOT_RUN / DETECTION_EFFICACY_UNMEASURED**.

The historical examples elsewhere in `cloud/`, `windows/`, `network/`, and `queries/kql-collection.md` are **not** included in this seven-query acceptance set; they remain unverified.
