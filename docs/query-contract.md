# Query and Telemetry Compatibility Contract

**State: October 2026 — no cloud/EDR tenant execution in this repository.**

This project distinguishes three types of artifacts and does **not** claim parity:

**Phase 2 addition:** Four more offline-only algorithms evaluate *invented normalized lab schemas* for lateral movement, persistence, cloud administrative changes, and network egress. These are documented in [PHASE2_HUNTS.md](PHASE2_HUNTS.md); they are **not** execution tests of the KQL Markdown and are not a replacement for vendor-specific telemetry connectors.

1. **Offline Python evaluator:** proven through synthetic CSV fixtures and tests. The inputs intentionally use selected columns resembling Microsoft Entra `SigninLogs` and Defender `DeviceProcessEvents`, not complete vendor schemas.
2. **Canonical KQL in the six core Markdown playbooks:** seven read-only, source-reviewed native-table candidates, kept identical to `queries/schema-reviewed/*.kql`. Microsoft Kusto.Language 12.4.1 reports zero errors from syntax plus curated-schema **static semantic analysis**. Tenant/service-side compilation, connector availability, runtime behavior, query-to-Python parity, and operational false-positive rates are **unverified**. See [static validation](KQL_STATIC_VALIDATION.md) and [live execution gate](LIVE_KQL_VALIDATION_GATE.md).
3. **Other historical/illustrative KQL:** continues to be unverified; do not treat the core seven-query parser check as coverage of other `cloud/`, `windows/`, `network/`, or catalog examples.

| Example family | Target product / table | Input guarantee | Status |
|---|---|---|---|
| Auth (two queries) | Microsoft Sentinel / `SigninLogs` | `TimeGenerated`, `Id`, `IsInteractive`, `UserPrincipalName`, `IPAddress`, string `ResultType` | Kusto static source-schema PASS; live tenant NOT RUN; fixed-bin spray limitations |
| PowerShell | Defender XDR / `DeviceProcessEvents` | `Timestamp`, `DeviceName`, `AccountName`, `FileName`, `ProcessCommandLine`, `InitiatingProcessFileName`, `ReportId` | Kusto static source-schema PASS; tenant NOT RUN |
| Proxy byte-volume | Sentinel / `CommonSecurityLog` | `SourceIP`, `DestinationIP`, `SentBytes`, `TimeGenerated` populated by connector | Kusto static source-schema PASS; byte direction/semantics and tenant NOT RUN |
| AWS management | Sentinel / `AWSCloudTrail` | `EventName`, `EventSource`, `UserIdentityArn`, `TimeGenerated`, `ErrorCode` | Documented only |
| Entra admin | Sentinel / `AuditLogs` | `OperationName`, `Result`, `InitiatedBy`, `TargetResources`, `Id`, `CorrelationId` | Kusto static source-schema PASS; exact operation variants and tenant NOT RUN |
| Registry autoruns | Defender XDR / `DeviceRegistryEvents` | `Timestamp`, `RegistryKey`, `RegistryValueData`, `ActionType`, initiating process, `ReportId` | Kusto static source-schema PASS; no task/service-creation coverage |
| Remote-execution pivot | Defender XDR / `DeviceProcessEvents` | Process command/file and initiating-process context | Kusto static source-schema PASS; not offline lateral-chain parity |
| RDP/network logons | Defender XDR / `DeviceLogonEvents` | `LogonType` is a **string**, `ActionType` varies | Other historical examples NOT RUN |
| Outbound connections | Defender XDR / `DeviceNetworkEvents` | `RemoteIP`, `RemotePort`, `Timestamp`, `DeviceName` | Documented only |
| DNS tunneling | Optional normalized `DnsEvents` | **No default universal schema is supplied** | **Blocked** until a defined connector/column map |
| JA3, session duration, HTTP body sizes | Separate Zeek/TLS/proxy sensor | Not default `DeviceNetworkEvents` columns | **Blocked** without separate source |

## ADX synthetic execution status

The seven native-table KQL **expressions** were run against ephemeral inline synthetic datatables in an Azure Data Explorer free cluster on 2026-10-15, returning the expected reviewed candidate sets. Exact executed query text and human-transcribed counts are retained in [the ADX evidence documentation](ADX_SYNTHETIC_EXECUTION.md). Source-dependent runtime behavior in **real Sentinel or Defender security telemetry remains unverified**. The newly generated assertion KQL is statically checked, but its fresh-time replay has not yet been executed in ADX.

## Reproducible curated KQL check

The seven canonical KQL files at `queries/schema-reviewed/` are parsed and statically type-checked by Microsoft's `Kusto.Language` 12.4.1 using manually curated minimal table definitions from the official references. `scripts/validate_kql_schemas.ps1` fails on parser/semantic errors and `scripts/sync_kql_examples.py --check` fails if a core playbook's KQL diverges. **These checks do not execute a query against Microsoft Sentinel or Defender XDR.** See [KQL static validation](KQL_STATIC_VALIDATION.md), and the [live tenant gate](LIVE_KQL_VALIDATION_GATE.md) for the remaining evidence requirements.

## Minimum requirements before promoting a KQL snippet

- Capture official vendor source/schema URLs, product/connector/license scope, data retention, and action types.
- Confirm column availability and types with a tenant-side read-only test in an **authorized** environment.
- Define synthetic positives, negatives, time-boundaries, null/missing telemetry, and desired false-positive behavior.
- Save actual query text/version, UTC time range, anonymized evidence, and evidence lineage.
- Separate candidate hits, analyst investigation, and confirmed incidents.
- Get approval before incident containment, account disabling, or automation affecting real assets.

## External vendor references

- [Microsoft Defender DeviceProcessEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
- [Microsoft Defender DeviceNetworkEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table)
- [Microsoft Defender DeviceLogonEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table)
- [Microsoft Sentinel SigninLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
- [Microsoft Sentinel CommonSecurityLog](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/commonsecuritylog)
- [Microsoft Sentinel AWSCloudTrail](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/awscloudtrail)
- [MITRE ATT&CK](https://attack.mitre.org/)

**Privacy:** `samples/logs/*-lab-v1.csv` is fake by design. Runbook examples must never require secrets or production connections to pass CI.
