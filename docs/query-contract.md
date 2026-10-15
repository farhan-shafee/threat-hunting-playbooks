# Query and Telemetry Compatibility Contract

**State: October 2026 — no cloud/EDR tenant execution in this repository.**

This project contains two different artifacts and does **not** claim parity:

1. **Offline Python evaluator:** proven through synthetic CSV fixtures and tests. The inputs intentionally use selected columns resembling Microsoft Entra `SigninLogs` and Defender `DeviceProcessEvents`, not complete vendor schemas.
2. **KQL Markdown examples:** investigator starting points with different source products, data connectors, licensing, action types, and retention. Formatting and documentation are reviewed; live KQL compilation, semantic behavior, and production false-positive rates are **unverified**.

| Example family | Target product / table | Input guarantee | Status |
|---|---|---|---|
| Auth | Microsoft Sentinel / `SigninLogs` | `TimeGenerated`, `UserPrincipalName`, `IPAddress`, string-convertible `ResultType` | Offline CSV rules tested; KQL tenant untested |
| PowerShell | Defender XDR / `DeviceProcessEvents` | `Timestamp`, `DeviceName`, `AccountName`, `FileName`, `ProcessCommandLine`, `InitiatingProcessFileName` | Offline CSV rules tested; KQL tenant untested |
| Proxy byte-volume | Sentinel / `CommonSecurityLog` | `SourceIP`, `DestinationIP`, `SentBytes`, `TimeGenerated` populated by connector | Documented only |
| AWS management | Sentinel / `AWSCloudTrail` | `EventName`, `EventSource`, `UserIdentityArn`, `TimeGenerated`, `ErrorCode` | Documented only |
| Entra admin | Sentinel / `AuditLogs` | `OperationName`, `InitiatedBy`, `TargetResources` | Documented only |
| RDP/network logons | Defender XDR / `DeviceLogonEvents` | `LogonType` is a **string**, `ActionType` varies | Documented only |
| Outbound connections | Defender XDR / `DeviceNetworkEvents` | `RemoteIP`, `RemotePort`, `Timestamp`, `DeviceName` | Documented only |
| DNS tunneling | Optional normalized `DnsEvents` | **No default universal schema is supplied** | **Blocked** until a defined connector/column map |
| JA3, session duration, HTTP body sizes | Separate Zeek/TLS/proxy sensor | Not default `DeviceNetworkEvents` columns | **Blocked** without separate source |

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
