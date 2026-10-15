# Hunt Playbook: Data Exfiltration Indicators

> **Query status:** Source-schema reviewed for Sentinel `CommonSecurityLog`, not executed in a tenant. The original `DeviceNetworkEvents.SentBytes` example was invalid because that table does not expose this generic field.

## Hypothesis
An adversary may stage sensitive files and transmit unusually large volumes to unapproved external destinations.

## Objective
Identify byte-volume anomalies and investigate whether transfers represent unauthorized data movement.

## Required Data Sources
- Microsoft Sentinel `CommonSecurityLog` from a proxy/firewall that actually populates `SentBytes`, `SourceIP`, `DestinationIP`, and `TimeGenerated`.
- Endpoint archive/file activity and process ancestry.
- Approved data-transfer destinations, enterprise proxy routing, and asset ownership.

## SIEM Query Examples

```kql
CommonSecurityLog
| where TimeGenerated >= ago(1d)
| where isnotempty(SourceIP) and isnotempty(DestinationIP)
| where isnotnull(SentBytes) and SentBytes >= 0
| summarize OutboundBytes=sum(SentBytes), Sessions=count()
    by SourceIP, DestinationIP, bin(TimeGenerated, 1h)
| where OutboundBytes > 500000000
| order by OutboundBytes desc
```

This assumes `SentBytes` is mapped from actual outbound transfer volumes on the relevant appliance. Connector-specific semantics, firewall retry duplicates, VPN egress, and NAT can invalidate this assumption. A threshold exceedance does **not** prove exfiltration.

## Expected Results
- Approved backups, bulk file movement, patch distribution, and media transfers.
- Potential unapproved high-volume outbound sessions requiring triage.

## Investigation Steps
1. Confirm that `SentBytes` is populated and means outbound bytes for this firewall connector.
2. Identify the internal owner of `SourceIP` and whether NAT/proxy rewriting occurred.
3. Validate the destination against approved applications and change records.
4. Correlate the window with sensitive file access, staging/compression, and process origin.
5. Assess data type, user authorization, and blast radius before escalating to incident handling.

## False Positive Guidance
- Backup/sync and approved cloud storage operations.
- CDNs, developer artifact uploads, streaming/media, and software distribution.
- Misinterpreted proxy byte direction or duplicate logs.

## Escalation Criteria
- Large outbound transfer plus unapproved destination plus credible sensitive-data access.
- Unauthorized export or staging from high-value repositories or endpoints.
- Corroborated repeated outbound transfer after denied policy change.

## MITRE ATT&CK Mapping
- T1567 Exfiltration Over Web Service (when supported by destination evidence)
- T1048 Exfiltration Over Alternative Protocol (when relevant)
- T1041 Exfiltration Over C2 Channel (requires C2 evidence)

## Tuning Notes
- Baseline by source asset, bytes/day, destination class, and approved scheduled jobs.
- Test byte counts and timestamp binning against actual connector samples before alert deployment.

## Reference
[Microsoft Sentinel CommonSecurityLog schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/commonsecuritylog)
