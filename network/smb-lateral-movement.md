# Network Hunt: SMB Lateral Movement Candidates

> **Query status:** Illustrative Defender XDR KQL only. No live sensor/tenant validation, confirmed lateral movement, or pass-the-hash detection performance is claimed.

## Hypothesis
Unauthorized lateral movement may combine unexpected internal SMB connections, network logons, and remote-service execution.

## Data prerequisites
`DeviceNetworkEvents` for TCP/445 activity, `DeviceLogonEvents` for network logons, `DeviceProcessEvents` for execution. Identify approved admin sources and maintenance windows.

## Query A: SMB destination-pair activity

```kql
DeviceNetworkEvents
| where Timestamp >= ago(1d)
| where RemotePort == 445
| where ActionType == "ConnectionSuccess"
| summarize SMBConnections=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by DeviceName, RemoteIP, bin(Timestamp, 1h)
| where SMBConnections >= 20
| order by SMBConnections desc
```

## Query B: Network logon failures

```kql
DeviceLogonEvents
| where Timestamp >= ago(1d)
| where LogonType =~ "Network"
| where ActionType contains "Failed"
| summarize FailedAttempts=count() by DeviceName, AccountName, RemoteIP, bin(Timestamp, 15m)
| where FailedAttempts >= 10
| order by FailedAttempts desc
```

The exact `ActionType` values are service-specific: confirm in the in-portal schema reference. This query is an investigative candidate, not confirmed SMB password spraying.

## Query C: Remote execution pivot

```kql
DeviceProcessEvents
| where Timestamp >= ago(1d)
| where ProcessCommandLine contains "psexec" or ProcessCommandLine contains "smbexec"
    or ProcessCommandLine contains "wmiexec" or ProcessCommandLine contains "secretsdump"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

Tools and process arguments are not definitive; attackers can rename utilities and administrators can use the same tools legitimately.

## Analyst workflow
1. Validate source/destination and actor authorization; identify non-admin workstations targeting critical systems.
2. Correlate logon type, source IP, process tree, service creation, and SMB/445 connection timing.
3. To establish ADMIN$/IPC$/C$ share access, collect Windows share-auditing events (for example 5140/5145) or a separate SMB sensor. `DeviceNetworkEvents.RemoteUrl` does not reliably report SMB share names.
4. Check NTLM/Kerberos context and supporting logon artifacts before suggesting pass-the-hash.
5. Escalate corroborated unauthorized host-to-host access, not just high volume.

## False positives
Software distribution, patch managers, EDR live response, backup agents, administrative jump servers, and vulnerability scanners.

## MITRE ATT&CK
- [T1021.002 — SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [T1550.002 — Pass the Hash](https://attack.mitre.org/techniques/T1550/002/) (requires separate evidence)
- [T1569.002 — Service Execution](https://attack.mitre.org/techniques/T1569/002/)
- [T1047 — Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)

## Reference
[DeviceNetworkEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) ·
[DeviceLogonEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table)
