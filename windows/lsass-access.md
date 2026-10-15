# Windows Hunt: Possible LSASS Credential-Dumping Preparation

> **Query status:** Illustrative Defender process triage; not live-SIEM-tested. A process **mentioning** LSASS is *not proof of LSASS memory access*.

## Objective
Identify tool execution and command lines that warrant review for possible credential dumping.

## Prerequisites
Microsoft Defender XDR `DeviceProcessEvents`. For proof of process-memory access, use an EDR sensor feature exposing cross-process access or explicitly configured Sysmon Event ID 10, plus file-creation context.

## Process-candidate query

```kql
DeviceProcessEvents
| where Timestamp >= ago(2d)
| where ProcessCommandLine contains "lsass"
    or ProcessCommandLine contains "sekurlsa"
    or ProcessCommandLine contains "comsvcs.dll"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| order by Timestamp desc
```

## Analyst steps
1. Confirm the process binary/signing details and actor identity.
2. Distinguish authorized debugging, diagnostics and EDR activity from suspicious execution.
3. Look for an actual LSASS handle/memory access signal, dump-file creation, and suspicious storage/egress.
4. Escalate only after corroborating evidence or high-risk unauthorized access.

## MITRE ATT&CK
- [T1003.001 — OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) (candidate only).

## Reference
[Microsoft Defender DeviceProcessEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
