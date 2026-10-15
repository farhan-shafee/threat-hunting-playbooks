# Windows Hunt: Scheduled Task Persistence Candidates

> **Query status:** Illustrative Microsoft Defender XDR registry pivot; not a full scheduled-task detection or a live-validated query.

## Objective
Surface changes involving the Windows TaskCache registry path and pivot to task-creation evidence.

## Query

```kql
DeviceRegistryEvents
| where Timestamp >= ago(7d)
| where RegistryKey contains @"\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache"
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName,
    RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

## Analyst workflow
1. Inventory changed `TaskCache` registry paths and the process making changes.
2. Correlate with Task Scheduler operational events or Windows Security 4698/4702 **if auditing is configured**.
3. Verify the task name, action executable, trigger, user, and legitimate maintenance owner.
4. Check whether the referenced payload is unsigned, unexpected, or accompanied by suspicious activity.
5. Escalate unauthorized persistence with corroborating task and execution evidence.

## False positives
Software installers, enterprise patching, management tools, legitimate scheduled tasks, and system maintenance.

## MITRE ATT&CK
- [T1053.005 — Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)

## Reference
[Microsoft Defender DeviceRegistryEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table)
