# Hunt Playbook: Persistence Mechanisms

## Hypothesis
Attackers may establish persistence via scheduled tasks, run keys, startup folders, or services.

## Objective
Identify suspicious persistence artifacts that survive reboot or user logoff.

## Required Data Sources
- Registry modification events
- Scheduled task and service creation events
- Endpoint process telemetry

## SIEM Query Examples

> **Status: Microsoft vendor-schema-reviewed static candidates, NOT executed in an authorized Sentinel/Defender tenant.**
> These are not claimed equivalent to the synthetic Python detectors.

### Registry autorun entries including direct executables

Source: [`queries/schema-reviewed/persistence-autoruns.kql`](../queries/schema-reviewed/persistence-autoruns.kql). Native table: `DeviceRegistryEvents`.

```kql
// DEFENDER XDR / DeviceRegistryEvents: Windows autorun registry changes.
// RegistryValueData is deliberately NOT filtered by script keywords;
// direct unfamiliar executable paths must remain reviewable.
// Does NOT detect all task or service creation; requires DeviceEvents/Windows logs.
DeviceRegistryEvents
| where Timestamp >= ago(1d)
| where isnotempty(RegistryKey)
| where RegistryKey contains @"\CurrentVersion\Run"
    or RegistryKey contains @"\CurrentVersion\RunOnce"
    or RegistryKey contains @"\Schedule\TaskCache"
| project Timestamp, DeviceName, ActionType, RegistryKey,
    RegistryValueName, RegistryValueData,
    InitiatingProcessFileName, InitiatingProcessAccountName, ReportId
| order by Timestamp desc
```

**Important limitation:** No validated service/task-creation coverage; ActionType values need in-portal review.

## Expected Results
- Software updater autoruns
- Endpoint management agent tasks
- Potential malicious autostart entries

## Investigation Steps
1. Identify created/modified persistence entry.
2. Validate binary/script reputation and signer.
3. Review process lineage and user context.
4. Check if persistence entry appears across additional hosts.
5. Remove unauthorized artifacts and monitor for re-creation.

## False Positive Guidance
- Vendor updaters and enterprise agents
- Approved login scripts
- Gold-image deployment tasks

## Escalation Criteria
- Autorun/task references suspicious unsigned payload.
- Persistence tied to known malicious command patterns.
- Repeated recreation after cleanup attempts.

## MITRE ATT&CK Mapping
- T1547 Boot or Logon Autostart Execution
- T1053 Scheduled Task/Job
- T1543 Create or Modify System Process

## Tuning Notes
- Maintain known-good autorun/task inventory.
- Prioritize new persistence on privileged or critical systems.
