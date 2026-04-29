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
```kql
DeviceRegistryEvents
| where RegistryKey has_any ("\\Run", "\\RunOnce", "Schedule\\TaskCache")
| where RegistryValueData has_any ("powershell", "cmd.exe", "wscript", "mshta", "http")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by Timestamp desc
```

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
