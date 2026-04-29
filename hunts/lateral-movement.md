# Hunt Playbook: Lateral Movement

## Hypothesis
An adversary with initial access may pivot internally through SMB, remote services, WMI, or PSRemoting.

## Objective
Identify suspicious host-to-host movement and remote execution behavior.

## Required Data Sources
- Endpoint process creation logs
- Network connection telemetry (east-west)
- Windows security events for remote logon/service creation

## SIEM Query Examples
```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("psexec", "wmic /node", "Invoke-Command", "Enter-PSSession", "schtasks /s")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

## Expected Results
- Legitimate remote admin actions by IT teams
- Patching or software deployment workflows
- Potential unauthorized lateral movement attempts

## Investigation Steps
1. Confirm whether source and destination pairing is expected.
2. Validate actor identity and privilege level.
3. Look for preceding credential theft/suspicious logon activity.
4. Review remote execution artifacts (service creation, task creation).
5. Scope additional affected endpoints.

## False Positive Guidance
- Planned maintenance windows
- Authorized admin jump boxes
- EDR/live-response tooling

## Escalation Criteria
- Remote execution from non-admin workstations.
- Lateral movement touching privileged infrastructure.
- Evidence of chained actions across multiple hosts.

## MITRE ATT&CK Mapping
- T1021 Remote Services
- T1021.002 SMB/Windows Admin Shares
- T1047 Windows Management Instrumentation

## Tuning Notes
- Baseline normal admin source hosts.
- Require multi-signal correlation (remote exec + unusual auth + new binary).
