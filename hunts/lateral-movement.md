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

> **Status: Microsoft vendor-schema-reviewed static candidates, NOT executed in an authorized Sentinel/Defender tenant.**
> These are not claimed equivalent to the synthetic Python detectors.

### Remote execution tool and command pivot

Source: [`queries/schema-reviewed/lateral-execution-pivot.kql`](../queries/schema-reviewed/lateral-execution-pivot.kql). Native table: `DeviceProcessEvents`.

```kql
// DEFENDER XDR / DeviceProcessEvents: remote-tool invocation candidates.
// NOT a validated connection -> logon -> execution correlation; this table
// lacks reliable destination-host/session attribution for that chain.
DeviceProcessEvents
| where Timestamp >= ago(1d)
| where isnotempty(ProcessCommandLine)
| where FileName in~ ("psexec.exe", "wmic.exe", "schtasks.exe",
    "powershell.exe", "pwsh.exe")
| extend CommandLower = tolower(ProcessCommandLine)
| where FileName =~ "psexec.exe"
    or CommandLower contains "/node:"
    or CommandLower contains "\\\\"
    or CommandLower contains "/s "
    or CommandLower contains "invoke-command"
    or CommandLower contains "enter-pssession"
| project Timestamp, DeviceName, AccountName, FileName,
    ProcessCommandLine, InitiatingProcessFileName, ReportId
| order by Timestamp desc
```

**Important limitation:** No 3-source host/logon/execution correlation or destination-host/session proof.

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
- Treat this KQL only as a remote-command *pivot*. True three-sensor connection/logon/execution correlation requires a separately proven join and event mapping; the offline Python lab is not equivalent.
