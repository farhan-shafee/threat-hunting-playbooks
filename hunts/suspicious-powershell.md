# Hunt Playbook: Suspicious PowerShell

## Hypothesis
Attackers may use PowerShell with obfuscation or encoded commands for execution, staging, and defense evasion.

## Objective
Identify potentially malicious PowerShell executions and prioritize events requiring analyst investigation.

## Required Data Sources
- EDR process telemetry (process name, command line, parent process, user, integrity level)
- PowerShell Script Block logs (if enabled)
- Network connection telemetry from host

## SIEM Query Examples
```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc","EncodedCommand","FromBase64String","IEX","Invoke-Expression")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

## Expected Results
- Administrative automation activity (common benign)
- Script execution from IT tooling
- Smaller subset of suspicious executions with encoded/obfuscated content

## Investigation Steps
1. Review parent-child process chain.
2. Decode encoded command content.
3. Check user context and endpoint criticality.
4. Correlate with outbound network activity and file writes.
5. Determine if activity aligns with approved admin scripts.

## False Positive Guidance
- IT management frameworks (RMM, SCCM, Intune)
- Backup and inventory scripts
- Legitimate security tooling scripts

## Escalation Criteria
- Encoded command launches unknown binaries/scripts.
- Evidence of credential access, downloader behavior, or persistence setup.
- Execution on high-value systems without approved change record.

## MITRE ATT&CK Mapping
- T1059.001 PowerShell
- T1027 Obfuscated/Compressed Files and Information
- T1105 Ingress Tool Transfer

## Tuning Notes
- Maintain allowlist of approved script hashes, signing certs, and admin hosts.
- Alert only when suspicious arguments + risky parent process co-occur.
