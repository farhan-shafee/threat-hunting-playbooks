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

> **Status: Microsoft vendor-schema-reviewed static candidates, NOT executed in an authorized Sentinel/Defender tenant.**
> These are not claimed equivalent to the synthetic Python detectors.

### PowerShell or pwsh suspicious command-line pivot

Source: [`queries/schema-reviewed/powershell-execution.kql`](../queries/schema-reviewed/powershell-execution.kql). Native table: `DeviceProcessEvents`.

```kql
// DEFENDER XDR / DeviceProcessEvents: command-line and parent-process pivot.
// Candidate text signals only: neither encoded execution nor compromise
// is established without decoded content and corroborating context.
DeviceProcessEvents
| where Timestamp >= ago(1d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where isnotempty(ProcessCommandLine)
| extend CommandLower = tolower(ProcessCommandLine),
    ParentLower = tolower(InitiatingProcessFileName)
| extend EncodedFlag = CommandLower matches regex @"(^|\s)-(enc|encodedcommand)(\s|:|$)",
    ScriptMarker = CommandLower contains "frombase64string"
        or CommandLower contains "invoke-expression"
        or CommandLower contains "iex("
        or CommandLower contains "downloadstring("
| where EncodedFlag or ScriptMarker
| extend RiskyParent = ParentLower in ("winword.exe", "excel.exe",
    "outlook.exe", "wscript.exe", "cscript.exe", "mshta.exe")
| extend ReviewPriority = iff(RiskyParent, "high", "medium")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
    InitiatingProcessFileName, EncodedFlag, ScriptMarker, RiskyParent,
    ReviewPriority, ReportId
| order by Timestamp desc
```

**Important limitation:** String matching does not decode payloads or verify process/signer identity.

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
- Treat risky parent process *plus* suspicious arguments as a higher-priority review candidate; suspicious arguments without that parent remain lower-priority candidates. This query does not publish an alert.
