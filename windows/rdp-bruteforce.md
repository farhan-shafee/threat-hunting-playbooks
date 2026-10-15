# Windows Hunt: RDP Brute-Force Candidates

> **Query status:** Illustrative Microsoft Defender XDR KQL only. The old `LogonType == 10` condition used Windows event semantics instead of the Defender string field.

## Objective
Identify repeated remote-interactive authentication failures that could signal credential guessing, plus any subsequent successful logon.

## Telemetry and query
Requires Microsoft Defender for Endpoint `DeviceLogonEvents`. Confirm the `ActionType` values from the in-portal schema.

```kql
DeviceLogonEvents
| where Timestamp >= ago(1d)
| where LogonType contains "Remote"
| summarize Failures=countif(ActionType contains "Failed"),
    Successes=countif(ActionType contains "Success"),
    FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by DeviceName, AccountName, RemoteIP, bin(Timestamp, 30m)
| where Failures >= 10
| order by Failures desc
```

## Investigate
1. Verify this was an RDP logon type and the failures truly mean invalid credentials.
2. Confirm source identity, shared bastion hosts, VPN egress, and infrastructure ownership.
3. A success in the same 30-minute bin does not establish that it followed failures; inspect individual event order.
4. Check privileged account exposure, process activity after any success, and change approvals.
5. Escalate only when correlated access or account compromise is plausible.

## False positives
Mistyped passwords, RDP gateways, stale saved credentials, network failures, and helpdesk activity.

## MITRE ATT&CK
- [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)

## Reference
[Microsoft Defender DeviceLogonEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table)
