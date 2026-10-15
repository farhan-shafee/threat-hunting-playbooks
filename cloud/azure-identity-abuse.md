# Cloud Hunt: Microsoft Entra Identity Abuse

> **Query status:** Source-schema reviewed, but not live-Sentinel-tested. `SigninLogs` and `AuditLogs` require appropriate diagnostic settings and retention.

## Hypothesis
Compromised identities may generate unusually rapid geographic changes, repeated authentication challenges, or unauthorized role assignments.

## Query A: Rapid country-change candidates (not proof of impossible travel)

```kql
SigninLogs
| where TimeGenerated >= ago(7d)
| where tostring(ResultType) == "0"
| extend Country = tostring(LocationDetails.countryOrRegion)
| where isnotempty(UserPrincipalName) and isnotempty(Country)
| project TimeGenerated, UserPrincipalName, IPAddress, Country, AppDisplayName
| order by UserPrincipalName asc, TimeGenerated asc
| serialize PreviousUser = prev(UserPrincipalName), PreviousCountry = prev(Country), PreviousTime = prev(TimeGenerated)
| where UserPrincipalName == PreviousUser and Country != PreviousCountry
| extend MinutesBetween = datetime_diff("minute", TimeGenerated, PreviousTime)
| where MinutesBetween between (0 .. 60)
| project TimeGenerated, UserPrincipalName, IPAddress, Country, PreviousCountry, MinutesBetween, AppDisplayName
```

A country-change candidate can be caused by VPN egress, shared networks, IP-geolocation errors, or travel; actual impossible-travel analysis needs distance, travel speed, device/session context, and exclusions. Sorting + `serialize` is essential before `prev()`.

## Query B: Repeated MFA-related failure descriptions

```kql
SigninLogs
| where TimeGenerated >= ago(1d)
| where tostring(ResultType) != "0"
| extend FailureDescription = tostring(Status.failureReason)
| where FailureDescription contains "MFA" or FailureDescription contains "multi-factor"
| summarize Attempts=count(), Reasons=make_set(FailureDescription, 5)
    by UserPrincipalName, IPAddress, bin(TimeGenerated, 15m)
| where Attempts >= 5
| order by Attempts desc
```

This is **not a measurement of MFA push prompts**. Check authentication details and tenant-specific error semantics before calling an event MFA fatigue.

## Query C: Identity administrative changes

```kql
AuditLogs
| where TimeGenerated >= ago(7d)
| where OperationName has_any ("role assignment", "Consent to application", "service principal")
| project TimeGenerated, OperationName, Result, InitiatedBy, TargetResources
| order by TimeGenerated desc
```

## Analyst workflow
1. Confirm data-source completeness and which sign-ins are interactive vs service principal.
2. Correlate candidates with device, Conditional Access result, user travel, and known corporate VPN exits.
3. Validate role/consent actions against change approvals and app publisher trust.
4. Escalate confirmed unexpected privilege grants or high-risk identity sessions; do not reset identities based solely on these candidate queries.

## False positives
Approved travel, proxy/VPN exits, provisioning jobs, directory sync, and failed legacy clients.

## MITRE ATT&CK
- [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [T1621 — MFA Request Generation](https://attack.mitre.org/techniques/T1621/) (only if actual prompt telemetry supports this)

## Schema reference
[Microsoft Sentinel SigninLogs table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
