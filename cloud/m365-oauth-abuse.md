# Cloud Hunt: Microsoft 365 OAuth Consent Abuse

> **Query status:** Illustrative Microsoft Sentinel queries; no tenant execution, sensitivity testing, or OAuth token-replay validation performed.

## Hypothesis
An adversary with identity access may gain app permissions or alter mailbox authorization to facilitate ongoing data access.

## Query A: Consent and service-principal activity

```kql
AuditLogs
| where TimeGenerated >= ago(7d)
| where OperationName has_any ("Consent to application", "Add service principal")
| project TimeGenerated, OperationName, Result, InitiatedBy, TargetResources
| order by TimeGenerated desc
```

Investigate actual granted permission scopes and the consenting principal. Administrative onboarding is common and not necessarily abuse.

## Query B: Mailbox permission changes (not mailbox read evidence)

```kql
OfficeActivity
| where TimeGenerated >= ago(7d)
| where Operation =~ "Add-MailboxPermission"
| project TimeGenerated, Operation, UserId, OfficeObjectId, Parameters
| order by TimeGenerated desc
```

This may indicate a permission change. **It does not prove an OAuth app accessed or collected messages**. Verify `OfficeActivity` ingestion and fields in the tenant and correlate with app/Graph audit telemetry before inferring application mailbox access.

## Query C: Unusual IP diversity for successful app sign-ins

```kql
SigninLogs
| where TimeGenerated >= ago(1d)
| where tostring(ResultType) == "0"
| where isnotempty(AppId) and isnotempty(UserPrincipalName)
| summarize SourceIPs=dcount(IPAddress), Examples=make_set(IPAddress, 10)
    by AppId, UserPrincipalName, bin(TimeGenerated, 1h)
| where SourceIPs >= 4
| order by SourceIPs desc
```

High IP diversity is an **investigative pivot**, not evidence of token replay. Proving token theft requires supporting token/session-device evidence unavailable in these columns.

## Analyst workflow
1. Verify the audited app ID, publisher, owner, tenant authorization policy, and actual scopes granted.
2. Correlate consent changes to approvals, sign-ins, mailbox permissions, and Graph activity where logged.
3. Separate legitimate multi-region SaaS app traffic from unauthorized app consent.
4. Preserve audit evidence and escalate high-impact unapproved grants to the identity/IR owner.

## MITRE ATT&CK
- [T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [T1114 — Email Collection](https://attack.mitre.org/techniques/T1114/) (only with actual collection evidence)
- [T1528 — Steal Application Access Token](https://attack.mitre.org/techniques/T1528/) (not directly detected by these queries)

## Schema
[AuditLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs) ·
[SigninLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs) ·
[OfficeActivity](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/officeactivity)
