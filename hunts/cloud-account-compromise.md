# Hunt Playbook: Cloud Account Compromise

## Hypothesis
Compromised cloud identities may be used for privilege abuse, persistence, and data access.

## Objective
Detect suspicious identity and permission actions in cloud control planes.

## Required Data Sources
- Microsoft Sentinel Entra `AuditLogs` and optional `SigninLogs` context. AWS CloudTrail is a separate platform/source and **is not covered by the KQL example below**.
- Conditional access / IAM policy change logs
- MFA and session/token telemetry

## SIEM Query Examples

> **Status: Microsoft vendor-schema-reviewed static candidates, NOT executed in an authorized Sentinel/Defender tenant.**
> These are not claimed equivalent to the synthetic Python detectors.

### Successful high-interest Entra administrative changes

Source: [`queries/schema-reviewed/cloud-entra-changes.kql`](../queries/schema-reviewed/cloud-entra-changes.kql). Native table: `AuditLogs`.

```kql
// SENTINEL / AuditLogs: completed high-interest Entra administration events.
// OperationName spellings come from Microsoft Entra audit activity reference.
// Result must indicate success. Neither unauthorized change nor account
// compromise can be inferred without independent approval/context evidence.
AuditLogs
| where TimeGenerated >= ago(7d)
| where OperationName in~ (
    "Add member to role",
    "Add role assignment to role definition",
    "Add member to role completed (PIM activation)",
    "Add member to role in PIM completed (timebound)",
    "Add app role assignment to service principal",
    "Add delegated permission grant",
    "Consent to application",
    "Add service principal credentials"
)
| where tostring(Result) =~ "success"
| extend ChangeClass = case(
    OperationName contains "PIM", "completed PIM change",
    OperationName contains "service principal credentials", "credential addition",
    OperationName contains "Consent", "application consent",
    OperationName contains "delegated permission", "delegated permission grant",
    OperationName contains "role", "role or app-role change",
    "other reviewed operation"
)
| project TimeGenerated, Id, OperationName, ChangeClass,
    Result, InitiatedBy, TargetResources, CorrelationId
| order by TimeGenerated desc
```

**Important limitation:** Not an authorization verdict; PIM eligibility and tenant-specific operation names require follow-up.

## Expected Results
- Legitimate administrative role grants
- Approved application onboarding
- Potential unauthorized privilege changes

## Investigation Steps
1. Validate change request and approver records.
2. Review actor identity risk context (location/device/MFA).
3. Inspect newly granted permissions/scopes.
4. Revoke suspicious grants and rotate impacted credentials.
5. Expand scope for downstream access activity.

## False Positive Guidance
- Planned IAM maintenance
- New enterprise application deployments
- Break-glass account usage with documented approval

## Escalation Criteria
- Privileged grants without approved change context.
- Suspicious OAuth consent with high-risk scopes.
- Root/global admin activity from unusual context.

## MITRE ATT&CK Mapping
- T1078 Valid Accounts
- T1098 Account Manipulation
- T1528 Steal Application Access Token

## Tuning Notes
- Tag high-risk operations and privileged roles.
- Separate automation account actions from human admin actions.
