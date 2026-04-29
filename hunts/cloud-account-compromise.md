# Hunt Playbook: Cloud Account Compromise

## Hypothesis
Compromised cloud identities may be used for privilege abuse, persistence, and data access.

## Objective
Detect suspicious identity and permission actions in cloud control planes.

## Required Data Sources
- Azure AuditLogs / SigninLogs or AWS CloudTrail
- Conditional access / IAM policy change logs
- MFA and session/token telemetry

## SIEM Query Examples
```kql
AuditLogs
| where OperationName has_any ("Add role assignment", "Consent to application", "Add service principal")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources
| order by TimeGenerated desc
```

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
