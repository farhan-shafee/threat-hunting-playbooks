# Cloud Hunt: AWS IAM Anomalies

> **Query status:** Source-schema reviewed against Microsoft Sentinel's `AWSCloudTrail` reference. These are investigative queries, **not** live-tenant-tested detections. This requires an enabled AWS CloudTrail connector.

## Hypothesis
A compromised AWS identity may create principals, alter IAM privileges, or make unusual root-account API calls.

## Required data
- Microsoft Sentinel `AWSCloudTrail` connector and retention appropriate to the hunt period.
- `TimeGenerated`, `EventName`, `EventSource`, `UserIdentityArn`, `UserIdentityType`, `SourceIpAddress`, `RequestParameters`, and `ErrorCode`.
- Cloud asset/identity ownership and approved IAM change records.

## Query A: IAM policy and credential management candidates

```kql
AWSCloudTrail
| where TimeGenerated >= ago(7d)
| where EventSource =~ "iam.amazonaws.com"
| where EventName in~ ("CreateUser", "CreateAccessKey", "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy")
| project TimeGenerated, EventName, UserIdentityArn, SourceIpAddress, RecipientAccountId, RequestParameters, ErrorCode
| order by TimeGenerated desc
```

**Interpretation:** These actions also occur during normal provisioning. Check whether `ErrorCode` indicates failure; a logged attempt is not proof of a completed privilege change.

## Query B: Root activity candidates

```kql
AWSCloudTrail
| where TimeGenerated >= ago(30d)
| where UserIdentityType =~ "Root"
| project TimeGenerated, EventName, EventSource, SourceIpAddress, RecipientAccountId, UserAgent, ErrorCode
| order by TimeGenerated desc
```

**Interpretation:** Investigate human root activity with change-control evidence and the AWS account owner. A single root event is not proof of account compromise.

## Analyst decisions
1. Confirm the connector and ingestion completeness; compare `TimeGenerated` against the AWS event time where available.
2. Identify the actor/assumed role and source context; normalize automation before flagging unusual activity.
3. Examine the specific principal, policy ARN, new key, or role and check its effective permissions.
4. Correlate with subsequent sign-ins, access key usage, resource access, and enforcement changes.
5. Escalate unexpected privilege grants or sensitive key creation on critical accounts; preserve evidence before remediation.

## Limits and false positives
- Infrastructure-as-code, CI/CD, SSO, and emergency-access accounts may generate legitimate IAM events.
- `SessionMfaAuthenticated == false` **does not, by itself, establish MFA bypass**. Session context varies for assumed roles and service calls.
- Access key creation is not proof of abuse; check actual use and policy context.
- These are candidate-finding queries, not baselined alerts or validated field coverage.

## MITRE ATT&CK
- [T1078.004 — Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- [T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/)

## Schema reference
[Microsoft Sentinel AWSCloudTrail table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/awscloudtrail)
