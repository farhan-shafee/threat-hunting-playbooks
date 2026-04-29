# Hunt Playbook: Unusual Authentication Behavior

## Hypothesis
Compromised credentials may be abused through brute force, password spraying, or anomalous login patterns.

## Objective
Detect unusual sign-in behavior that indicates account compromise risk.

## Required Data Sources
- Identity provider logs (success/failure, IP, geolocation, MFA outcomes)
- VPN authentication logs
- Endpoint logon telemetry

## SIEM Query Examples
```kql
SigninLogs
| summarize Failed=countif(ResultType != 0), Success=countif(ResultType == 0), IPs=dcount(IPAddress)
    by UserPrincipalName, bin(TimeGenerated, 1h)
| where Failed > 20 or (Success > 0 and Failed > 10)
| order by TimeGenerated desc
```

## Expected Results
- Users with mistyped passwords
- Service account authentication noise
- Potential brute-force or spray attempts on exposed identities

## Investigation Steps
1. Validate source IP reputation and ASN type (residential, hosting, VPN).
2. Compare with user baseline behavior (geo/time/device).
3. Check for MFA prompt fatigue patterns.
4. Verify whether successful login followed repeated failures.
5. Trigger password reset/session revoke when needed.

## False Positive Guidance
- SSO outages causing repeated retries
- Misconfigured legacy clients
- Known vulnerability scanning ranges

## Escalation Criteria
- Multiple users targeted by same source with high failure rates.
- Successful authentication after sustained failures.
- Privileged account anomalies or impossible travel indicators.

## MITRE ATT&CK Mapping
- T1110 Brute Force
- T1078 Valid Accounts
- T1621 Multi-Factor Authentication Request Generation

## Tuning Notes
- Separate interactive users from service principals.
- Tune thresholds by business unit and login volume.
