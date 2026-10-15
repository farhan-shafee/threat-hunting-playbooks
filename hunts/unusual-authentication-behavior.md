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

> **Status: Microsoft vendor-schema-reviewed static candidates, NOT executed in an authorized Sentinel/Defender tenant.**
> These are not claimed equivalent to the synthetic Python detectors.

### Ordered invalid-password failures followed by interactive success

Source: [`queries/schema-reviewed/auth-failure-success.kql`](../queries/schema-reviewed/auth-failure-success.kql). Native table: `SigninLogs`.

```kql
// SENTINEL / SigninLogs: strictly earlier interactive invalid-password failures
// followed by a success for the same user and source IP. Read-only candidate.
// NOT equivalent to the offline Python reset-state detector.
let Logins =
    SigninLogs
    | where TimeGenerated >= ago(2d)
    | where IsInteractive == true
    | where isnotempty(Id) and isnotempty(UserPrincipalName) and isnotempty(IPAddress)
    | extend UserKey = tolower(UserPrincipalName), Outcome = tostring(ResultType)
    | where Outcome in ("50126", "0")
    | project Id, EventTime = TimeGenerated, UserKey, IPAddress, Outcome
    | summarize arg_max(EventTime, *) by Id;
let Failed =
    Logins
    | where Outcome == "50126"
    | project UserKey, IPAddress, FailureTime = EventTime, FailureId = Id;
let Successful =
    Logins
    | where Outcome == "0" and EventTime >= ago(1d)
    | project UserKey, IPAddress, SuccessTime = EventTime, SuccessId = Id;
Successful
| join kind=inner (Failed) on UserKey, IPAddress
| where FailureTime < SuccessTime and FailureTime >= SuccessTime - 15m
| summarize FailureCount = count(), FirstFailure = min(FailureTime),
    LastFailure = max(FailureTime), FailureIds = make_set(FailureId, 32)
    by UserKey, IPAddress, SuccessTime, SuccessId
| where FailureCount >= 5
| project SuccessTime, UserKey, IPAddress, FailureCount, FirstFailure,
    LastFailure, SuccessId, FailureIds
| order by SuccessTime desc
```

**Important limitation:** Does not model offline identity reset on other outcomes; join can be expensive.

### Fixed-bin multi-user password-spray candidate

Source: [`queries/schema-reviewed/auth-spray.kql`](../queries/schema-reviewed/auth-spray.kql). Native table: `SigninLogs`.

```kql
// SENTINEL / SigninLogs: fixed 15-minute BIN password-spray candidate.
// Bin boundary misses are possible; this is NOT a sliding 15-minute window.
// Only ResultType=50126 is counted; service-principal sign-ins are excluded.
SigninLogs
| where TimeGenerated >= ago(1d)
| where IsInteractive == true
| where tostring(ResultType) == "50126"
| where isnotempty(Id) and isnotempty(UserPrincipalName) and isnotempty(IPAddress)
| project EventTime = TimeGenerated, SigninId = Id,
    UserKey = tolower(UserPrincipalName), IPAddress
| summarize arg_max(EventTime, *) by SigninId
| summarize FailureEvents = count(), DistinctUsers = count_distinct(UserKey),
    FirstSeen = min(EventTime), LastSeen = max(EventTime),
    SampleIds = make_set(SigninId, 32)
    by IPAddress, WindowStart = bin(EventTime, 15m)
| where FailureEvents >= 6 and DistinctUsers >= 3
| project WindowStart, IPAddress, FailureEvents, DistinctUsers,
    FirstSeen, LastSeen, SampleIds
| order by WindowStart desc
```

**Important limitation:** Fixed time bins can miss boundary-straddling patterns; not equivalent to sliding offline rule.

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
