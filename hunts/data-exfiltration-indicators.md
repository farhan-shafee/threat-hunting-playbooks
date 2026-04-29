# Hunt Playbook: Data Exfiltration Indicators

## Hypothesis
Adversaries may exfiltrate data through large outbound transfers, unusual destinations, or covert channels.

## Objective
Detect outbound activity consistent with potential data theft.

## Required Data Sources
- Network flow/proxy logs (bytes sent/received, URL, destination IP)
- DNS query logs
- Endpoint file access and compression process telemetry

## SIEM Query Examples
```kql
DeviceNetworkEvents
| summarize BytesSent=sum(tolong(SentBytes)) by DeviceName, RemoteIP, RemoteUrl, bin(Timestamp, 1h)
| where BytesSent > 500000000
| order by BytesSent desc
```

## Expected Results
- Backup or sync jobs
- Software distribution traffic
- Potential anomalous high-volume outbound sessions

## Investigation Steps
1. Validate destination ownership/business purpose.
2. Check process responsible for outbound session.
3. Correlate with archive/encryption utilities on host.
4. Determine data classification exposure risk.
5. Contain endpoint if unauthorized transfer suspected.

## False Positive Guidance
- Approved cloud backup platforms
- Large patch/content delivery events
- Video/media business workflows

## Escalation Criteria
- High-volume transfer to unapproved or rare destinations.
- Compressed sensitive files staged before transfer.
- Repeated transfer pattern from same endpoint/account.

## MITRE ATT&CK Mapping
- T1041 Exfiltration Over C2 Channel
- T1567 Exfiltration to Cloud Storage
- T1071 Application Layer Protocol

## Tuning Notes
- Build per-host outbound baselines by day/time.
- Maintain allowlist of sanctioned cloud storage domains.
