# Network Hunt: Command-and-Control (C2) Candidates

> **Query status:** Column choices reviewed against Microsoft Defender XDR `DeviceNetworkEvents` documentation. Heuristic examples are not validated in a live tenant. **No C2 is proven** by these indicators alone.

## Hypothesis
Compromised endpoints may create repeated outbound connections to rare destinations on consistent schedules.

## Data prerequisites
- Defender for Endpoint `DeviceNetworkEvents` (requires active EDR sensor and suitable retention).
- Process and DNS context, approved endpoints, known update services, and maintenance calendar.
- For packet timing or application-layer metrics, use a separate Zeek/proxy/TLS sensor with its own schema.

## Query A: Connection interval consistency candidates

```kql
DeviceNetworkEvents
| where Timestamp >= ago(2d)
| where ActionType == "ConnectionSuccess"
| where isnotempty(RemoteIP)
| project Timestamp, DeviceName, RemoteIP, RemotePort
| order by DeviceName asc, RemoteIP asc, RemotePort asc, Timestamp asc
| serialize PreviousHost = prev(DeviceName), PreviousIP = prev(RemoteIP),
    PreviousPort = prev(RemotePort), PreviousTime = prev(Timestamp)
| where DeviceName == PreviousHost and RemoteIP == PreviousIP and RemotePort == PreviousPort
| extend IntervalSeconds = datetime_diff("second", Timestamp, PreviousTime)
| where IntervalSeconds between (30 .. 300)
| summarize IntervalSamples=count(), MeanSeconds=avg(IntervalSeconds),
    StdDevSeconds=stdev(IntervalSeconds) by DeviceName, RemoteIP, RemotePort
| where IntervalSamples >= 10 and StdDevSeconds <= MeanSeconds * 0.2
| order by IntervalSamples desc
```

**Caveats:** Missing events and grouped gaps bias the mean/variance. Short runs may be highly periodic for legitimate updaters. Validate the underlying individual connections.

## Query B: Rare destination pivot

```kql
DeviceNetworkEvents
| where Timestamp >= ago(7d)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType =~ "Public"
| summarize Connections=count(), Devices=dcount(DeviceName),
    FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by RemoteIP, RemotePort
| where Devices <= 2 and Connections between (2 .. 50)
| order by Connections asc
```

Rare does not imply malicious; common benign causes include SaaS apps, signed updates, and developer tools.

## Unsupported field warning
The documented `DeviceNetworkEvents` schema does **not** contain generic `JA3`/`JA3S`, `NetworkDuration`, `RequestBodySize`, or `ResponseBodySize` columns. Do not paste a query using those names into Defender XDR and represent it as validated. If your environment has a TLS/proxy sensor, document its table name, field mappings, and collection permissions separately.

## Investigation
1. Check sensor health and endpoint identity; exclude lab/test assets if applicable.
2. Enrich with initiating process, signer, DNS/domain, host criticality, and external IP ownership.
3. Inspect raw timing distribution (jitter, missing intervals, process restarts), not just aggregates.
4. Compare approved update/batch schedules; avoid treating a single suspicious metric as confirmation.
5. Escalate only with corroborating process activity, unauthorized egress, or C2 infrastructure evidence.

## MITRE ATT&CK
- [T1071 — Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
- [T1571 — Non-Standard Port](https://attack.mitre.org/techniques/T1571/)

## Reference
[Microsoft Defender DeviceNetworkEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table)
