# Phase 2 — Four Additional Offline Evidence Hunts

**Status:** Synthetic-only execution implemented. This document specifies the four *normalized teaching schemas* consumed by `huntlab/extended.py`. None of these CSV formats is a native Sentinel, Defender, AWS CloudTrail, Windows Event Log, Zeek, or firewall schema.

## Common event and evidence contract

Each fixture is UTF-8 CSV with `Timestamp` (timezone-aware ISO-8601), a nonempty `EventId`, and the fields listed below. Parsing is strict, timestamps normalize to UTC, and inputs are limited to 5,000,000 bytes / 20,000 records. Headers cannot be duplicated, and every row must have the declared number of fields. Fields used by a rule have additional enum and numeric constraints.

Each `EventId` is a **synthetic source-event identity**:
- Repeated IDs with *identical fields* are suppressed once and counted in `duplicate_events_suppressed`.
- Repeated IDs with *different fields* reject the entire input as ambiguous.
- Evidence ordinals point back to the original CSV records; ordinal numbers can change if the fixture order changes.
- Input SHA-256 is normalized UTF-8 source integrity **only**; no evidentiary chain of custody or signing is claimed.

Report schema `1.1` adds `events_unique`, `duplicate_events_suppressed`, and `data_quality_warnings` for these four hunts. Their rule versions start at `1.0.0`. Phase 1 `auth`/`powershell` remain at their previously published schema and rule versions; their fixture hashes, outputs, and logic are unchanged.

For an offline analyst handoff, candidates provide rule, priority, entity, first/last UTC timestamps, evidence-record ordinals, rule parameters, source hash, and `review required; not confirmed compromise`. An incident-response owner must separately confirm source integrity, real-world authorization, severity, and actions.

## 1. Lateral movement — `--hunt lateral`

**Hypothesis:** A source host's TCP/445 connection followed by a network logon on a target and a remote service/WMI execution in a ten-minute window may warrant lateral-movement investigation.

Columns:

| Field | Synthetic contract |
|---|---|
| `Timestamp`, `EventId` | Time and source-event identity |
| `EventType` | `connection`, `logon`, or `execution` |
| `SourceHost`, `TargetHost` | Distinct, nonempty endpoint names; exact host-pair correlation ignoring case |
| `AccountName` | Actor on logon/execution, `-` on connection; matching actor required |
| `Outcome` | `success`, `denied`, `pending` |
| `Detail` | Connection `tcp445`/`other`; logon `network`/`remote_interactive`/`other`; execution `service`/`wmi`/`other` |
| `Approved` | Human-supplied synthetic annotation `yes`/`no`/`unknown` |

**Rule:** `LATERAL-REMOTE-EXECUTION` requires successful `tcp445` connection then successful `network` logon then successful `service` or `wmi` execution on the **same host pair**, with the **same actor on logon/execution**, and strictly increasing timestamps. Total chain duration must be at most 600 seconds (inclusive). Unauthorized (`no`) execution is a *high-priority candidate*; unknown authorization is *medium*. `yes` is suppressed.

**Conservatism:** Simultaneous events are evaluated as a group. Same-timestamp connection/logon/execution records never establish order from CSV position. Ambiguous or failed logons invalidate stale logon joins. Missing an entire connection, logon, or execution class adds a warning; having all three classes in the file does **not** guarantee complete coverage for every asset.

**Blind spots:** Native sensors usually do not provide the complete cross-source identity implied by this normalized fixture. A host-pair/account join **cannot prove a specific remote session**, command execution attribution, credential theft, malicious intent, or origin of the actor. NAT, name collisions, shared identities, incomplete telemetry, administrative tooling, and delayed ingestion can defeat or confuse the heuristic. No actual SMB-share or service-creation KQL is evaluated.

ATT&CK investigation context: T1021.002 (SMB/Windows Admin Shares), T1569.002 (Service Execution), T1047 (Windows Management Instrumentation). This is **not** tested coverage of all those techniques.

## 2. Persistence — `--hunt persistence`

**Hypothesis:** Unapproved autorun/task/service changes or recreation of a deleted artifact may indicate persistence that merits analyst triage.

Columns: `Timestamp`, `EventId`, `Host`, `Actor`, `ArtifactType` (`run_key`, `scheduled_task`, `service`), `ArtifactPath`, `Action` (`created`, `modified`, `deleted`), `Executable`, `SignerStatus` (`signed`, `unsigned`, `unknown`), `Approved`.

- `PERSIST-UNAPPROVED-ENTRY`: each creation or modification with `Approved=no` is a candidate. An **unsigned** executable raises priority to high; signed/unknown still require review at medium. A signature is not authorization or benignity proof.
- `PERSIST-RECREATION`: deletion followed by a creation or modification of the same case-insensitive host, artifact type, and path, with `Approved=no`, strictly later and within 3600 seconds. High priority; both event ordinals retained. One recreation finding is emitted per deletion.
- Approved and unknown-approval entries do not assert an **unapproved entry** in this particular rule; deletion alone is not an alert. `-` executable is allowed for deletion only.

**Blind spots:** Registry paths, task actions, true process identity, signature validation, and service control state are annotations. An attacker could persist through mechanisms outside these three families or with signed binaries. No real registry or scheduled-task action is performed.

ATT&CK investigative context: T1547.001 (Registry Run Keys/Startup Folder), T1053.005 (Scheduled Task), T1543.003 (Windows Service).

## 3. Cloud control-plane changes — `--hunt cloud`

**Hypothesis:** Completed and unapproved changes granting privileged identities/apps, or creation of credentials, are higher-signal investigation candidates than pending or denied changes.

Columns: `Timestamp`, `EventId`, `Provider` (`aws`, `entra`), `Actor`, `Target`, `Operation`, `Outcome` (`success`, `denied`, `pending`), `Approved`, `Scope`.

Supported normalized operation names: `role_grant`, `app_consent`, `policy_admin_grant`, `pim_activation`, `pim_request`, `access_key_create`, `read_resource`. Entra-only PIM/consent and AWS-only policy/key operations enforce provider consistency. Privileged scopes: `admin`, `global_admin`, `owner`, `privileged_app` (not `read_only` or `standard`).

- `CLOUD-UNAPPROVED-ADMIN-GRANT`: `Approved=no` + `Outcome=success` + privileged scope + role grant, app consent, admin policy grant, or PIM activation → high.
- `CLOUD-UNAPPROVED-ACCESS-KEY`: `aws` key creation, `Approved=no` and `Outcome=success` → medium.
- Denied operations, pending grants, and mere PIM *requests* are not treated as completed grants. Authorized or unknown-approval activities are not classified as unauthorized in these two rules.

**Blind spots:** Native audit operation names and permission schemas differ by vendor/tenant, and `success` cannot establish token compromise, effective permissions after propagation, or subsequent key abuse. `Approved=no` requires a real change-control source in future integrations. There are no credentials, cloud API calls, or automatic IAM changes.

ATT&CK context: T1098 Account Manipulation; T1078.004 Valid Accounts (Cloud Accounts) only if further activity supports it.

## 4. Network egress — `--hunt egress`

**Hypothesis:** A large outbound byte total to an externally classified destination within a rolling hour merits analyst review when authorization is unconfirmed or denied.

Columns: `Timestamp`, `EventId`, `SourceHost`, `DestinationIP` (parsable IPv4/IPv6), `SessionId`, `Direction` (`outbound`/`inbound`), `DestinationClass` (`external`/`internal`/`unknown`), `CounterMode` (`delta`/`cumulative`/`unknown`), `Bytes`, `Approved`.

`EGRESS-HIGH-VOLUME` aggregates **at least 500,000,000 observed bytes** in an inclusive 3600-second rolling window per case-insensitive source host, destination IP, and approval class. The decision requires `Direction=outbound`, `DestinationClass=external` and `Approved != yes`. A synthetic `no` is high-priority; `unknown` is medium. One candidate per host/destination/approval group avoids repeated threshold alerts.

**Byte accounting contract:**
- `delta` means the number of transmitted bytes **since the previous logged sample** for that session; values are added directly.
- `cumulative` requires its first event in that session to have a **zero** counter baseline. Contributions equal successive nonnegative differences. Both prior and current sample ordinals are included in evidence.
- A nonzero first cumulative value, a counter decrease/reset, or `CounterMode=unknown` yields a **data-quality warning** and excludes the entire ambiguous session rather than quietly asserting a byte count.
- Each session (source + IP + session ID) must have consistent mode, direction, destination class and approval annotation; mixed definitions fail the input.
- Duplicate `EventId` records are suppressed before any summation. Internal, inbound, and approved transfers are negative controls.

**Blind spots:** `DestinationClass=external` and `Approved=no` are **synthetic annotations**, not global-routability or permission proofs. Fixture IPs intentionally use documentation ranges; thus global routability checks would be wrong for this lab. NAT/proxy metadata, direction semantics, partial sessions, duplicated sensors, retransmission accounting, encrypted payload context, content classification, session-ID collisions, and missing counters remain major real-world issues. High volume does **not** prove exfiltration or C2.

Potential ATT&CK *hypotheses* (not validated detection coverage): T1041 and T1567 only when further destination, protocol and data evidence corroborate exfiltration.

## Reproduction gates

```bash
python -B scripts/demo_hunts.py
python -B -m unittest discover -s tests -v
python -B scripts/render_reports.py --check
python -B scripts/validate_playbooks.py
```

The independently authored `tests/expected/phase2-v1.json` lists exact candidate rules, entities, severity, UTC bounds and source-record ordinals, plus signal excerpts. Test code independently hashes fixtures; this manifest is *not generated by the evaluator*. New tests assert authorized/benign controls, missing sensor evidence, malformed schemas, duplicate/conflicting IDs, equal timestamps, strict ordering, inclusive/exclusive time boundaries, cumulative counter resets, and byte-sum conservation.

**Promotion criterion:** validate the corresponding *separate* KQL against an authorized platform and documented real source schema, capture redacted execution evidence and independent expected events, verify permissions/retention/sensor coverage, and report measured limitations. Until then, this remains a **synthetic offline project** and a portfolio demonstration—not a live detection service.
