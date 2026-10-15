# Live Sentinel / Defender query execution gate

**Native Sentinel/Defender validation status: BLOCKED — no specified authorized Sentinel/XDR tenant with native security connectors.** Separately, Azure Data Explorer free-cluster *synthetic `datatable`* execution succeeded for seven queries; this is documented in [ADX_SYNTHETIC_EXECUTION.md](ADX_SYNTHETIC_EXECUTION.md) and is not a substitute for real security telemetry.

All seven source-reviewed KQL files pass syntax and curated-source-schema analysis with Microsoft's official Kusto.Language parser. **This is not enough to claim any query works in an actual Microsoft Sentinel or Defender XDR environment.**

## Minimum owner inputs

An authorized workspace owner must identify the target Microsoft product(s), tenant / workspace identifier and allowed read-only query scope. Do not paste access tokens, passwords, customer records or actual security incident data into this repository. A read-only user identity with the least necessary log/advanced-hunting permissions and appropriate data-retention controls is required.

No cloud provisioning, ingestion changes, Azure IAM modifications, detection-rule publishing or investigation/containment action is authorized by static code review.

## Execution sequence per query (authorized environment only)

1. Confirm deployment/product: Sentinel Log Analytics for `SigninLogs`, `AuditLogs` and `CommonSecurityLog`, or Defender XDR Advanced Hunting for `DeviceProcessEvents` and `DeviceRegistryEvents`. Tables can be absent if connectors/products are not deployed.
2. Confirm the actual table exists and required columns have the documented types in the target workspace. Prefer a **read-only metadata/schema check** in the product portal.
3. Establish a narrow allowed time range (for example the last hour for connectivity, then a bounded review window). Start with an aggregate row count, not unrestricted raw exports. Avoid production disclosure in shared screenshots.
4. Open one canonical source from `queries/schema-reviewed/`. Perform a service-side compile/run with an explicitly bounded time window. Record exact query SHA-256, UTC start/end, product, workspace identifier in private authorized records, permissions and any compile errors.
5. Inspect actual result fields and semantics. For auth, check event-ID dedup, error-code meaning and chronological order. For cloud, check exact operation variants and whether Result reports completion. For Defender, check ActionType/file-name population and process lineage. For CommonSecurityLog, verify direction, connector mapping, retransmissions, duplicates, delta versus cumulative bytes and routing.
6. Establish at least one independently reviewed synthetic/pilot positive, benign negative, timestamp-boundary and missing-field condition. If no matching events exist, label **no events observed**, not detection validated.
7. Re-run with only deidentified/approved evidence; retain count summaries, error categories and sanitized timestamps rather than sensitive raw account, host or IP data.
8. Require an analyst to review false positives and false negatives, tuning, change authorization, and any operator/tenant-specific behavior. Do **not** automatically promote a query to a live alert or initiate response actions.
9. Assign an explicit status: `PASS_TENANT_EXECUTED_WITH_EVIDENCE`, `FAIL_RUNTIME_OR_SEMANTICS`, `NO_DATA`, `NO_PERMISSION` or `NOT_RUN`. A successful no-result query proves only that execution succeeded, not the alert's sensitivity or usefulness.

## Traceability template

| Evidence field | Required entry |
|---|---|
| Canonical query name and SHA-256 | e.g. `auth-failure-success.kql` and digest |
| Vendor platform, environment and read-only permissions | Sentinel / Defender; sanitized workspace identity |
| Validation timestamp / UTC query window | Record actual dates, not just `ago(1d)` |
| Source schema and connector state | Present/absent, populated fields, data retention |
| Compile/execute outcome | Pass/fail, code, redacted error if any |
| Bounded result count and redacted evidence | No raw customer telemetry in public GitHub |
| Positive / negative / boundary expectations | Independent scenario definition and observed outcomes |
| Known incompleteness and query-to-Python parity differences | Explicit and documented |
| Review identity and disposition | Authorized security engineer / owner approval |
| Promotion decision | Static only, tenant executed, or pilot qualified — never infer from CI |

## Prioritized rollout

Start with `SigninLogs` invalid-password/failure-success and `DeviceProcessEvents` PowerShell command pivots because the offline lab already demonstrates those *related* concepts. Validate those service-side examples independently; **do not assume Python/KQL parity**. Next review Entra administrative changes and registry autoruns. Tackle lateral-movement multi-table joins and network transfer byte-accounting only after the necessary sensor/connector provenance exists. The current read-only lateral and egress KQL files remain *narrow pivots*, not implementation of the offline chain or interval-based detector.

**Current acceptance:** No actual tenant execution or quantitative sensitivity metrics. Await explicit owner-selected workspace/product and authorization before any live queries.
