# Threat Hunting Methodology (Portfolio Lab)

## Scope
This methodology supports portfolio demonstration and interview discussion. It is not a substitute for organization-specific incident response policy.

## Hunt lifecycle

### 1) Hypothesis
State a behavior-focused, testable hypothesis.

### 2) Telemetry readiness
Confirm required tables and fields are available before running hunts.

### 3) Initial detection pass
Run broad logic to identify candidate events.

### 4) Investigation and enrichment
Attach context: user role, host criticality, parent process lineage, destination risk, and change-control evidence.

### 5) Decisioning
Classify each candidate as:
- benign expected activity
- suspicious, monitor
- escalate for incident handling

### 6) Tuning
Reduce repeat noise with allowlists, entity baselines, and threshold/window adjustments.

### 7) Documentation
Record what was found, what was escalated, and what changed in the detection logic.

## Data quality checklist
Before trusting results:
- Timestamp normalization confirmed (UTC preferred)
- Key entity fields present (host/user/IP/process)
- Log gaps or ingestion delays noted
- Retention window sufficient for hunt objective

## Escalation philosophy
Escalate when multiple independent risk signals converge (for example: suspicious auth + remote execution + anomalous egress), or when impact potential is high even from a single signal on a critical asset.

## Portfolio integrity rules
- No fake client names or breach claims.
- No fabricated “production metrics” presented as real outcomes.
- Label synthetic examples clearly.
