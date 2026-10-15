# Illustrative Hunt Narrative: Lateral Movement

> **Not a completed or reproducible hunt.** This qualitative example has no corresponding fixture or executable evaluator in this repository. It does not assert that real hosts, incidents, or investigations were involved.

## Hypothesis
Unexpected remote administration from a workstation to sensitive assets may indicate unauthorized lateral movement.

## Analyst approach
- Verify the source and destination pair against approved administrative workflows.
- Correlate remote logons, service/task creation, and process lineage.
- Distinguish scheduled deployment tooling from unauthorized command execution.
- Preserve UTC timestamps, identity context, and source evidence before escalation.

## Reproducibility gap
This case awaits an explicitly documented synthetic network + host-auth + process fixture, reproducible correlation logic, and positive/negative tests. See [engineering roadmap](../../docs/engineering-audit.md).
