# Archived Illustrative Hunt Narrative: PowerShell

> **Not reproduced from the old `powershell-sample.csv`.** Prior narrative counts and escalation claims are not supported by a matching fixture and should not be presented as measured outcomes.

## Hypothesis
Encoded PowerShell launched by an unusual parent can indicate suspicious execution, but the same signals can occur in legitimate tooling.

## Analyst approach
- Examine parent-child process context, command-line indicators, and authorized scripts.
- Use a benign service automation control to challenge the heuristic.
- Correlate endpoint network/file telemetry before concluding malicious activity.
- Document the threshold and reason for manual review.

## Reproducible evidence
Use the [current PowerShell synthetic case report](reproduced/powershell-v1.md), created from [fixture data](../logs/powershell-lab-v1.csv) by the tested offline evaluator.
