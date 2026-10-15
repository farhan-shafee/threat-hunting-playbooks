# Archived Illustrative Hunt Narrative: Authentication

> **Not reproduced from the included CSV.** This is a qualitative scenario sketch from the earlier portfolio iteration, not a completed incident or measured hunt. Do not cite event totals, user counts, blocked IPs, or investigative outcomes from it.

## Hypothesis
Repeated invalid-password events from one source may represent credential guessing or spray.

## Analyst approach
- Separate invalid-password results from MFA and other authentication codes.
- Count distinct affected identities over a defined window.
- Correlate individual failure sequences with successful logons.
- Validate known VPNs, sign-in outages, and approved testing.
- Escalate only when suspicious authentication has supporting evidence.

## Reproducible evidence
Use the [current input-backed authentication report](reproduced/auth-v1.md). That report is calculated from [synthetic CSV](../logs/auth-lab-v1.csv) with automated lineage and regression tests.
