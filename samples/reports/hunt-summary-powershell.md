# Completed Hunt Summary: Suspicious PowerShell (Lab Example)

## Hunt Window
2026-04-20 00:00 UTC to 2026-04-20 23:59 UTC

## Hypothesis Tested
Encoded or obfuscated PowerShell usage may indicate malicious execution.

## Result
- 17 total PowerShell events reviewed
- 2 events triaged as suspicious
- 1 escalated for deeper malware analysis in lab workflow

## Why Escalated
The escalated event combined encoded command usage, Office parent process, and outbound connection to rare destination.

## Follow-up Actions
- Add allowlist for known patch automation account.
- Tighten query to prioritize risky parent-child chains.

> This is a synthetic portfolio example, not a real production incident record.
