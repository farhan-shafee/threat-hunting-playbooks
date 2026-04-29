# Completed Hunt Summary: Lateral Movement (Lab Example)

## Hunt Window
2026-04-22 00:00 UTC to 2026-04-22 23:59 UTC

## Hypothesis Tested
If a compromised account is used for internal pivoting, remote execution artifacts and unusual host-to-host administration patterns should co-occur.

## Findings
- 9 remote execution candidates from hunt query
- 7 matched approved maintenance activity
- 2 remained suspicious pending credential validation

## Analyst Decision
Escalated 2 events because they originated from a non-standard admin workstation and targeted a privileged server segment.

## Tuning Changes
- Added approved jump host allowlist.
- Added suppression for scheduled patching maintenance window.

> Synthetic portfolio record for demonstration only.
