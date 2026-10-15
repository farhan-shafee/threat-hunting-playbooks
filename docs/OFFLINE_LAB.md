# Offline Threat-Hunting Evidence Lab

This is a **deterministic, synthetic-only teaching exercise**. It supports review of selected indicator logic without SIEM credentials or a paid service. It does not parse KQL and cannot validate queries in the historical playbooks.

## Architecture

```text
samples/logs/*-lab-v1.csv
          |
          v
  huntlab.engine.load_csv
  - strict UTF-8 CSV
  - header/required-field checks
  - timezone-aware timestamps -> UTC
  - bounded bytes and records
  - normalized input SHA-256
          |
          v
  huntlab.engine.run_hunt
  - authentication state / sliding time window
  - PowerShell command/parent triage
          |
          v
  Deterministic JSON review candidates
          |
          v
  scripts/render_reports.py
  -> samples/reports/reproduced/*.md
          |
          v
  CI verifies committed reports match
```

## Input contracts

### `auth`

Required CSV columns:
- `TimeGenerated`: timezone-aware ISO-8601 datetime (UTC `Z` or explicit offset)
- `UserPrincipalName`: non-empty identity
- `IPAddress`: non-empty string; IP address syntax is not verified in v1
- `ResultType`: numeric string; `0` success and `50126` invalid credentials

Unknown result codes are not assumed to mean incorrect passwords. `50140` or `50074` do not count toward the failure thresholds. The evaluator sorts events chronologically and retains CSV record ordinals for reproducibility.

### `powershell`

Required columns: `Timestamp`, `DeviceName`, `AccountName`, `FileName`, `ProcessCommandLine` and `InitiatingProcessFileName`.

`FileName` must be exactly `powershell.exe` or `pwsh.exe`, case-insensitive. This is a simple allowlisted executable-name comparison, not signed binary identity verification.

### Parser protections

Input must be nonempty UTF-8 CSV, with unique headers, nonempty required fields, no malformed records, no missing timezone, at most 20,000 records and at most 5,000,000 bytes. Normalize CRLF to LF and remove the UTF-8 BOM before hashing. **The SHA-256 describes the normalized bytes, not a canonicalized security event stream or signed chain of custody.**

The evaluator reads local files and does not make network requests, use credentials, launch payloads, download malware, block IPs, or isolate endpoints.

## Rules: exact evaluated semantics

| Rule ID | Required conditions | Report priority |
|---|---|---|
| `AUTH-FAILED-THEN-SUCCESS` | At least 5 `50126` failures for the **same user and IP**, then `0` success; failures are at most 15 minutes before success; another outcome for that pair breaks sequence | High |
| `AUTH-SPRAY` | 6+ `50126` failures for one IP over a 15-minute sliding window, targeting at least 3 distinct identities; one review candidate per source IP | Medium |
| `PS-SUSPICIOUS-EXECUTION` | PowerShell/pwsh event contains an `-enc`/`-encodedcommand` flag or one of several bounded text indicators (`frombase64string`, `invoke-expression`, `iex(`, `downloadstring(`) | Medium; High with Office/script-host parent |

The PowerShell parent names checked are `winword.exe`, `excel.exe`, `outlook.exe`, `wscript.exe`, `cscript.exe` and `mshta.exe`, ignoring letter case.

**Severity is triage priority, not a verified incident severity.** One event can warrant analyst review without establishing compromise. The scripts do not decode or execute encoded scripts, fetch live enrichment, verify binaries, or decide containment.

## Run and verify

From the repository root:

```bash
python scripts/run_hunt.py --hunt auth --input samples/logs/auth-lab-v1.csv
python scripts/run_hunt.py --hunt powershell --input samples/logs/powershell-lab-v1.csv

python scripts/render_reports.py
python scripts/render_reports.py --check
python -m unittest discover -s tests -v
python scripts/validate_playbooks.py
```

For local integration, optionally add `--output out.json` to the runner. Its parent directory must exist.

Committed `*-lab-v1.csv` files are the sources for generated evidence reports. Additional `*-fixture-v1.csv` files support a second set of regression expectations, including negative cases and priority differences.

## Known blind spots and non-claims

1. No tenant or provider schema validation; offline evaluator results **do not prove** anything about `SigninLogs`, `DeviceProcessEvents` or other historical query examples.
2. Simple string matching can be bypassed by alternate command syntax, paths, Unicode tricks, escaped tokens, encoded command variations and process masquerading.
3. There is no ingestion-delay model, session correlation across IPs, successful MFA state, trusted-device state, detection baselining, external reputation or false-positive calibration.
4. The fixed thresholds are not optimized on real-world population distributions. No precision/recall, detection rate, SOC service-level objective or organizational risk score is claimed.
5. The tests use intentionally synthetic sources and documentation IP blocks (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
6. Historical narrative summaries in the original repository are not generated from these inputs. They remain **illustrative**, not evidence of executed historical hunts.
7. CLI input is untrusted local data. Do not submit private log files to a public repository or publish sensitive input paths.

## Investigation handoff

Each candidate provides: rule, entity, timestamp range, input record ordinals, matched signals and the mandatory `review required` disposition. A human analyst should enrich the event, check approved administrative activity and validate telemetry health before concluding a security incident.

To demonstrate end-to-end SIEM hunts in a later milestone, choose one platform (for example, Microsoft Defender XDR), verify its table/field reference, create authorized lab telemetry, test KQL in that platform, capture execution evidence and assert parity with independently reviewed expectations. Never imply that local Python assertions performed that integration test.
