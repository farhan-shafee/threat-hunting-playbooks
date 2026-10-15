# Reproduced synthetic hunt: auth

> Generated entirely from the committed synthetic CSV by
> `python scripts/render_reports.py`. Not a production incident.

- Result schema version: 1&#46;0
- Hunt: auth
- Scope: synthetic offline telemetry&#59; no live SIEM execution
- Input events: **15**
- Review candidates: **2**
- Input SHA-256 (normalized UTF-8): 99e5faf77e9309131ec3c080f622e90e1940b79497067ff8885003e5dbedefb8
- Window: 15 minutes

## Rule versions and effective parameters

```json
{
  "effective_parameters": {
    "AUTH-FAILED-THEN-SUCCESS": {
      "failure_result": "50126",
      "lookback_inclusive": true,
      "lookback_seconds": 900,
      "minimum_failures": 5,
      "other_outcomes": "reset_sequence",
      "success_result": "0",
      "temporal_order": "strictly_earlier",
      "timestamp_ties": "discard_failures_tied_with_success"
    },
    "AUTH-SPRAY": {
      "failure_result": "50126",
      "maximum_findings_per_ip": 1,
      "minimum_distinct_identities": 3,
      "minimum_failures": 6,
      "window_inclusive": true,
      "window_seconds": 900
    }
  },
  "rule_versions": {
    "AUTH-FAILED-THEN-SUCCESS": "1.1.0",
    "AUTH-SPRAY": "1.1.0"
  }
}
```

## Review candidates

| Candidate | Rule | Severity | Entity | First seen (UTC) | Last seen (UTC) | Evidence records | Disposition |
|---|---|---|---|---|---|---|---|
| 1 | AUTH&#45;SPRAY | medium | 198&#46;51&#46;100&#46;24 | 2026&#45;04&#45;20T08&#58;00&#58;00Z | 2026&#45;04&#45;20T08&#58;05&#58;00Z | 2&#44; 3&#44; 4&#44; 5&#44; 6&#44; 7 | review required&#59; not confirmed compromise |
| 2 | AUTH&#45;FAILED&#45;THEN&#45;SUCCESS | high | admin&#64;lab&#46;local \| 203&#46;0&#46;113&#46;44 | 2026&#45;04&#45;20T09&#58;00&#58;00Z | 2026&#45;04&#45;20T09&#58;05&#58;00Z | 8&#44; 9&#44; 10&#44; 11&#44; 12&#44; 13 | review required&#59; not confirmed compromise |

## Candidate rationale

Each row preserves one evaluated signal; candidate numbers refer to the table above.

| Candidate | Rule | Evaluated signal |
|---|---|---|
| 1 | AUTH&#45;SPRAY | 6 invalid&#45;password failures |
| 1 | AUTH&#45;SPRAY | 3 distinct identities within 15 minutes |
| 2 | AUTH&#45;FAILED&#45;THEN&#45;SUCCESS | 5 invalid&#45;password failures before success |
| 2 | AUTH&#45;FAILED&#45;THEN&#45;SUCCESS | same identity and source IP within 15 minutes |

## Interpretation and limits

- These are deterministic **review candidates**, not a claim of compromise.
- Synthetic inputs use reserved example IP space and `@lab.local` identities.
- The Python evaluator is not a KQL execution engine; SIEM queries must be
  verified against the target platform's actual schema and live configuration.
- Offline fixture tests cannot establish real-world detection performance.
- Untrusted values are literal text. Control characters are preserved as
  numeric character references in the Markdown source; no raw command lines are included.
