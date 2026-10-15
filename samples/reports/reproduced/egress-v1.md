# Reproduced synthetic hunt: egress

> Generated entirely from the committed synthetic CSV by
> `python scripts/render_reports.py`. Not a production incident.

- Result schema version: 1&#46;1
- Hunt: egress
- Scope: synthetic offline telemetry&#59; no live SIEM execution
- Input events: **12**
- Review candidates: **2**
- Input SHA-256 (normalized UTF-8): 2ce3894c829b35861db17aea20f39fd2fc1a3d882f3d671a0bfea6f3124b4e95
- Window: 60&#45;minute rolling outbound byte total
- Unique event IDs: **11**
- Duplicate event IDs suppressed: **1**

## Rule versions and effective parameters

```json
{
  "effective_parameters": {
    "EGRESS-HIGH-VOLUME": {
      "approved_yes_suppressed": true,
      "cumulative_requires_first_observation_zero": true,
      "max_findings_per_host_destination_approval": 1,
      "minimum_bytes": 500000000,
      "requires_destination_class": "external",
      "requires_direction": "outbound",
      "window_inclusive": true,
      "window_seconds": 3600
    }
  },
  "rule_versions": {
    "EGRESS-HIGH-VOLUME": "1.0.0"
  }
}
```

## Review candidates

| Candidate | Rule | Severity | Entity | First seen (UTC) | Last seen (UTC) | Evidence records | Disposition |
|---|---|---|---|---|---|---|---|
| 1 | EGRESS&#45;HIGH&#45;VOLUME | high | SRC&#45;A &#45;&#62; 203&#46;0&#46;113&#46;50 | 2026&#45;04&#45;24T08&#58;00&#58;00Z | 2026&#45;04&#45;24T08&#58;10&#58;00Z | 2&#44; 3 | review required&#59; not confirmed compromise |
| 2 | EGRESS&#45;HIGH&#45;VOLUME | medium | SRC&#45;E &#45;&#62; 203&#46;0&#46;113&#46;11 | 2026&#45;04&#45;24T10&#58;00&#58;00Z | 2026&#45;04&#45;24T10&#58;10&#58;00Z | 8&#44; 9 | review required&#59; not confirmed compromise |

## Candidate rationale

Each row preserves one evaluated signal; candidate numbers refer to the table above.

| Candidate | Rule | Evaluated signal |
|---|---|---|
| 1 | EGRESS&#45;HIGH&#45;VOLUME | 520000000 observed outbound incremental bytes in rolling 60&#45;minute window |
| 1 | EGRESS&#45;HIGH&#45;VOLUME | external destination classification is a synthetic annotation |
| 1 | EGRESS&#45;HIGH&#45;VOLUME | transfer authorization &#40;synthetic annotation&#41;&#58; no |
| 1 | EGRESS&#45;HIGH&#45;VOLUME | cumulative contributions require prior observed counter values |
| 2 | EGRESS&#45;HIGH&#45;VOLUME | 600000000 observed outbound incremental bytes in rolling 60&#45;minute window |
| 2 | EGRESS&#45;HIGH&#45;VOLUME | external destination classification is a synthetic annotation |
| 2 | EGRESS&#45;HIGH&#45;VOLUME | transfer authorization &#40;synthetic annotation&#41;&#58; unknown |
| 2 | EGRESS&#45;HIGH&#45;VOLUME | cumulative contributions require prior observed counter values |

## Interpretation and limits

- These are deterministic **review candidates**, not a claim of compromise.
- Synthetic inputs use reserved example IP space and `@lab.local` identities.
- The Python evaluator is not a KQL execution engine; SIEM queries must be
  verified against the target platform's actual schema and live configuration.
- Offline fixture tests cannot establish real-world detection performance.
- Untrusted values are literal text. Control characters are preserved as
  numeric character references in the Markdown source; no raw command lines are included.


## Data-quality warnings

- cumulative session NO&#45;BASE missing zero baseline
- unquantified counter for session NO&#45;METRIC
