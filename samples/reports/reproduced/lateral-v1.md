# Reproduced synthetic hunt: lateral

> Generated entirely from the committed synthetic CSV by
> `python scripts/render_reports.py`. Not a production incident.

- Result schema version: 1&#46;1
- Hunt: lateral
- Scope: synthetic offline telemetry&#59; no live SIEM execution
- Input events: **19**
- Review candidates: **2**
- Input SHA-256 (normalized UTF-8): 94d5f5da7457f5e4e51507808ff54df40fbe0ac43a2d6ddecc1a96e6fa239bb9
- Window: 10&#45;minute strictly ordered three&#45;event correlation
- Unique event IDs: **18**
- Duplicate event IDs suppressed: **1**

## Rule versions and effective parameters

```json
{
  "effective_parameters": {
    "LATERAL-REMOTE-EXECUTION": {
      "connection_detail": "tcp445",
      "execution_details": [
        "service",
        "wmi"
      ],
      "join_fields": [
        "SourceHost",
        "TargetHost",
        "AccountName on logon/execution"
      ],
      "logon_detail": "network",
      "max_chain_seconds": 600,
      "one_finding_per_execution": true,
      "strict_event_order": true
    }
  },
  "rule_versions": {
    "LATERAL-REMOTE-EXECUTION": "1.0.0"
  }
}
```

## Review candidates

| Candidate | Rule | Severity | Entity | First seen (UTC) | Last seen (UTC) | Evidence records | Disposition |
|---|---|---|---|---|---|---|---|
| 1 | LATERAL&#45;REMOTE&#45;EXECUTION | high | WKSTN&#45;A &#45;&#62; SRV&#45;FIN \| admin&#64;lab&#46;local | 2026&#45;04&#45;21T08&#58;00&#58;00Z | 2026&#45;04&#45;21T08&#58;04&#58;00Z | 2&#44; 3&#44; 4 | review required&#59; not confirmed compromise |
| 2 | LATERAL&#45;REMOTE&#45;EXECUTION | medium | LAPTOP&#45;77 &#45;&#62; SRV&#45;CRIT \| alice&#64;lab&#46;local | 2026&#45;04&#45;21T11&#58;00&#58;00Z | 2026&#45;04&#45;21T11&#58;06&#58;00Z | 11&#44; 12&#44; 15 | review required&#59; not confirmed compromise |

## Candidate rationale

Each row preserves one evaluated signal; candidate numbers refer to the table above.

| Candidate | Rule | Evaluated signal |
|---|---|---|
| 1 | LATERAL&#45;REMOTE&#45;EXECUTION | outbound TCP&#47;445 connection before target network logon |
| 1 | LATERAL&#45;REMOTE&#45;EXECUTION | successful remote execution&#58; service |
| 1 | LATERAL&#45;REMOTE&#45;EXECUTION | execution authorization &#40;synthetic annotation&#41;&#58; no |
| 1 | LATERAL&#45;REMOTE&#45;EXECUTION | joined by host pair and account&#44; not a verified remote session |
| 2 | LATERAL&#45;REMOTE&#45;EXECUTION | outbound TCP&#47;445 connection before target network logon |
| 2 | LATERAL&#45;REMOTE&#45;EXECUTION | successful remote execution&#58; wmi |
| 2 | LATERAL&#45;REMOTE&#45;EXECUTION | execution authorization &#40;synthetic annotation&#41;&#58; unknown |
| 2 | LATERAL&#45;REMOTE&#45;EXECUTION | joined by host pair and account&#44; not a verified remote session |

## Interpretation and limits

- These are deterministic **review candidates**, not a claim of compromise.
- Synthetic inputs use reserved example IP space and `@lab.local` identities.
- The Python evaluator is not a KQL execution engine; SIEM queries must be
  verified against the target platform's actual schema and live configuration.
- Offline fixture tests cannot establish real-world detection performance.
- Untrusted values are literal text. Control characters are preserved as
  numeric character references in the Markdown source; no raw command lines are included.


## Data-quality warnings

- None recorded for this synthetic input.
