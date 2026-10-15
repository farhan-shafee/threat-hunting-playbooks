# Reproduced synthetic hunt: persistence

> Generated entirely from the committed synthetic CSV by
> `python scripts/render_reports.py`. Not a production incident.

- Result schema version: 1&#46;1
- Hunt: persistence
- Scope: synthetic offline telemetry&#59; no live SIEM execution
- Input events: **9**
- Review candidates: **5**
- Input SHA-256 (normalized UTF-8): 0f1ecf1b9e35386b9234fede895dd406e63ff1d714347e82682abccbc6546190
- Window: event review&#59; 60&#45;minute deletion&#47;recreation
- Unique event IDs: **8**
- Duplicate event IDs suppressed: **1**

## Rule versions and effective parameters

```json
{
  "effective_parameters": {
    "PERSIST-RECREATION": {
      "delete_then_create_seconds": 3600,
      "deletion_consumed_by": "first strictly later update group",
      "match_fields": [
        "Host",
        "ArtifactType",
        "ArtifactPath"
      ],
      "requires_approved": "no",
      "simultaneous_updates": "one candidate with all later unapproved changes",
      "strict_event_order": true,
      "tie_policy": "simultaneous; cannot establish temporal order"
    },
    "PERSIST-UNAPPROVED-ENTRY": {
      "actions": [
        "created",
        "modified"
      ],
      "artifact_types": [
        "run_key",
        "scheduled_task",
        "service"
      ],
      "other_signer_priority": "medium",
      "requires_approved": "no",
      "unsigned_priority": "high"
    }
  },
  "rule_versions": {
    "PERSIST-RECREATION": "1.0.1",
    "PERSIST-UNAPPROVED-ENTRY": "1.0.0"
  }
}
```

## Review candidates

| Candidate | Rule | Severity | Entity | First seen (UTC) | Last seen (UTC) | Evidence records | Disposition |
|---|---|---|---|---|---|---|---|
| 1 | PERSIST&#45;UNAPPROVED&#45;ENTRY | high | WKSTN&#45;22 \| run&#95;key \| HKCU&#92;Software&#92;Microsoft&#92;Windows&#92;CurrentVersion&#92;Run&#92;Updater | 2026&#45;04&#45;22T08&#58;00&#58;00Z | 2026&#45;04&#45;22T08&#58;00&#58;00Z | 2 | review required&#59; not confirmed compromise |
| 2 | PERSIST&#45;UNAPPROVED&#45;ENTRY | medium | SRV&#45;ADMIN \| service \| ExampleService | 2026&#45;04&#45;22T08&#58;06&#58;00Z | 2026&#45;04&#45;22T08&#58;06&#58;00Z | 4 | review required&#59; not confirmed compromise |
| 3 | PERSIST&#45;RECREATION | high | WKSTN&#45;22 \| run&#95;key \| HKCU&#92;Software&#92;Lab&#92;Unwanted | 2026&#45;04&#45;22T09&#58;00&#58;00Z | 2026&#45;04&#45;22T09&#58;05&#58;00Z | 5&#44; 6 | review required&#59; not confirmed compromise |
| 4 | PERSIST&#45;UNAPPROVED&#45;ENTRY | high | WKSTN&#45;22 \| run&#95;key \| HKCU&#92;Software&#92;Lab&#92;Unwanted | 2026&#45;04&#45;22T09&#58;05&#58;00Z | 2026&#45;04&#45;22T09&#58;05&#58;00Z | 6 | review required&#59; not confirmed compromise |
| 5 | PERSIST&#45;UNAPPROVED&#45;ENTRY | medium | SRV&#45;OLD \| scheduled&#95;task \| &#92;Tasks&#92;Legacy | 2026&#45;04&#45;22T11&#58;01&#58;00Z | 2026&#45;04&#45;22T11&#58;01&#58;00Z | 8 | review required&#59; not confirmed compromise |

## Candidate rationale

Each row preserves one evaluated signal; candidate numbers refer to the table above.

| Candidate | Rule | Evaluated signal |
|---|---|---|
| 1 | PERSIST&#45;UNAPPROVED&#45;ENTRY | artifact created&#59; executable&#58; C&#58;&#92;Users&#92;analyst&#92;AppData&#92;Local&#92;temp&#46;exe |
| 1 | PERSIST&#45;UNAPPROVED&#45;ENTRY | signer metadata&#58; unsigned |
| 1 | PERSIST&#45;UNAPPROVED&#45;ENTRY | approval&#61;no is a synthetic annotation&#44; not source verification |
| 2 | PERSIST&#45;UNAPPROVED&#45;ENTRY | artifact modified&#59; executable&#58; C&#58;&#92;ProgramData&#92;agent&#46;exe |
| 2 | PERSIST&#45;UNAPPROVED&#45;ENTRY | signer metadata&#58; signed |
| 2 | PERSIST&#45;UNAPPROVED&#45;ENTRY | approval&#61;no is a synthetic annotation&#44; not source verification |
| 3 | PERSIST&#45;RECREATION | same artifact path deleted and recreated within 60 minutes |
| 3 | PERSIST&#45;RECREATION | recreation approval&#61;no &#40;synthetic annotation&#41; |
| 4 | PERSIST&#45;UNAPPROVED&#45;ENTRY | artifact created&#59; executable&#58; C&#58;&#92;Users&#92;analyst&#92;recreate&#46;exe |
| 4 | PERSIST&#45;UNAPPROVED&#45;ENTRY | signer metadata&#58; unsigned |
| 4 | PERSIST&#45;UNAPPROVED&#45;ENTRY | approval&#61;no is a synthetic annotation&#44; not source verification |
| 5 | PERSIST&#45;UNAPPROVED&#45;ENTRY | artifact created&#59; executable&#58; C&#58;&#92;Windows&#92;System32&#92;legit&#46;exe |
| 5 | PERSIST&#45;UNAPPROVED&#45;ENTRY | signer metadata&#58; signed |
| 5 | PERSIST&#45;UNAPPROVED&#45;ENTRY | approval&#61;no is a synthetic annotation&#44; not source verification |

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
