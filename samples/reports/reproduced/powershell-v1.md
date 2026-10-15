# Reproduced synthetic hunt: powershell

> Generated entirely from the committed synthetic CSV by
> `python scripts/render_reports.py`. Not a production incident.

- Hunt: `powershell`
- Input events: **6**
- Review candidates: **3**
- Input SHA-256 (normalized UTF-8): `51039dfadf48eefd0272dc8a169a1333757ffacbce0ef47e52d71b1139d341e9`
- Window: per process event

## Review candidates

| Rule | Severity | Entity | First seen (UTC) | Evidence records |
|---|---|---|---|---|
| PS-SUSPICIOUS-EXECUTION | high | WKSTN-22 \| jdoe | 2026-04-20T10:21:00Z | 2 |
| PS-SUSPICIOUS-EXECUTION | high | WKSTN-31 \| analyst | 2026-04-20T10:30:00Z | 5 |
| PS-SUSPICIOUS-EXECUTION | medium | SRV-07 \| svc_patch | 2026-04-20T10:32:00Z | 7 |

## Interpretation and limits

- These are deterministic **review candidates**, not a claim of compromise.
- Synthetic inputs use reserved example IP space and `@lab.local` identities.
- The Python evaluator is not a KQL execution engine; SIEM queries must be
  verified against the target platform's actual schema and live configuration.
- Offline fixture tests cannot establish real-world detection performance.
