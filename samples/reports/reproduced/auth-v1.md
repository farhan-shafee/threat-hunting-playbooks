# Reproduced synthetic hunt: auth

> Generated entirely from the committed synthetic CSV by
> `python scripts/render_reports.py`. Not a production incident.

- Hunt: `auth`
- Input events: **15**
- Review candidates: **2**
- Input SHA-256 (normalized UTF-8): `99e5faf77e9309131ec3c080f622e90e1940b79497067ff8885003e5dbedefb8`
- Window: 15 minutes

## Review candidates

| Rule | Severity | Entity | First seen (UTC) | Evidence records |
|---|---|---|---|---|
| AUTH-SPRAY | medium | 198.51.100.24 | 2026-04-20T08:00:00Z | 2, 3, 4, 5, 6, 7 |
| AUTH-FAILED-THEN-SUCCESS | high | admin@lab.local \| 203.0.113.44 | 2026-04-20T09:00:00Z | 8, 9, 10, 11, 12, 13 |

## Interpretation and limits

- These are deterministic **review candidates**, not a claim of compromise.
- Synthetic inputs use reserved example IP space and `@lab.local` identities.
- The Python evaluator is not a KQL execution engine; SIEM queries must be
  verified against the target platform's actual schema and live configuration.
- Offline fixture tests cannot establish real-world detection performance.
