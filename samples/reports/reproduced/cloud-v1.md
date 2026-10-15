# Reproduced synthetic hunt: cloud

> Generated entirely from the committed synthetic CSV by
> `python scripts/render_reports.py`. Not a production incident.

- Result schema version: 1&#46;1
- Hunt: cloud
- Scope: synthetic offline telemetry&#59; no live SIEM execution
- Input events: **11**
- Review candidates: **4**
- Input SHA-256 (normalized UTF-8): 5bd2899396199c7e67730c86d27ed2d3721d3acfbb5b67c3b889078a75b26382
- Window: per successful change event
- Unique event IDs: **10**
- Duplicate event IDs suppressed: **1**

## Rule versions and effective parameters

```json
{
  "effective_parameters": {
    "CLOUD-UNAPPROVED-ACCESS-KEY": {
      "operation": "access_key_create",
      "required_outcome": "success",
      "requires_approved": "no"
    },
    "CLOUD-UNAPPROVED-ADMIN-GRANT": {
      "operations": [
        "role_grant",
        "app_consent",
        "policy_admin_grant",
        "pim_activation"
      ],
      "privileged_scopes": [
        "admin",
        "global_admin",
        "owner",
        "privileged_app"
      ],
      "required_outcome": "success",
      "requires_approved": "no"
    }
  },
  "rule_versions": {
    "CLOUD-UNAPPROVED-ACCESS-KEY": "1.0.0",
    "CLOUD-UNAPPROVED-ADMIN-GRANT": "1.0.0"
  }
}
```

## Review candidates

| Candidate | Rule | Severity | Entity | First seen (UTC) | Last seen (UTC) | Evidence records | Disposition |
|---|---|---|---|---|---|---|---|
| 1 | CLOUD&#45;UNAPPROVED&#45;ADMIN&#45;GRANT | high | entra \| role&#45;example&#45;1 \| admin&#64;lab&#46;local | 2026&#45;04&#45;23T08&#58;00&#58;00Z | 2026&#45;04&#45;23T08&#58;00&#58;00Z | 2 | review required&#59; not confirmed compromise |
| 2 | CLOUD&#45;UNAPPROVED&#45;ACCESS&#45;KEY | medium | aws \| access&#45;key&#45;example \| svc&#45;ci&#64;lab&#46;local | 2026&#45;04&#45;23T08&#58;05&#58;00Z | 2026&#45;04&#45;23T08&#58;05&#58;00Z | 3 | review required&#59; not confirmed compromise |
| 3 | CLOUD&#45;UNAPPROVED&#45;ADMIN&#45;GRANT | high | entra \| unapproved&#45;app \| operator&#64;lab&#46;local | 2026&#45;04&#45;23T08&#58;15&#58;00Z | 2026&#45;04&#45;23T08&#58;15&#58;00Z | 8 | review required&#59; not confirmed compromise |
| 4 | CLOUD&#45;UNAPPROVED&#45;ADMIN&#45;GRANT | high | entra \| pim&#45;role&#45;example \| operator&#64;lab&#46;local | 2026&#45;04&#45;23T08&#58;25&#58;00Z | 2026&#45;04&#45;23T08&#58;25&#58;00Z | 10 | review required&#59; not confirmed compromise |

## Candidate rationale

Each row preserves one evaluated signal; candidate numbers refer to the table above.

| Candidate | Rule | Evaluated signal |
|---|---|---|
| 1 | CLOUD&#45;UNAPPROVED&#45;ADMIN&#45;GRANT | successful role&#95;grant with global&#95;admin scope |
| 1 | CLOUD&#45;UNAPPROVED&#45;ADMIN&#45;GRANT | approval&#61;no is a synthetic annotation&#59; confirm change record |
| 1 | CLOUD&#45;UNAPPROVED&#45;ADMIN&#45;GRANT | successful administrative change is not proof of stolen identity |
| 2 | CLOUD&#45;UNAPPROVED&#45;ACCESS&#45;KEY | successful access&#45;key creation recorded |
| 2 | CLOUD&#45;UNAPPROVED&#45;ACCESS&#45;KEY | approval&#61;no is a synthetic annotation&#59; subsequent key usage unverified |
| 3 | CLOUD&#45;UNAPPROVED&#45;ADMIN&#45;GRANT | successful app&#95;consent with privileged&#95;app scope |
| 3 | CLOUD&#45;UNAPPROVED&#45;ADMIN&#45;GRANT | approval&#61;no is a synthetic annotation&#59; confirm change record |
| 3 | CLOUD&#45;UNAPPROVED&#45;ADMIN&#45;GRANT | successful administrative change is not proof of stolen identity |
| 4 | CLOUD&#45;UNAPPROVED&#45;ADMIN&#45;GRANT | successful pim&#95;activation with admin scope |
| 4 | CLOUD&#45;UNAPPROVED&#45;ADMIN&#45;GRANT | approval&#61;no is a synthetic annotation&#59; confirm change record |
| 4 | CLOUD&#45;UNAPPROVED&#45;ADMIN&#45;GRANT | successful administrative change is not proof of stolen identity |

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
