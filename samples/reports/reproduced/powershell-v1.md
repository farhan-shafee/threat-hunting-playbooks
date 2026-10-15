# Reproduced synthetic hunt: powershell

> Generated entirely from the committed synthetic CSV by
> `python scripts/render_reports.py`. Not a production incident.

- Result schema version: 1&#46;0
- Hunt: powershell
- Scope: synthetic offline telemetry&#59; no live SIEM execution
- Input events: **6**
- Review candidates: **3**
- Input SHA-256 (normalized UTF-8): 51039dfadf48eefd0272dc8a169a1333757ffacbce0ef47e52d71b1139d341e9
- Window: per process event

## Rule versions and effective parameters

```json
{
  "effective_parameters": {
    "PS-SUSPICIOUS-EXECUTION": {
      "encoded_flag_pattern": "(?i)(?:^|\\s)-(?:enc|encodedcommand)(?=\\s|:|$)",
      "executable_names": [
        "powershell.exe",
        "pwsh.exe"
      ],
      "high_priority_parents": [
        "cscript.exe",
        "excel.exe",
        "mshta.exe",
        "outlook.exe",
        "winword.exe",
        "wscript.exe"
      ],
      "payload_markers": [
        "frombase64string",
        "invoke-expression",
        "iex(",
        "downloadstring("
      ]
    }
  },
  "rule_versions": {
    "PS-SUSPICIOUS-EXECUTION": "1.1.0"
  }
}
```

## Review candidates

| Candidate | Rule | Severity | Entity | First seen (UTC) | Last seen (UTC) | Evidence records | Disposition |
|---|---|---|---|---|---|---|---|
| 1 | PS&#45;SUSPICIOUS&#45;EXECUTION | high | WKSTN&#45;22 \| jdoe | 2026&#45;04&#45;20T10&#58;21&#58;00Z | 2026&#45;04&#45;20T10&#58;21&#58;00Z | 2 | review required&#59; not confirmed compromise |
| 2 | PS&#45;SUSPICIOUS&#45;EXECUTION | high | WKSTN&#45;31 \| analyst | 2026&#45;04&#45;20T10&#58;30&#58;00Z | 2026&#45;04&#45;20T10&#58;30&#58;00Z | 5 | review required&#59; not confirmed compromise |
| 3 | PS&#45;SUSPICIOUS&#45;EXECUTION | medium | SRV&#45;07 \| svc&#95;patch | 2026&#45;04&#45;20T10&#58;32&#58;00Z | 2026&#45;04&#45;20T10&#58;32&#58;00Z | 7 | review required&#59; not confirmed compromise |

## Candidate rationale

Each row preserves one evaluated signal; candidate numbers refer to the table above.

| Candidate | Rule | Evaluated signal |
|---|---|---|
| 1 | PS&#45;SUSPICIOUS&#45;EXECUTION | encoded&#45;command argument |
| 1 | PS&#45;SUSPICIOUS&#45;EXECUTION | Office or script&#45;host parent&#58; winword&#46;exe |
| 2 | PS&#45;SUSPICIOUS&#45;EXECUTION | script execution&#47;encoding marker&#58; iex&#40; |
| 2 | PS&#45;SUSPICIOUS&#45;EXECUTION | Office or script&#45;host parent&#58; excel&#46;exe |
| 3 | PS&#45;SUSPICIOUS&#45;EXECUTION | encoded&#45;command argument |

## Interpretation and limits

- These are deterministic **review candidates**, not a claim of compromise.
- Synthetic inputs use reserved example IP space and `@lab.local` identities.
- The Python evaluator is not a KQL execution engine; SIEM queries must be
  verified against the target platform's actual schema and live configuration.
- Offline fixture tests cannot establish real-world detection performance.
- Untrusted values are literal text. Control characters are preserved as
  numeric character references in the Markdown source; no raw command lines are included.
