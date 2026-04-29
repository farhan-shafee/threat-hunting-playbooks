# Threat Hunting Portfolio Lab

A hands-on, interview-ready lab that demonstrates how I run structured threat hunts and document analyst decisions.

> This repo is a **portfolio lab**. It is intentionally educational and does **not** claim production SOC authority, customer incident ownership, or enterprise-wide detection coverage.

## Why this exists

I built this lab to show practical capability for SOC Analyst / Security Analyst / Threat Hunter / Junior Detection Engineer roles:
- turning attacker behavior into hunt hypotheses
- writing and tuning SIEM queries
- triaging findings with evidence-based escalation criteria
- documenting outcomes in concise hunt summaries

## Repository map

```text
hunts/                  # Primary hunt playbooks (6 core scenarios)
docs/                   # Methodology, assumptions, and reference guidance
samples/logs/           # Synthetic telemetry snippets for practice
samples/reports/        # Example completed hunt summaries
queries/                # Reusable KQL snippets
scripts/                # Validation checks used locally and in CI
.github/workflows/      # CI workflow
legacy-playbooks/       # (planned) migration target for older markdown content
```

## Core hunt playbooks

- Suspicious PowerShell → `hunts/suspicious-powershell.md`
- Unusual authentication behavior → `hunts/unusual-authentication-behavior.md`
- Lateral movement → `hunts/lateral-movement.md`
- Data exfiltration indicators → `hunts/data-exfiltration-indicators.md`
- Cloud account compromise → `hunts/cloud-account-compromise.md`
- Persistence mechanisms → `hunts/persistence-mechanisms.md`

Every playbook includes:
- hypothesis + objective
- required data sources
- SIEM query examples
- expected results
- investigation steps
- false-positive guidance
- escalation criteria
- MITRE ATT&CK mapping
- tuning notes

## Workflow used in this lab

1. Define a falsifiable hypothesis.
2. Verify telemetry prerequisites.
3. Run initial query and collect candidate findings.
4. Enrich with process/user/network/cloud context.
5. Decide benign vs suspicious using explicit criteria.
6. Tune logic to reduce recurring false positives.
7. Document hunt summary and follow-up actions.

See `docs/threat-hunting-methodology.md`.

## Sample outputs included

- synthetic log snippets in `samples/logs/`
- completed hunt summaries in `samples/reports/`

These artifacts are synthetic by design and are provided to demonstrate analysis workflow, not real incidents.

## Skills demonstrated

- SIEM query authoring (KQL-style)
- endpoint + identity + network + cloud triage
- ATT&CK-based behavior mapping
- practical false-positive reduction
- written communication for investigation outcomes

## Limitations and honesty notes

- Queries are generalized and require adaptation to your schema/table names.
- Thresholds are starter values, not universal production thresholds.
- Sample data is intentionally small and synthetic.
- This repository avoids fabricated companies, breaches, threat intel claims, and fake impact metrics.

## Quickstart

```bash
make validate
```

This runs markdown quality checks for hunt playbook structure and query code-block presence.
