# Threat Hunting Portfolio Lab

This repository is a **portfolio lab** for demonstrating practical threat hunting and junior detection engineering skills.

It is intentionally scoped for learning, interview discussion, and repeatable practice — **not a claim of production SOC ownership or real incident response authority**.

## Purpose

- Show how I structure hunts from hypothesis to escalation decision.
- Demonstrate SIEM query writing (primarily KQL-style examples).
- Document triage workflows, false-positive handling, and tuning decisions.
- Provide reusable examples for SOC Analyst / Security Analyst / Threat Hunter roles.

## Repository Structure

```text
hunts/                  # Hunt playbooks (host, identity, network, cloud)
docs/                   # Methodology and lab assumptions
samples/logs/           # Small synthetic sample telemetry for practice
samples/reports/        # Example completed hunt summaries
queries/                # Query snippets and reusable building blocks
scripts/                # Validation/checklist scripts
.github/workflows/      # CI checks
```

## Hunt Workflow Used in This Lab

1. Define a hypothesis tied to attacker behavior.
2. Confirm required telemetry and field availability.
3. Run initial query and collect candidate findings.
4. Investigate process/user/network context.
5. Reduce noise with allowlists, thresholds, and time windows.
6. Decide: close as benign, monitor, or escalate.
7. Record findings and tuning updates.

See `docs/threat-hunting-methodology.md` for full details.

## Included Hunt Playbooks

- Suspicious PowerShell (`hunts/suspicious-powershell.md`)
- Unusual Authentication Behavior (`hunts/unusual-authentication-behavior.md`)
- Lateral Movement (`hunts/lateral-movement.md`)
- Data Exfiltration Indicators (`hunts/data-exfiltration-indicators.md`)
- Cloud Account Compromise (`hunts/cloud-account-compromise.md`)
- Persistence Mechanisms (`hunts/persistence-mechanisms.md`)

## Sample Outputs

This lab includes:
- Synthetic sample logs in `samples/logs/`.
- Example completed hunt summaries in `samples/reports/`.

These are fabricated training artifacts and do not represent real customer/company incidents.

## Skills Demonstrated

- Threat hypothesis development
- KQL/SIEM query construction
- Host, network, identity, and cloud triage
- MITRE ATT&CK mapping
- Detection tuning and false-positive reduction
- Investigation documentation

## Limitations

- Queries are generalized and may require schema changes per SIEM/EDR.
- No claim of production coverage completeness.
- Sample logs are synthetic and not full-fidelity enterprise telemetry.
- ATT&CK mappings are analyst interpretations and should be validated in each environment.

## Quick Start

```bash
make validate
```

Runs markdown and playbook quality checks used by CI.
