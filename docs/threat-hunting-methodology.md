# Threat Hunting Methodology (Portfolio Lab)

## Scope
This methodology is designed for a lab portfolio and interview discussion, not formal production SOC governance.

## Hunt Lifecycle
1. **Form hypothesis** based on ATT&CK behaviors and likely attacker objectives.
2. **Confirm telemetry**: required tables/fields and retention.
3. **Initial query run** to find suspicious candidates.
4. **Context enrichment**: user, host criticality, parent process, geo, reputation.
5. **Triage decision**: benign / suspicious / escalate.
6. **Tune detection**: thresholds, allowlists, suppression logic.
7. **Document outcomes** in hunt summary reports.

## Analyst Principles
- Prefer reproducible logic over one-off intuition.
- Keep assumptions explicit.
- Record false-positive patterns.
- Avoid overclaiming confidence where telemetry is incomplete.

## Evidence Handling (Lab)
- Use synthetic or sanitized sample data only.
- Do not include sensitive corporate telemetry.

## Continuous Improvement
- Update playbooks when schema changes.
- Version query adjustments in git history.
- Add tests/checklists for quality gates.
