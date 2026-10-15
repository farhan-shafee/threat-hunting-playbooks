# Contributing

Thanks for contributing to this threat hunting portfolio lab.

## Guidelines
- Keep content educational and evidence-based.
- Do not include fake companies, fake breaches, or fabricated real-world claims.
- Prefer synthetic or sanitized sample data.
- Use the hunt playbook section template in `hunts/`.

## New offline hunt acceptance checklist
- Use synthetic-only telemetry and document its *explicit* normalized schema. Never copy secrets or customer logs.
- Define falsifiable behavior, benign controls, missing-data outcomes, event ordering, and counter semantics before writing rules.
- Add hand-authored expected candidate IDs, timestamps, evidence records and priorities; do not generate those expectations from the implementation being tested.
- Cover negative scenarios, timestamp ties, boundary windows, duplicate/conflicting source IDs, malformed inputs, and deterministic report reproducibility.
- Include an exact scope statement: offline Python checks are not KQL compilation, a real attack detection guarantee, or evidence of production incident handling.
- Keep historical queries unverified until a separately authorized tenant-side validation exists.

## Local Validation
Run:

```bash
make validate
```
