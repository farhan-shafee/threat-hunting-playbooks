#!/usr/bin/env python3
from pathlib import Path
import re
import sys

REQUIRED_SECTIONS = [
    "## Hypothesis",
    "## Objective",
    "## Required Data Sources",
    "## SIEM Query Examples",
    "## Expected Results",
    "## Investigation Steps",
    "## False Positive Guidance",
    "## Escalation Criteria",
    "## MITRE ATT&CK Mapping",
    "## Tuning Notes",
]

KQL_BLOCK_PATTERN = re.compile(r"```(?:kql|sql)?\n.+?```", re.DOTALL | re.IGNORECASE)


def validate_file(file: Path) -> list[str]:
    errors: list[str] = []
    text = file.read_text(encoding="utf-8")

    missing_sections = [s for s in REQUIRED_SECTIONS if s not in text]
    if missing_sections:
        errors.append(f"missing sections: {', '.join(missing_sections)}")

    if "## SIEM Query Examples" in text and not KQL_BLOCK_PATTERN.search(text):
        errors.append("missing fenced SIEM query code block (```kql ... ```)")

    return errors


def main() -> int:
    hunt_dir = Path("hunts")
    files = sorted(hunt_dir.glob("*.md"))
    if not files:
        print("[FAIL] No hunt playbooks found in hunts/")
        return 1

    failed = False
    for file in files:
        errors = validate_file(file)
        if errors:
            failed = True
            print(f"[FAIL] {file}")
            for err in errors:
                print(f"  - {err}")
        else:
            print(f"[OK] {file}")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
