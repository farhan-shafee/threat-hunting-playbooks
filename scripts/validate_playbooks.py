#!/usr/bin/env python3
from pathlib import Path
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


def main() -> int:
    hunt_dir = Path("hunts")
    files = sorted(hunt_dir.glob("*.md"))
    if not files:
        print("No hunt playbooks found in hunts/")
        return 1

    failed = False
    for file in files:
        text = file.read_text(encoding="utf-8")
        missing = [s for s in REQUIRED_SECTIONS if s not in text]
        if missing:
            failed = True
            print(f"[FAIL] {file}: missing sections -> {', '.join(missing)}")
        else:
            print(f"[OK] {file}")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
