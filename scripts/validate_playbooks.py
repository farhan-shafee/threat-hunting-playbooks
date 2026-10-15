#!/usr/bin/env python3
"""Fail-closed Markdown structural validation, relative to this script's repo."""
from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
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
QUERY_BLOCK = re.compile(r"(?ms)^```(?:kql|sql)\s*\n(?P<query>.*?)^```[ \t]*$")
UNFENCED_LANGUAGE = re.compile(r"(?m)^[ \t]*(?:kql|sql)[ \t]*$")
FENCE = re.compile(r"(?m)^```")


def validate_file(file: Path, is_core_hunt: bool = False) -> list[str]:
    problems: list[str] = []
    content = file.read_text(encoding="utf-8")
    if len(FENCE.findall(content)) % 2:
        problems.append("unbalanced Markdown code fences")
    if UNFENCED_LANGUAGE.search(content):
        problems.append("unfenced language marker (kql/sql)")
    if is_core_hunt:
        absent = [
            section for section in REQUIRED_SECTIONS
            if not re.search(rf"(?m)^{re.escape(section)}[ \t]*$", content)
        ]
        if absent:
            problems.append("missing sections: " + ", ".join(absent))
        section = re.search(
            r"(?ms)^## SIEM Query Examples[ \t]*\n(.*?)(?=^## |\Z)",
            content,
        )
        if not section:
            problems.append("missing SIEM query section")
        else:
            match = QUERY_BLOCK.search(section.group(1))
            if not match or not match.group("query").strip():
                problems.append("missing fenced, nonempty SIEM query in query section")
    return problems


def main() -> int:
    core = sorted((ROOT / "hunts").glob("*.md"))
    if len(core) != 6:
        print(f"[FAIL] Expected 6 core hunt playbooks, found {len(core)}")
        return 1
    all_docs = sorted(ROOT.rglob("*.md"))
    failed = 0
    for path in all_docs:
        if ".git" in path.parts:
            continue
        errors = validate_file(path, is_core_hunt=path in core)
        if errors:
            failed += 1
            print(f"[FAIL] {path.relative_to(ROOT)}: {'; '.join(errors)}")
    if not failed:
        print(f"[OK] Validated {len(all_docs)} Markdown documents, including 6 core hunts")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
