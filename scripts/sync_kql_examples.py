#!/usr/bin/env python3
"""Keep six core playbook snippets identical to their canonical KQL files.

--check is read-only and required in CI. --write updates only the
SIEM Query Examples Markdown section of the six core hunts; it does
NOT compile KQL or contact a tenant.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "queries" / "schema-reviewed"
SECTION = re.compile(
    r"(?ms)^## SIEM Query Examples[ \t]*\n.*?(?=^## Expected Results[ \t]*$)"
)


def load_manifest() -> dict:
    return json.loads((PACK / "manifest.json").read_text(encoding="utf-8"))


def snippets_for_playbook(entries: list[dict]) -> str:
    lines = [
        "## SIEM Query Examples",
        "",
        "> **Status: Microsoft vendor-schema-reviewed static candidates, NOT "
        "executed in an authorized Sentinel/Defender tenant.**",
        "> These are not claimed equivalent to the synthetic Python detectors.",
        "",
    ]
    for entry in entries:
        source = f"queries/schema-reviewed/{entry['file']}"
        query = (PACK / entry["file"]).read_text(encoding="utf-8").strip()
        if not query or "\x60\x60\x60" in query:
            raise ValueError(f"Invalid KQL source: {entry['file']}")
        lines.extend([
            f"### {entry['label']}",
            "",
            f"Source: [\x60{source}\x60](../{source}). "
            f"Native table: \x60{entry['table']}\x60.",
            "",
            "\x60\x60\x60kql",
            query,
            "\x60\x60\x60",
            "",
            f"**Important limitation:** {entry['limit']}",
            "",
        ])
    return "\n".join(lines) + "\n"


def render_playbook(content: str, entries: list[dict]) -> str:
    replacement = snippets_for_playbook(entries)
    if not SECTION.search(content):
        raise ValueError("Missing or malformed core SIEM Query Examples section")
    return SECTION.sub(lambda _match: replacement, content, count=1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true",
                      help="Read-only validation; fail on any stale or missing example")
    mode.add_argument("--write", action="store_true",
                      help="Rewrite only the core SIEM Query Examples sections")
    args = parser.parse_args(argv)
    grouped: dict[str, list[dict]] = defaultdict(list)
    for entry in load_manifest()["queries"]:
        grouped[entry["playbook"]].append(entry)
    if len(grouped) != 6:
        print("[FAIL] Expected six core playbooks", file=sys.stderr)
        return 2
    failures = 0
    for relative, entries in sorted(grouped.items()):
        path = ROOT / relative
        original = path.read_text(encoding="utf-8").replace("\r\n", "\n")
        try:
            expected = render_playbook(original, entries)
        except ValueError as exc:
            print(f"[FAIL] {relative}: {exc}")
            failures += 1
            continue
        if original != expected:
            if args.check:
                print(f"[FAIL] stale canonical query in {relative}")
                failures += 1
            else:
                path.write_text(expected, encoding="utf-8", newline="\n")
                print(f"[OK] synced {relative}")
        else:
            print(f"[OK] in sync: {relative}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
