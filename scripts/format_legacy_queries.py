#!/usr/bin/env python3
"""One-time, idempotent formatting for historical Markdown query examples.

This corrects Markdown fences; it DOES NOT validate query syntax, schema,
or detection accuracy. Historical examples remain explicitly unverified.
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
HISTORICAL_DIRS = ("cloud", "network", "windows", "queries")
BARE_BLOCK = re.compile(
    r"(?m)^(?:kql|sql)[ \t]*\n"
    r"(?P<body>(?:(?!^[ \t]*$)[^\n]+\n?)+)"
)
NOTICE = (
    "> **Query status:** Historical, illustrative KQL only; not executed "
    "against a live SIEM.\n"
    "> Verify required data connector, table names, columns, and logic "
    "against your actual environment before use.\n\n"
)


def normalize(path: Path) -> bool:
    original = path.read_text(encoding="utf-8")
    lines = original.splitlines()
    text = "\n".join(lines) + "\n"
    text = BARE_BLOCK.sub(
        lambda m: "```kql\n" + m.group("body").rstrip() + "\n```\n", text
    )
    if "Query status:" not in text:
        first_line, separator, rest = text.partition("\n")
        text = first_line + "\n\n" + NOTICE + rest.lstrip("\n")
    if text != original.replace("\r\n", "\n"):
        path.write_text(text, encoding="utf-8", newline="\n")
        return True
    return False


def main() -> int:
    count = 0
    for directory in HISTORICAL_DIRS:
        for path in sorted((ROOT / directory).glob("*.md")):
            if normalize(path):
                print(f"formatted: {path.relative_to(ROOT)}")
                count += 1
    print(f"Updated {count} historical Markdown files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
