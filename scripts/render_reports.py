#!/usr/bin/env python3
"""Generate or verify committed reports from immutable synthetic CSV fixtures."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import string
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from huntlab import run_hunt  # noqa: E402

CASES = {
    "auth": ("auth-lab-v1.csv", "auth-v1.md"),
    "powershell": ("powershell-lab-v1.csv", "powershell-v1.md"),
    "lateral": ("lateral-lab-v1.csv", "lateral-v1.md"),
    "persistence": ("persistence-lab-v1.csv", "persistence-v1.md"),
    "cloud": ("cloud-lab-v1.csv", "cloud-v1.md"),
    "egress": ("egress-lab-v1.csv", "egress-v1.md"),
}


def table_cell(value: object) -> str:
    """Render untrusted text literally, without creating Markdown or HTML.

    CommonMark recognizes syntax before decoding character references. Encode
    input backslashes too, so they cannot cancel the generated table-pipe escape.
    Control characters stay recoverable in source without creating table rows.
    """
    # Include URL/email punctuation: GFM can autolink even inside otherwise
    # escaped link syntax if a raw scheme, www. prefix, or address survives.
    syntax = set(string.punctuation)
    return "".join(
        r"\|" if character == "|" else
        f"&#{ord(character)};" if character in syntax or ord(character) < 32
        or ord(character) == 127 else character
        for character in str(value)
    )


def render(report: dict) -> str:
    hunt = table_cell(report["hunt_id"])
    configuration = json.dumps({
        "rule_versions": report["rule_versions"],
        "effective_parameters": report["effective_parameters"],
    }, indent=2, sort_keys=True, ensure_ascii=True)
    lines = [
        f"# Reproduced synthetic hunt: {hunt}",
        "",
        "> Generated entirely from the committed synthetic CSV by",
        "> `python scripts/render_reports.py`. Not a production incident.",
        "",
        f"- Result schema version: {table_cell(report['result_schema_version'])}",
        f"- Hunt: {hunt}",
        f"- Scope: {table_cell(report['lab_scope'])}",
        f"- Input events: **{table_cell(report['events_evaluated'])}**",
        f"- Review candidates: **{table_cell(report['findings_count'])}**",
        f"- Input SHA-256 (normalized UTF-8): {table_cell(report['input_sha256_normalized_utf8'])}",
        f"- Window: {table_cell(report['time_window'])}",
        *([
            f"- Unique event IDs: **{table_cell(report['events_unique'])}**",
            f"- Duplicate event IDs suppressed: **{table_cell(report['duplicate_events_suppressed'])}**",
        ] if "events_unique" in report else []),
        "",
        "## Rule versions and effective parameters",
        "",
        "```json",
        configuration,
        "```",
        "",
        "## Review candidates",
        "",
        "| Candidate | Rule | Severity | Entity | First seen (UTC) | Last seen (UTC) | Evidence records | Disposition |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for candidate, finding in enumerate(report["findings"], start=1):
        cells = [
            candidate, finding["rule_id"], finding["severity"], finding["entity"],
            finding["first_seen_utc"], finding["last_seen_utc"],
            ", ".join(map(str, finding["evidence_records"])), finding["disposition"],
        ]
        lines.append("| " + " | ".join(map(table_cell, cells)) + " |")
    if not report["findings"]:
        lines.append("| None | — | — | — | — | — | — | — |")
    lines += [
        "",
        "## Candidate rationale",
        "",
        "Each row preserves one evaluated signal; candidate numbers refer to the table above.",
        "",
        "| Candidate | Rule | Evaluated signal |",
        "|---|---|---|",
    ]
    for candidate, finding in enumerate(report["findings"], start=1):
        for signal in finding["signals"]:
            lines.append("| " + " | ".join(map(table_cell, [
                candidate, finding["rule_id"], signal,
            ])) + " |")
    if not report["findings"]:
        lines.append("| None | — | — |")
    lines += [
        "",
        "## Interpretation and limits",
        "",
        "- These are deterministic **review candidates**, not a claim of compromise.",
        "- Synthetic inputs use reserved example IP space and `@lab.local` identities.",
        "- The Python evaluator is not a KQL execution engine; SIEM queries must be",
        "  verified against the target platform's actual schema and live configuration.",
        "- Offline fixture tests cannot establish real-world detection performance.",
        "- Untrusted values are literal text. Control characters are preserved as",
        "  numeric character references in the Markdown source; no raw command lines are included.",
        "",
    ]
    if "data_quality_warnings" in report:
        lines.extend(["", "## Data-quality warnings", ""])
        if report["data_quality_warnings"]:
            lines.extend("- " + table_cell(warning)
                         for warning in report["data_quality_warnings"])
        else:
            lines.append("- None recorded for this synthetic input.")
        lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--check", action="store_true", help="Fail when reports differ")
    args = p.parse_args(argv)
    out = ROOT / "samples" / "reports" / "reproduced"
    failed = False
    for hunt, (sample, filename) in CASES.items():
        expected = render(run_hunt(hunt, ROOT / "samples" / "logs" / sample))
        destination = out / filename
        if args.check:
            if not destination.is_file() or destination.read_text(
                encoding="utf-8"
            ).replace("\r\n", "\n") != expected:
                print(f"[FAIL] stale or missing: {destination}")
                failed = True
            else:
                print(f"[OK] reproducible report: {filename}")
        else:
            out.mkdir(parents=True, exist_ok=True)
            destination.write_text(expected, encoding="utf-8", newline="\n")
            print(f"[OK] generated: {filename}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
