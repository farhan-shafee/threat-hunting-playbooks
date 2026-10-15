#!/usr/bin/env python3
"""Generate or verify committed reports from immutable synthetic CSV fixtures."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from huntlab import run_hunt  # noqa: E402

CASES = {
    "auth": ("auth-lab-v1.csv", "auth-v1.md"),
    "powershell": ("powershell-lab-v1.csv", "powershell-v1.md"),
}


def table_cell(value: object) -> str:
    """Escape untrusted text before placing it inside a Markdown table."""
    return str(value).replace("|", r"\|").replace("\n", " ").replace("\r", " ")


def render(report: dict) -> str:
    hunt = report["hunt_id"]
    lines = [
        f"# Reproduced synthetic hunt: {hunt}",
        "",
        "> Generated entirely from the committed synthetic CSV by",
        "> `python scripts/render_reports.py`. Not a production incident.",
        "",
        f"- Hunt: `{hunt}`",
        f"- Input events: **{report['events_evaluated']}**",
        f"- Review candidates: **{report['findings_count']}**",
        f"- Input SHA-256 (normalized UTF-8): `{report['input_sha256_normalized_utf8']}`",
        f"- Window: {report['time_window']}",
        "",
        "## Review candidates",
        "",
        "| Rule | Severity | Entity | First seen (UTC) | Evidence records |",
        "|---|---|---|---|---|",
    ]
    for f in report["findings"]:
        lines.append(
            f"| {table_cell(f['rule_id'])} | {table_cell(f['severity'])} | {table_cell(f['entity'])} | "
            f"{table_cell(f['first_seen_utc'])} | {', '.join(map(str, f['evidence_records']))} |"
        )
    if not report["findings"]:
        lines.append("| None | — | — | — | — |")
    lines += [
        "",
        "## Interpretation and limits",
        "",
        "- These are deterministic **review candidates**, not a claim of compromise.",
        "- Synthetic inputs use reserved example IP space and `@lab.local` identities.",
        "- The Python evaluator is not a KQL execution engine; SIEM queries must be",
        "  verified against the target platform's actual schema and live configuration.",
        "- Offline fixture tests cannot establish real-world detection performance.",
        "",
    ]
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
