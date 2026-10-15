#!/usr/bin/env python3
"""Run a small synthetic offline hunt and write deterministic JSON evidence."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from huntlab import HuntInputError, run_hunt  # noqa: E402


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline synthetic evidence only; no live SIEM connection."
    )
    parser.add_argument("--hunt", choices=("auth", "powershell"), required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, help="Optional local JSON report path")
    args = parser.parse_args(argv)
    try:
        result = run_hunt(args.hunt, args.input)
        document = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output:
            if not args.output.parent.is_dir():
                raise HuntInputError("output directory does not exist")
            args.output.write_text(document, encoding="utf-8", newline="\n")
            print(f"Wrote {args.output}; {result['findings_count']} review candidates")
        else:
            print(document, end="")
        return 0
    except (HuntInputError, OSError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
