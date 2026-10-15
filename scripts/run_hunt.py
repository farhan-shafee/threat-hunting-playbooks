#!/usr/bin/env python3
"""Run a small synthetic offline hunt and write deterministic JSON evidence."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from huntlab import HuntInputError, run_hunt  # noqa: E402


def reject_input_alias(source: Path, destination: Path) -> None:
    """Reject identical paths and filesystem identities, including linked files."""
    aliases = source.absolute() == destination.absolute()
    if not aliases:
        try:
            aliases = source.samefile(destination)
        except FileNotFoundError:
            pass  # A new destination has no filesystem identity to compare.
    if aliases:
        raise HuntInputError("output must not refer to the input file")


def write_atomic(destination: Path, document: str) -> None:
    """Publish a complete report without truncating an existing destination."""
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", delete=False,
            dir=destination.parent, prefix=f".{destination.name}.", suffix=".tmp",
        ) as handle:
            temporary = Path(handle.name)
            handle.write(document)
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline synthetic evidence only; no live SIEM connection."
    )
    parser.add_argument("--hunt", choices=("auth", "powershell"), required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, help="Optional local JSON report path")
    args = parser.parse_args(argv)
    try:
        if args.output:
            reject_input_alias(args.input, args.output)
            if not args.output.parent.is_dir():
                raise HuntInputError("output directory does not exist")
        result = run_hunt(args.hunt, args.input)
        document = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output:
            write_atomic(args.output, document)
            print(f"Wrote {args.output}; {result['findings_count']} review candidates")
        else:
            print(document, end="")
        return 0
    except (HuntInputError, OSError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
