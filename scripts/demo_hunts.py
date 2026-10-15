#!/usr/bin/env python3
"""Six-scenario, read-only reviewer demonstration (synthetic CSV only).

Outputs a compact table without contacting any SIEM, network, or cloud
service and without modifying artifacts.
"""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from huntlab import HuntInputError, run_hunt  # noqa: E402
from scripts.render_reports import CASES  # noqa: E402


def main() -> int:
    print("OFFLINE SYNTHETIC THREAT HUNTING - no tenant access, no incident claims")
    print("Hunt         Events  Review candidates  Data warnings  SHA-256 (prefix)")
    print("-" * 78)
    for hunt, (source, _) in CASES.items():
        try:
            result = run_hunt(hunt, ROOT / "samples" / "logs" / source)
        except (OSError, HuntInputError) as exc:
            print(f"[ERROR] {hunt}: {exc}", file=sys.stderr)
            return 2
        print(
            f"{hunt:<12} {result['events_evaluated']:>6} "
            f"{result['findings_count']:>18} "
            f"{len(result.get('data_quality_warnings', [])):>14} "
            f"{result['input_sha256_normalized_utf8'][:12]}"
        )
    print()
    print("Every candidate needs human triage. View complete evidence with:")
    print("  python -B scripts/run_hunt.py --hunt <name> --input samples/logs/<name>-lab-v1.csv")
    print("  python -B scripts/render_reports.py --check")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
