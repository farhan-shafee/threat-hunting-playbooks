#!/usr/bin/env python3
"""Build stable-source, fresh-time ADX synthetic validation queries.

No cloud credentials, network requests, data ingestion, or saved database
objects. This generates an inline datatable for each of the seven canonical
KQL examples that were run manually on Azure Data Explorer on 2026-10-15.

--check is strictly read-only. --write updates ONLY the generated replay
queries; it never updates the captured executed queries or result receipt.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence" / "adx-free-2026-10-15"
RAW = EVIDENCE / "executed"
REPLAY = ROOT / "queries" / "adx-validation" / "generated"
NATIVE = ROOT / "queries" / "schema-reviewed"
RECEIPT = EVIDENCE / "receipt.json"

CAPTURE = re.compile(
    r"(?ms)^let (?P<table>[A-Za-z][A-Za-z0-9_]*) = datatable"
    r"\((?P<schema>[^()\n]+)\)[ \t]*\n\[[ \t]*\n"
    r"(?P<rows>.*?)\n\];"
)
TIMESTAMP = re.compile(
    r"(?m)^(?P<indent>[ \t]*)datetime\((?P<when>[-0-9:.TZ+]+)\)(?P<comma>,)"
)
SENSITIVE = re.compile(
    r"(?i)@outlook\.com|farhanshafee|authorization:\s*bearer|"
    r"client.secret|account.?key\s*=|password\s*=|kusto\.windows\.net"
)
MUTATING = re.compile(
    r"(?im)^\s*\.(?:set|append|drop|delete|ingest|create|alter|clear|export)\b"
)


def read_receipt() -> dict:
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    if (receipt.get("receipt_version") != "1.0"
            or receipt.get("scope", {}).get("sentinel_tenant_execution") is not False
            or receipt.get("scope", {}).get("defender_xdr_tenant_execution") is not False):
        raise ValueError("Missing or invalid synthetic-only evidence scope")
    names = [s["file"] for s in receipt["scenarios"]]
    manifest = json.loads((NATIVE / "manifest.json").read_text(encoding="utf-8"))
    canonical = {q["file"]: q["table"] for q in manifest["queries"]}
    if len(names) != 7 or len(set(names)) != 7 or set(names) != set(canonical):
        raise ValueError("Expected exactly seven canonical KQL source queries")
    for scenario in receipt["scenarios"]:
        if scenario["table"] != canonical[scenario["file"]]:
            raise ValueError("Table mismatch in source evidence receipt")
        if scenario["expected_rows"] < 1 or scenario["expected_rows"] > 100:
            raise ValueError("Unsafe expected hit count")
        if scenario["fixture_rows"] < scenario["expected_rows"] or scenario["fixture_rows"] > 100:
            raise ValueError("Unsafe fixture row count")
        if scenario["anchor_minutes"] not in (15, 60):
            raise ValueError("Unknown replay bin contract")
        field = scenario.get("identity_field", "")
        keys = scenario.get("expected_identity_values", [])
        if (not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", field)
                or not isinstance(keys, list)
                or len(keys) != scenario["expected_rows"]
                or len({(type(v).__name__, str(v)) for v in keys}) != len(keys)
                or not all(isinstance(v, (str, int)) and not isinstance(v, bool)
                           for v in keys)):
            raise ValueError("Missing, malformed or duplicate expected identity values")
    return receipt


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def capture_parts(scenario: dict) -> tuple[str, str, str, list[datetime], str]:
    filename = scenario["file"]
    if not re.fullmatch(r"[a-z0-9-]+\.kql", filename):
        raise ValueError("Unsafe query filename")
    content = (RAW / filename).read_text(encoding="utf-8")
    if SENSITIVE.search(content) or MUTATING.search(content):
        raise ValueError(f"Sensitive or mutating material detected: {filename}")
    if sha256_text(content) != scenario["captured_query_sha256"]:
        raise ValueError(f"Captured executed query hash mismatch: {filename}")
    match = CAPTURE.search(content)
    if not match:
        raise ValueError(f"No canonical datatable declaration found: {filename}")
    native_query = (NATIVE / filename).read_text(encoding="utf-8").strip()
    if content[match.end():].strip() != native_query:
        raise ValueError(f"Captured query differs from current canonical source: {filename}")
    table = match["table"]
    if table != scenario["table"]:
        raise ValueError(f"Table identity drift: {filename}")
    schema = match["schema"]
    first_column, sep, other_columns = schema.partition(",")
    if not sep or first_column.strip() not in ("Timestamp:datetime", "TimeGenerated:datetime"):
        raise ValueError(f"First column must be native event timestamp: {filename}")
    times: list[datetime] = []
    for row in TIMESTAMP.finditer(match["rows"]):
        at = datetime.fromisoformat(row["when"].replace("Z", "+00:00"))
        if at.utcoffset() != timedelta(0) or at.second or at.microsecond:
            raise ValueError(f"Expected UTC minute-resolution timestamps: {filename}")
        times.append(at.astimezone(timezone.utc))
    if len(times) != scenario["fixture_rows"]:
        raise ValueError(f"Fixture timestamp count mismatch: {filename}")
    if not times or max(times) - min(times) > timedelta(hours=2):
        raise ValueError(f"Fixture observation interval too broad: {filename}")
    return table, first_column.strip().split(":")[0], other_columns.strip(), times, match["rows"]


def separate_native_query(native: str) -> tuple[str, str]:
    """Split native top-level 'let' statements and the final tabular expression.

    Canonical query inventory has exactly one query, no Kusto management commands,
    and at most three intermediate 'let' statements (auth correlation).
    """
    # Some canonical QUERY COMMENTS contain a semicolon; those do not
    # delimit a Kusto let statement. Match actual statement-ending lines.
    boundaries = list(re.finditer(r"(?m)^(?![ \t]*//)[^\n]*;[ \t]*$", native))
    if boundaries:
        last = boundaries[-1]
        preamble = native[:last.end()].strip() + "\n"
        final_expression = native[last.end():].strip()
        if not re.search(r"(?m)^let [A-Za-z]", preamble):
            raise ValueError("Unexpected terminating statement in canonical query")
    else:
        preamble, final_expression = "", native.strip()
    if not final_expression or MUTATING.search(native):
        raise ValueError("Native KQL must be read-only and nonempty")
    return preamble, final_expression


def build(scenario: dict) -> tuple[str, str]:
    filename = scenario["file"]
    table, timestamp_col, other_columns, times, rows = capture_parts(scenario)
    bin_minutes = scenario["anchor_minutes"]
    earliest = min(times)
    baseline = earliest.replace(minute=(earliest.minute // bin_minutes) * bin_minutes)
    if bin_minutes == 60:
        baseline = earliest.replace(minute=0)
    offsets = [int((at - baseline).total_seconds() // 60) for at in times]
    if max(offsets) >= 180 or min(offsets) < 0:
        raise ValueError(f"Fixture offsets outside bounded replay range: {filename}")
    offset_index = 0

    def substitute(found: re.Match) -> str:
        nonlocal offset_index
        value = offsets[offset_index]
        offset_index += 1
        return f"{found['indent']}{value}{found['comma']}"

    converted = TIMESTAMP.sub(substitute, rows)
    if offset_index != len(times) or TIMESTAMP.search(converted):
        raise ValueError("Incomplete timestamp conversion")
    # Subtract two hours before binning, avoiding future data while allowing
    # all seven historical source queries' ago(...) filters to match.
    preamble = (
        "// GENERATED from the captured 2026-10-15 synthetic ADX execution.\n"
        "// Read-only in-memory datatable; NO Sentinel/Defender tenant execution.\n"
        "// Never treat this replay as proof of real sensor or connector coverage.\n"
        f"let LabSyntheticAnchor = bin(now() - 2h, {bin_minutes}m);\n"
        f"let {table} = datatable(FixtureMinute:int, {other_columns})\n"
        "[\n"
        f"{converted}\n"
        "]\n"
        f"| extend {timestamp_col} = LabSyntheticAnchor + FixtureMinute * 1m\n"
        "| project-away FixtureMinute;\n"
    )
    native = (NATIVE / filename).read_text(encoding="utf-8")
    replay = preamble + native.rstrip() + "\n"
    native_lets, native_final = separate_native_query(native)
    clause = scenario["match"]
    if (not clause or ";" in clause or "\n" in clause or MUTATING.search(clause)
            or len(clause) > 500):
        raise ValueError("Unsafe or ambiguous validation predicate")
    n = scenario["expected_rows"]
    identity_field = scenario["identity_field"]
    expected_ids = json.dumps(scenario["expected_identity_values"], separators=(",", ":"))
    assertions = (
        preamble + native_lets
        + "let LabSyntheticResults = materialize(\n" + native_final + "\n);\n"
        + "let LabObserved = toscalar(LabSyntheticResults | count);\n"
        + "let LabMatched = toscalar(LabSyntheticResults | where " + clause
        + " | count);\n"
        + "let LabActualIds = toscalar(LabSyntheticResults | summarize "
        + "Ids=make_set(" + identity_field + "));\n"
        + "let LabExpectedIds = dynamic(" + expected_ids + ");\n"
        + "let LabIdsEqual = array_length(set_difference(LabActualIds, LabExpectedIds)) == 0\n"
        + "  and array_length(set_difference(LabExpectedIds, LabActualIds)) == 0;\n"
        + 'print Scenario="' + filename[:-4] + '", Expected=' + str(n)
        + ', Observed=LabObserved, Matched=LabMatched,\n'
        + '  IdentityMatch=LabIdsEqual,\n'
        + '  Verdict=iff(LabObserved == ' + str(n) + ' and LabMatched == '
        + str(n) + ' and LabIdsEqual, "PASS", "FAIL")\n'
    )
    return replay, assertions


def expected_queries() -> dict[str, str]:
    receipt = read_receipt()
    rendered: dict[str, str] = {}
    for scenario in receipt["scenarios"]:
        full, assertions = build(scenario)
        rendered[scenario["file"]] = full
        rendered[scenario["file"].replace(".kql", ".assert.kql")] = assertions
    return rendered


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--write", action="store_true",
                        help="Regenerate KQL only; leave the immutable capture and receipt unchanged")
    action.add_argument("--check", action="store_true",
                        help="Read-only deterministic drift and capture-integrity check")
    args = parser.parse_args(argv)
    try:
        generated = expected_queries()
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"[ERROR] ADX validation source contract: {error}", file=sys.stderr)
        return 2
    if args.write:
        REPLAY.mkdir(parents=True, exist_ok=True)
    existing = sorted(file.name for file in REPLAY.glob("*.kql")) if REPLAY.exists() else []
    if args.check and existing != sorted(generated):
        print("[FAIL] Replay KQL inventory differs from captured manifest", file=sys.stderr)
        return 1
    for filename, text in sorted(generated.items()):
        dest = REPLAY / filename
        if args.write:
            dest.write_text(text, encoding="utf-8", newline="\n")
        elif not dest.exists() or dest.read_text(encoding="utf-8").replace("\r\n", "\n") != text:
            print(f"[FAIL] Replay KQL drift: {filename}", file=sys.stderr)
            return 1
    print(f"[OK] {len(generated)//2} synthetic replay queries and "
          f"{len(generated)//2} executable PASS/FAIL assertions "
          f"{'generated' if args.write else 'reproduced exactly'}")
    print("[SCOPE] KQL in ADX datatables only. No tenant/SIEM execution or cloud calls.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
