"""Small, auditable hunt evaluator for synthetic CSV evidence.

This is NOT a KQL interpreter, a live SIEM integration, an alerting service,
or proof of compromise. All thresholds are teaching parameters.
"""
from __future__ import annotations

import csv
from collections import Counter, deque
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import io
from itertools import groupby
from pathlib import Path
import re

from .extended import EXT_RULE_IDS, EXT_RULE_PARAMETERS, EXT_SCHEMAS, WINDOWS, evaluate_extended

MAX_INPUT_BYTES = 5_000_000
MAX_RECORDS = 20_000

SCHEMAS = {
    "auth": ("TimeGenerated", "UserPrincipalName", "IPAddress", "ResultType"),
    "powershell": (
        "Timestamp", "DeviceName", "AccountName", "FileName",
        "ProcessCommandLine", "InitiatingProcessFileName",
    ),
}
SCHEMAS.update(EXT_SCHEMAS)
OFFICE_OR_SCRIPT_PARENTS = {
    "winword.exe", "excel.exe", "outlook.exe", "wscript.exe",
    "cscript.exe", "mshta.exe",
}
ENCODED_FLAG = re.compile(r"(?i)(?:^|\s)-(?:enc|encodedcommand)(?=\s|:|$)")
PAYLOAD_MARKERS = ("frombase64string", "invoke-expression", "iex(", "downloadstring(")
RULE_IDS = {
    "auth": ("AUTH-FAILED-THEN-SUCCESS", "AUTH-SPRAY"),
    "powershell": ("PS-SUSPICIOUS-EXECUTION",),
}
RULE_VERSIONS = {rule: "1.1.0" for rules in RULE_IDS.values() for rule in rules}
RULE_IDS.update(EXT_RULE_IDS)
RULE_VERSIONS.update({rule: "1.0.0" for rules in EXT_RULE_IDS.values() for rule in rules})
RULE_PARAMETERS = {
    "AUTH-FAILED-THEN-SUCCESS": {
        "minimum_failures": 5,
        "lookback_seconds": 900,
        "lookback_inclusive": True,
        "failure_result": "50126",
        "success_result": "0",
        "temporal_order": "strictly_earlier",
        "timestamp_ties": "discard_failures_tied_with_success",
        "other_outcomes": "reset_sequence",
    },
    "AUTH-SPRAY": {
        "minimum_failures": 6,
        "minimum_distinct_identities": 3,
        "window_seconds": 900,
        "window_inclusive": True,
        "failure_result": "50126",
        "maximum_findings_per_ip": 1,
    },
    "PS-SUSPICIOUS-EXECUTION": {
        "executable_names": ["powershell.exe", "pwsh.exe"],
        "encoded_flag_pattern": ENCODED_FLAG.pattern,
        "payload_markers": list(PAYLOAD_MARKERS),
        "high_priority_parents": sorted(OFFICE_OR_SCRIPT_PARENTS),
    },
}
RULE_PARAMETERS.update(EXT_RULE_PARAMETERS)


class HuntInputError(ValueError):
    """Invalid, ambiguous, or oversized telemetry input."""


@dataclass(frozen=True)
class Row:
    record: int  # CSV record ordinal; not necessarily physical file line
    at: datetime
    fields: dict[str, str]


def _timestamp(raw: str, record: int, field: str) -> datetime:
    try:
        value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timezone missing")
        return value.astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise HuntInputError(
            f"record {record}: {field} must be timezone-aware ISO-8601"
        ) from exc


def load_csv(hunt_id: str, source: Path) -> tuple[list[Row], str]:
    if hunt_id not in SCHEMAS:
        raise HuntInputError(f"unknown hunt: {hunt_id}")
    if not source.is_file():
        raise HuntInputError(f"not a readable CSV file: {source}")
    with source.open("rb") as handle:
        data = handle.read(MAX_INPUT_BYTES + 1)
    if not data or len(data) > MAX_INPUT_BYTES:
        raise HuntInputError("CSV is empty or exceeds the 5 MB lab input limit")
    try:
        payload = data.decode("utf-8-sig").replace("\r\n", "\n")
    except UnicodeDecodeError as exc:
        raise HuntInputError("CSV must be UTF-8") from exc
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    reader = csv.DictReader(io.StringIO(payload, newline=""), strict=True)
    time_key = "TimeGenerated" if hunt_id == "auth" else "Timestamp"
    rows: list[Row] = []
    try:
        names = reader.fieldnames
        if not names or len(names) != len(set(names)) or any(not h for h in names):
            raise HuntInputError("CSV has missing or duplicate column names")
        missing = set(SCHEMAS[hunt_id]) - set(names)
        if missing:
            raise HuntInputError(f"missing required columns: {', '.join(sorted(missing))}")
        for ordinal, item in enumerate(reader, start=2):
            if ordinal > MAX_RECORDS + 1:
                raise HuntInputError("CSV exceeds the 20,000-record lab limit")
            if None in item or any(value is None for value in item.values()):
                raise HuntInputError(f"record {ordinal}: malformed column count")
            fields = {key: (val or "").strip() for key, val in item.items()}
            if any(not fields[key] for key in SCHEMAS[hunt_id]):
                raise HuntInputError(f"record {ordinal}: empty required field")
            at = _timestamp(fields[time_key], ordinal, time_key)
            if hunt_id == "auth" and not fields["ResultType"].isdigit():
                raise HuntInputError(f"record {ordinal}: ResultType must be numeric")
            rows.append(Row(ordinal, at, fields))
    except csv.Error as exc:
        raise HuntInputError(f"invalid CSV syntax: {exc}") from exc
    if not rows:
        raise HuntInputError("CSV contains no events")
    rows.sort(key=lambda item: (item.at, item.record))
    return rows, digest


def _when(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _finding(
    hunt_id: str,
    rule_id: str,
    severity: str,
    entity: str,
    evidence: list[Row],
    signals: list[str],
) -> dict:
    ordered = sorted(evidence, key=lambda e: (e.at, e.record))
    return {
        "hunt_id": hunt_id,
        "rule_id": rule_id,
        "severity": severity,
        "entity": entity,
        "first_seen_utc": _when(ordered[0].at),
        "last_seen_utc": _when(ordered[-1].at),
        "evidence_records": [event.record for event in ordered],
        "signals": signals,
        "disposition": "review required; not confirmed compromise",
    }


def _auth_findings(rows: list[Row]) -> list[dict]:
    results: list[dict] = []
    follow = RULE_PARAMETERS["AUTH-FAILED-THEN-SUCCESS"]
    spray = RULE_PARAMETERS["AUTH-SPRAY"]
    lookback = timedelta(seconds=follow["lookback_seconds"])
    spray_window = timedelta(seconds=spray["window_seconds"])
    per_identity: dict[tuple[str, str], list[Row]] = {}
    per_ip_failures: dict[str, list[Row]] = {}
    for row in rows:
        f = row.fields
        per_identity.setdefault((f["IPAddress"], f["UserPrincipalName"]), []).append(row)
        if f["ResultType"] == spray["failure_result"]:
            per_ip_failures.setdefault(f["IPAddress"], []).append(row)

    # A success uses only strictly earlier failures in the inclusive lookback.
    # Timestamp groups avoid inferring an order from CSV position: successes
    # discard tied failures, and unrelated outcomes reset the entire group.
    for (ip, user), events in sorted(per_identity.items()):
        failures: deque[Row] = deque()
        for at, same_time in groupby(events, key=lambda event: event.at):
            group = list(same_time)
            codes = {event.fields["ResultType"] for event in group}
            if codes - {follow["failure_result"], follow["success_result"]}:
                failures.clear()
                continue
            while failures and at - failures[0].at > lookback:
                failures.popleft()
            successes = [event for event in group
                         if event.fields["ResultType"] == follow["success_result"]]
            if successes:
                if len(failures) >= follow["minimum_failures"]:
                    results.append(_finding(
                        "auth", "AUTH-FAILED-THEN-SUCCESS", "high",
                        f"{user} | {ip}", list(failures) + successes,
                        [f"{len(failures)} invalid-password failures before success",
                         "same identity and source IP within 15 minutes"],
                    ))
                failures.clear()
            else:
                failures.extend(group)

    # Evaluate the complete timestamp group at each window boundary so tied
    # CSV permutations cannot change which failures support the first finding.
    for ip, failures in sorted(per_ip_failures.items()):
        window: deque[Row] = deque()
        identities: Counter[str] = Counter()
        for at, same_time in groupby(failures, key=lambda event: event.at):
            while window and at - window[0].at > spray_window:
                identity = window.popleft().fields["UserPrincipalName"]
                identities[identity] -= 1
                if not identities[identity]:
                    del identities[identity]
            for row in same_time:
                window.append(row)
                identities[row.fields["UserPrincipalName"]] += 1
            if (len(window) >= spray["minimum_failures"]
                    and len(identities) >= spray["minimum_distinct_identities"]):
                results.append(_finding(
                    "auth", "AUTH-SPRAY", "medium", ip, list(window),
                    [f"{len(window)} invalid-password failures",
                     f"{len(identities)} distinct identities within 15 minutes"],
                ))
                break
    return results


def _powershell_findings(rows: list[Row]) -> list[dict]:
    results: list[dict] = []
    parameters = RULE_PARAMETERS["PS-SUSPICIOUS-EXECUTION"]
    for row in rows:
        f = row.fields
        if f["FileName"].lower() not in parameters["executable_names"]:
            continue
        command = f["ProcessCommandLine"].lower()
        parent = f["InitiatingProcessFileName"].lower()
        encoded = bool(ENCODED_FLAG.search(command))
        markers = [marker for marker in parameters["payload_markers"] if marker in command]
        risky_parent = parent in parameters["high_priority_parents"]
        if not encoded and not markers:
            continue
        signals: list[str] = []
        if encoded:
            signals.append("encoded-command argument")
        if markers:
            signals.append("script execution/encoding marker: " + ", ".join(markers))
        if risky_parent:
            signals.append("Office or script-host parent: " + parent)
        results.append(_finding(
            "powershell", "PS-SUSPICIOUS-EXECUTION",
            "high" if risky_parent else "medium",
            f"{f['DeviceName']} | {f['AccountName']}", [row], signals,
        ))
    return results


def run_hunt(hunt_id: str, source: str | Path) -> dict:
    """Return a deterministic, content-addressed finding report."""
    rows, digest = load_csv(hunt_id, Path(source))
    extra = None
    if hunt_id == "auth":
        findings = _auth_findings(rows)
    elif hunt_id == "powershell":
        findings = _powershell_findings(rows)
    else:
        findings, unique_events, duplicates, quality = evaluate_extended(
            hunt_id, rows, _finding, HuntInputError
        )
        extra = {
            "events_unique": unique_events,
            "duplicate_events_suppressed": duplicates,
            "data_quality_warnings": quality,
        }
    findings.sort(
        key=lambda finding: (
            datetime.fromisoformat(finding["first_seen_utc"].replace("Z", "+00:00")),
            finding["rule_id"], finding["entity"],
        )
    )
    report = {
        "result_schema_version": "1.0" if extra is None else "1.1",
        "rule_versions": {rule: RULE_VERSIONS[rule] for rule in RULE_IDS[hunt_id]},
        "effective_parameters": deepcopy({
            rule: RULE_PARAMETERS[rule] for rule in RULE_IDS[hunt_id]
        }),
        "lab_scope": "synthetic offline telemetry; no live SIEM execution",
        "hunt_id": hunt_id,
        "input_sha256_normalized_utf8": digest,
        "events_evaluated": len(rows),
        "findings_count": len(findings),
        "time_window": "15 minutes" if hunt_id == "auth" else "per process event",
        "findings": findings,
    }
    if extra is not None:
        report["time_window"] = WINDOWS[hunt_id]
        report.update(extra)
    return report
