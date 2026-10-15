"""Small, auditable hunt evaluator for synthetic CSV evidence.

This is NOT a KQL interpreter, a live SIEM integration, an alerting service,
or proof of compromise. All thresholds are teaching parameters.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import io
from pathlib import Path
import re

WINDOW = timedelta(minutes=15)
MAX_INPUT_BYTES = 5_000_000
MAX_RECORDS = 20_000

SCHEMAS = {
    "auth": ("TimeGenerated", "UserPrincipalName", "IPAddress", "ResultType"),
    "powershell": (
        "Timestamp", "DeviceName", "AccountName", "FileName",
        "ProcessCommandLine", "InitiatingProcessFileName",
    ),
}
OFFICE_OR_SCRIPT_PARENTS = {
    "winword.exe", "excel.exe", "outlook.exe", "wscript.exe",
    "cscript.exe", "mshta.exe",
}
ENCODED_FLAG = re.compile(r"(?i)(?:^|\s)-(?:enc|encodedcommand)(?=\s|:|$)")
PAYLOAD_MARKERS = ("frombase64string", "invoke-expression", "iex(", "downloadstring(")


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
    except ValueError as exc:
        raise HuntInputError(
            f"record {record}: {field} must be timezone-aware ISO-8601"
        ) from exc


def load_csv(hunt_id: str, source: Path) -> tuple[list[Row], str]:
    if hunt_id not in SCHEMAS:
        raise HuntInputError(f"unknown hunt: {hunt_id}")
    if not source.is_file():
        raise HuntInputError(f"not a readable CSV file: {source}")
    data = source.read_bytes()
    if not data or len(data) > MAX_INPUT_BYTES:
        raise HuntInputError("CSV is empty or exceeds the 5 MB lab input limit")
    try:
        payload = data.decode("utf-8-sig").replace("\r\n", "\n")
    except UnicodeDecodeError as exc:
        raise HuntInputError("CSV must be UTF-8") from exc
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    reader = csv.DictReader(io.StringIO(payload, newline=""), strict=True)
    names = reader.fieldnames
    if not names or len(names) != len(set(names)) or any(not h for h in names):
        raise HuntInputError("CSV has missing or duplicate column names")
    missing = set(SCHEMAS[hunt_id]) - set(names)
    if missing:
        raise HuntInputError(f"missing required columns: {', '.join(sorted(missing))}")
    time_key = "TimeGenerated" if hunt_id == "auth" else "Timestamp"
    rows: list[Row] = []
    try:
        for ordinal, item in enumerate(reader, start=2):
            if ordinal > MAX_RECORDS + 1:
                raise HuntInputError("CSV exceeds the 20,000-record lab limit")
            if None in item or any(item.get(key) is None for key in SCHEMAS[hunt_id]):
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
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


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
    per_identity: dict[tuple[str, str], list[Row]] = {}
    per_ip_failures: dict[str, list[Row]] = {}
    for row in rows:
        f = row.fields
        per_identity.setdefault((f["IPAddress"], f["UserPrincipalName"]), []).append(row)
        if f["ResultType"] == "50126":
            per_ip_failures.setdefault(f["IPAddress"], []).append(row)

    # Brute-force follow-through: 5 invalid-password failures, then a success,
    # same IP + identity, strictly within 15 minutes, with no earlier success
    # in between. Other error codes are not treated as password failures.
    for (ip, user), events in sorted(per_identity.items()):
        failures: list[Row] = []
        for row in events:
            code = row.fields["ResultType"]
            if code == "50126":
                failures = [e for e in failures if row.at - e.at <= WINDOW]
                failures.append(row)
            elif code == "0":
                nearby = [e for e in failures if row.at - e.at <= WINDOW]
                if len(nearby) >= 5:
                    results.append(_finding(
                        "auth", "AUTH-FAILED-THEN-SUCCESS", "high",
                        f"{user} | {ip}", nearby + [row],
                        [f"{len(nearby)} invalid-password failures before success",
                         "same identity and source IP within 15 minutes"],
                    ))
                failures = []
            else:
                failures = []  # MFA and unrelated errors break this sequence

    # Password spray: >=6 invalid-password failures involving >=3 distinct
    # users from one source IP in one 15-minute window. One finding/IP.
    for ip, failures in sorted(per_ip_failures.items()):
        left = 0
        for right, row in enumerate(failures):
            while row.at - failures[left].at > WINDOW:
                left += 1
            window = failures[left:right + 1]
            distinct = {e.fields["UserPrincipalName"] for e in window}
            if len(window) >= 6 and len(distinct) >= 3:
                results.append(_finding(
                    "auth", "AUTH-SPRAY", "medium", ip, window,
                    [f"{len(window)} invalid-password failures",
                     f"{len(distinct)} distinct identities within 15 minutes"],
                ))
                break
    return results


def _powershell_findings(rows: list[Row]) -> list[dict]:
    results: list[dict] = []
    for row in rows:
        f = row.fields
        if f["FileName"].lower() not in {"powershell.exe", "pwsh.exe"}:
            continue
        command = f["ProcessCommandLine"].lower()
        parent = f["InitiatingProcessFileName"].lower()
        encoded = bool(ENCODED_FLAG.search(command))
        markers = [marker for marker in PAYLOAD_MARKERS if marker in command]
        risky_parent = parent in OFFICE_OR_SCRIPT_PARENTS
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
    findings = (
        _auth_findings(rows) if hunt_id == "auth" else _powershell_findings(rows)
    )
    findings.sort(
        key=lambda finding: (
            finding["first_seen_utc"], finding["rule_id"], finding["entity"],
        )
    )
    return {
        "lab_scope": "synthetic offline telemetry; no live SIEM execution",
        "hunt_id": hunt_id,
        "input_sha256_normalized_utf8": digest,
        "events_evaluated": len(rows),
        "findings_count": len(findings),
        "time_window": "15 minutes" if hunt_id == "auth" else "per process event",
        "findings": findings,
    }
