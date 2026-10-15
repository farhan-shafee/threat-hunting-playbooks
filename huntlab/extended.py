"""Four *offline synthetic* hunt families.

The schemas in this file are invented normalization contracts for isolated
training fixtures. They do not claim parity with any EDR, SIEM, cloud
provider, packet sensor, or incident-response platform.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from heapq import heappop, heappush
from ipaddress import ip_address
from itertools import groupby
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from .engine import Row

EXT_SCHEMAS = {
    "lateral": (
        "Timestamp", "EventId", "EventType", "SourceHost", "TargetHost",
        "AccountName", "Outcome", "Detail", "Approved",
    ),
    "persistence": (
        "Timestamp", "EventId", "Host", "Actor", "ArtifactType",
        "ArtifactPath", "Action", "Executable", "SignerStatus", "Approved",
    ),
    "cloud": (
        "Timestamp", "EventId", "Provider", "Actor", "Target",
        "Operation", "Outcome", "Approved", "Scope",
    ),
    "egress": (
        "Timestamp", "EventId", "SourceHost", "DestinationIP",
        "SessionId", "Direction", "DestinationClass", "CounterMode",
        "Bytes", "Approved",
    ),
}
EXT_RULE_IDS = {
    "lateral": ("LATERAL-REMOTE-EXECUTION",),
    "persistence": ("PERSIST-UNAPPROVED-ENTRY", "PERSIST-RECREATION"),
    "cloud": ("CLOUD-UNAPPROVED-ADMIN-GRANT", "CLOUD-UNAPPROVED-ACCESS-KEY"),
    "egress": ("EGRESS-HIGH-VOLUME",),
}
EXT_RULE_PARAMETERS = {
    "LATERAL-REMOTE-EXECUTION": {
        "max_chain_seconds": 600,
        "strict_event_order": True,
        "connection_detail": "tcp445",
        "logon_detail": "network",
        "execution_details": ["service", "wmi"],
        "join_fields": ["SourceHost", "TargetHost", "AccountName on logon/execution"],
        "one_finding_per_execution": True,
    },
    "PERSIST-UNAPPROVED-ENTRY": {
        "actions": ["created", "modified"],
        "artifact_types": ["run_key", "scheduled_task", "service"],
        "requires_approved": "no",
        "unsigned_priority": "high",
        "other_signer_priority": "medium",
    },
    "PERSIST-RECREATION": {
        "delete_then_create_seconds": 3600,
        "strict_event_order": True,
        "requires_approved": "no",
        "match_fields": ["Host", "ArtifactType", "ArtifactPath"],
        "tie_policy": "simultaneous; cannot establish temporal order",
        "deletion_consumed_by": "first strictly later update group",
        "simultaneous_updates": "one candidate with all later unapproved changes",
    },
    "CLOUD-UNAPPROVED-ADMIN-GRANT": {
        "operations": [
            "role_grant", "app_consent", "policy_admin_grant", "pim_activation",
        ],
        "privileged_scopes": ["admin", "global_admin", "owner", "privileged_app"],
        "required_outcome": "success",
        "requires_approved": "no",
    },
    "CLOUD-UNAPPROVED-ACCESS-KEY": {
        "operation": "access_key_create",
        "required_outcome": "success",
        "requires_approved": "no",
    },
    "EGRESS-HIGH-VOLUME": {
        "minimum_bytes": 500_000_000,
        "window_seconds": 3600,
        "window_inclusive": True,
        "requires_direction": "outbound",
        "requires_destination_class": "external",
        "approved_yes_suppressed": True,
        "max_findings_per_host_destination_approval": 1,
        "cumulative_requires_first_observation_zero": True,
        "cumulative_interval_policy": "entire previous-to-current interval inside window",
        "overlong_intervals": "exclude contribution; emit warning",
        "delta_event_semantics": "per-event bytes attributed to event timestamp",
    },
}
WINDOWS = {
    "lateral": "10-minute strictly ordered three-event correlation",
    "persistence": "event review; 60-minute deletion/recreation",
    "cloud": "per successful change event",
    "egress": "60-minute rolling outbound byte total",
}

APPROVAL = {"yes", "no", "unknown"}
OUTCOMES = {"success", "denied", "pending"}
PERSIST_TYPES = {"run_key", "scheduled_task", "service"}
PERSIST_ACTIONS = {"created", "modified", "deleted"}
CLOUD_OPERATIONS = {
    "role_grant", "app_consent", "policy_admin_grant", "pim_activation",
    "pim_request", "access_key_create", "read_resource",
}
PRIVILEGED_SCOPES = frozenset(
    EXT_RULE_PARAMETERS["CLOUD-UNAPPROVED-ADMIN-GRANT"]["privileged_scopes"]
)


def _enum(row: Row, field: str, allowed: set[str], error_type: type[Exception]) -> str:
    value = row.fields[field]
    if value not in allowed:
        raise error_type(
            f"record {row.record}: {field} must be one of {', '.join(sorted(allowed))}"
        )
    return value


def _validate_row(hunt: str, row: Row, error_type: type[Exception]) -> None:
    f = row.fields
    _enum(row, "Approved", APPROVAL, error_type)
    if hunt == "lateral":
        event = _enum(row, "EventType", {"connection", "logon", "execution"}, error_type)
        _enum(row, "Outcome", OUTCOMES, error_type)
        if f["SourceHost"].casefold() == f["TargetHost"].casefold():
            raise error_type(f"record {row.record}: lateral source/target must differ")
        allowed_details = {
            "connection": {"tcp445", "other"},
            "logon": {"network", "remote_interactive", "other"},
            "execution": {"service", "wmi", "other"},
        }
        _enum(row, "Detail", allowed_details[event], error_type)
        if event != "connection" and f["AccountName"] == "-":
            raise error_type(f"record {row.record}: actor account required for {event}")
    elif hunt == "persistence":
        _enum(row, "ArtifactType", PERSIST_TYPES, error_type)
        action = _enum(row, "Action", PERSIST_ACTIONS, error_type)
        _enum(row, "SignerStatus", {"signed", "unsigned", "unknown"}, error_type)
        if action != "deleted" and f["Executable"] == "-":
            raise error_type(f"record {row.record}: executable required for {action}")
    elif hunt == "cloud":
        _enum(row, "Provider", {"aws", "entra"}, error_type)
        operation = _enum(row, "Operation", CLOUD_OPERATIONS, error_type)
        if ((f["Provider"] == "aws" and operation in {"app_consent", "pim_request", "pim_activation"})
                or (f["Provider"] == "entra" and operation in {"policy_admin_grant", "access_key_create"})):
            raise error_type(f"record {row.record}: incompatible provider/operation")
        _enum(row, "Outcome", OUTCOMES, error_type)
        _enum(
            row, "Scope",
            {"admin", "global_admin", "owner", "privileged_app", "standard", "read_only"},
            error_type,
        )
    else:
        _enum(row, "Direction", {"outbound", "inbound"}, error_type)
        _enum(row, "DestinationClass", {"external", "internal", "unknown"}, error_type)
        mode = _enum(row, "CounterMode", {"delta", "cumulative", "unknown"}, error_type)
        try:
            ip_address(f["DestinationIP"])
        except ValueError as exc:
            raise error_type(
                f"record {row.record}: DestinationIP is not an IP address"
            ) from exc
        if mode == "unknown":
            if f["Bytes"] != "?":
                raise error_type(
                    f"record {row.record}: unknown counter requires Bytes=?"
                )
        elif not f["Bytes"].isascii() or not f["Bytes"].isdigit():
            raise error_type(
                f"record {row.record}: Bytes must be a nonnegative integer"
            )
        elif int(f["Bytes"]) > 10**15:
            raise error_type(f"record {row.record}: implausibly large lab byte counter")


def _unique_rows(
    hunt: str, rows: list[Row], error_type: type[Exception]
) -> tuple[list[Row], int]:
    seen: dict[str, Row] = {}
    unique: list[Row] = []
    duplicates = 0
    for row in rows:
        _validate_row(hunt, row, error_type)
        event_id = row.fields["EventId"]
        if event_id in seen:
            if row.fields != seen[event_id].fields:
                raise error_type(
                    f"record {row.record}: conflicting duplicate EventId {event_id!r}"
                )
            duplicates += 1
            continue
        seen[event_id] = row
        unique.append(row)
    return unique, duplicates


def _lateral(rows: list[Row], finding: Callable) -> tuple[list[dict], list[str]]:
    """Strictly ordered, conservative three-source correlation.

    Treat a timestamp group as simultaneous. No CSV record order within that
    group may establish connection -> logon -> execution. Ambiguous same-time
    connection or logon updates block correlation for that actor/pair.
    """
    results: list[dict] = []
    last_connection: dict[tuple[str, str], Row] = {}
    last_logon: dict[tuple[str, str, str], tuple[Row, Row]] = {}
    window = timedelta(seconds=600)

    def pair_of(row: Row) -> tuple[str, str]:
        f = row.fields
        return f["SourceHost"].casefold(), f["TargetHost"].casefold()

    def actor_of(row: Row) -> tuple[str, str, str]:
        return (*pair_of(row), row.fields["AccountName"].casefold())

    for at, simultaneous in groupby(rows, key=lambda event: event.at):
        batch = list(simultaneous)
        connections: dict[tuple[str, str], list[Row]] = {}
        logons: dict[tuple[str, str, str], list[Row]] = {}
        for row in batch:
            if row.fields["EventType"] == "connection":
                connections.setdefault(pair_of(row), []).append(row)
            elif row.fields["EventType"] == "logon":
                logons.setdefault(actor_of(row), []).append(row)

        # First evaluate executions against strictly *prior* observations.
        for row in batch:
            f = row.fields
            if (f["EventType"] != "execution"
                    or f["Outcome"] != "success"
                    or f["Detail"] not in {"service", "wmi"}
                    or f["Approved"] == "yes"):
                continue
            pair = pair_of(row)
            actor = actor_of(row)
            if pair in connections or actor in logons:
                continue  # same-time sensor evidence has no reliable order
            chain = last_logon.get(actor)
            if chain is None:
                continue
            connection, logon = chain
            if not (connection.at < logon.at < row.at
                    and row.at - connection.at <= window):
                continue
            results.append(finding(
                "lateral", "LATERAL-REMOTE-EXECUTION",
                "high" if f["Approved"] == "no" else "medium",
                f"{f['SourceHost']} -> {f['TargetHost']} | {f['AccountName']}",
                [connection, logon, row],
                [
                    "outbound TCP/445 connection before target network logon",
                    f"successful remote execution: {f['Detail']}",
                    f"execution authorization (synthetic annotation): {f['Approved']}",
                    "joined by host pair and account, not a verified remote session",
                ],
            ))

        # Failed/multiple simultaneous logons invalidate stale actor joins.
        for actor, events in logons.items():
            last_logon.pop(actor, None)
            if len(events) != 1 or actor[:2] in connections:
                continue
            row = events[0]
            conn = last_connection.get(actor[:2])
            if (conn is not None and row.fields["Outcome"] == "success"
                    and row.fields["Detail"] == "network"
                    and conn.at < at and at - conn.at <= window):
                last_logon[actor] = (conn, row)

        # Finally publish same-time connections for *future* logons only.
        for pair, events in connections.items():
            last_connection.pop(pair, None)
            if len(events) == 1:
                row = events[0]
                if row.fields["Outcome"] == "success" and row.fields["Detail"] == "tcp445":
                    last_connection[pair] = row

    warnings = []
    for component in ("connection", "logon", "execution"):
        if not any(row.fields["EventType"] == component for row in rows):
            warnings.append(f"missing {component} telemetry; no complete chain can be established")
    return results, warnings


def _persistence(rows: list[Row], finding: Callable) -> tuple[list[dict], list[str]]:
    results: list[dict] = []
    deletions: dict[tuple[str, str, str], Row] = {}
    window = timedelta(seconds=3600)

    def artifact_key(row: Row) -> tuple[str, str, str]:
        fields = row.fields
        return (
            fields["Host"].casefold(), fields["ArtifactType"],
            fields["ArtifactPath"].casefold(),
        )

    for at, same_time in groupby(rows, key=lambda event: event.at):
        batch = list(same_time)
        artifacts: dict[tuple[str, str, str], list[Row]] = {}
        for row in batch:
            fields = row.fields
            artifacts.setdefault(artifact_key(row), []).append(row)
            if fields["Action"] == "deleted" or fields["Approved"] != "no":
                continue
            results.append(finding(
                "persistence", "PERSIST-UNAPPROVED-ENTRY",
                "high" if fields["SignerStatus"] == "unsigned" else "medium",
                f"{fields['Host']} | {fields['ArtifactType']} | {fields['ArtifactPath']}",
                [row], [
                    f"artifact {fields['Action']}; executable: {fields['Executable']}",
                    f"signer metadata: {fields['SignerStatus']}",
                    "approval=no is a synthetic annotation, not source verification",
                ],
            ))

        # A timestamp group is simultaneous: row order cannot establish which
        # tied action preceded a deletion, and a tied update cannot consume it.
        for key, group in sorted(artifacts.items()):
            earlier = deletions.get(key)
            changes = [r for r in group if r.fields["Action"] != "deleted"]
            unapproved = [r for r in changes if r.fields["Approved"] == "no"]
            if earlier is not None and earlier.at < at and changes:
                if at - earlier.at <= window and unapproved:
                    actor = min(unapproved, key=lambda r: r.fields["EventId"]).fields
                    results.append(finding(
                        "persistence", "PERSIST-RECREATION", "high",
                        f"{actor['Host']} | {actor['ArtifactType']} | {actor['ArtifactPath']}",
                        [earlier, *unapproved], [
                            "same artifact path deleted and recreated within 60 minutes",
                            "recreation approval=no (synthetic annotation)",
                        ],
                    ))
                # An actual *later* update uses up the pending deletion,
                # including authorized changes, so it cannot be reused.
                deletions.pop(key, None)

            tied_deletions = [r for r in group if r.fields["Action"] == "deleted"]
            if tied_deletions:
                # Deterministic selection for multiple deletes at one instant.
                # Tied updates cannot establish temporal order against them.
                deletions[key] = min(
                    tied_deletions, key=lambda r: r.fields["EventId"]
                )
    return results, []


def _cloud(rows: list[Row], finding: Callable) -> tuple[list[dict], list[str]]:
    results: list[dict] = []
    sensitive = set(EXT_RULE_PARAMETERS["CLOUD-UNAPPROVED-ADMIN-GRANT"]["operations"])
    for row in rows:
        f = row.fields
        if f["Approved"] != "no" or f["Outcome"] != "success":
            continue
        if f["Operation"] in sensitive and f["Scope"] in PRIVILEGED_SCOPES:
            results.append(finding(
                "cloud", "CLOUD-UNAPPROVED-ADMIN-GRANT", "high",
                f"{f['Provider']} | {f['Target']} | {f['Actor']}",
                [row], [
                    f"successful {f['Operation']} with {f['Scope']} scope",
                    "approval=no is a synthetic annotation; confirm change record",
                    "successful administrative change is not proof of stolen identity",
                ],
            ))
        elif f["Operation"] == "access_key_create":
            results.append(finding(
                "cloud", "CLOUD-UNAPPROVED-ACCESS-KEY", "medium",
                f"{f['Provider']} | {f['Target']} | {f['Actor']}",
                [row], [
                    "successful access-key creation recorded",
                    "approval=no is a synthetic annotation; subsequent key usage unverified",
                ],
            ))
    return results, []


def _egress(
    rows: list[Row], finding: Callable, error_type: type[Exception]
) -> tuple[list[dict], list[str]]:
    results: list[dict] = []
    warnings: list[str] = []
    sessions: dict[tuple[str, str, str], list[Row]] = {}
    for row in rows:
        f = row.fields
        key = (f["SourceHost"].casefold(), str(ip_address(f["DestinationIP"])), f["SessionId"])
        sessions.setdefault(key, []).append(row)

    # A session has ONE counter representation and ONE routing classification.
    # Never calculate bytes from a nonzero first cumulative observation:
    # without the zero baseline, total transmission cannot be established.
    increments: dict[tuple[str, str, str], list[tuple[Row, int, list[Row]]]] = {}
    for key, events in sorted(sessions.items()):
        first = events[0].fields
        dimensions = ("CounterMode", "Direction", "DestinationClass", "Approved")
        for row in events[1:]:
            if any(row.fields[name] != first[name] for name in dimensions):
                raise error_type(
                    f"record {row.record}: inconsistent counter/session dimensions"
                )
        mode = first["CounterMode"]
        if mode == "unknown":
            warnings.append(f"unquantified counter for session {key[2]}")
            continue
        if mode == "cumulative" and int(first["Bytes"]) != 0:
            warnings.append(f"cumulative session {key[2]} missing zero baseline")
            continue
        if mode == "cumulative" and any(
            prior.at == current.at for prior, current in zip(events, events[1:])
        ):
            warnings.append(f"cumulative session {key[2]} has simultaneous counter samples")
            continue  # no temporal order can be inferred from CSV row position
        previous = events[0] if mode == "cumulative" else None
        contributions = []
        for row in events:
            if mode == "delta":
                amount = int(row.fields["Bytes"])
                sources = [row]
            elif previous is row:
                continue  # zero baseline observation, not a transfer
            else:
                earlier_value = int(previous.fields["Bytes"])
                current_value = int(row.fields["Bytes"])
                if current_value < earlier_value:
                    warnings.append(f"cumulative counter reset in session {key[2]}")
                    contributions = []  # abandon entire ambiguous session
                    break
                amount = current_value - earlier_value
                sources = [previous, row]
                previous = row
            contributions.append((row, amount, sources))
        if contributions:
            increments[key] = contributions

    by_pair: dict[tuple[str, str, str], list[tuple[Row, int, list[Row]]]] = {}
    for key, events in increments.items():
        first = sessions[key][0].fields
        if (first["Direction"] != "outbound"
                or first["DestinationClass"] != "external"
                or first["Approved"] == "yes"):
            continue
        pair = (key[0], key[1], first["Approved"])
        by_pair.setdefault(pair, []).extend(events)

    threshold = EXT_RULE_PARAMETERS["EGRESS-HIGH-VOLUME"]["minimum_bytes"]
    lookback = timedelta(seconds=3600)
    for (source, target, approved), events in sorted(by_pair.items()):
        events.sort(key=lambda e: (e[0].at, e[0].record))
        # Keep only contributions whose WHOLE observation interval falls
        # inside the rolling hour. A cumulative delta is observed across
        # [previous sample, current sample], not at the endpoint alone.
        # A min-heap on interval START is necessary: overlapping sessions
        # can have different start times even when their ends are sorted.
        active: list[tuple[datetime, int, int, list[Row]]] = []
        total = 0
        for at_row, amount, ancestors in events:
            interval_start = ancestors[0].at
            if at_row.at - interval_start > lookback:
                warnings.append(
                    "cumulative observation interval exceeds 60-minute window "
                    f"for session {at_row.fields['SessionId']}"
                )
                continue
            heappush(active, (interval_start, at_row.record, amount, ancestors))
            total += amount
            cutoff = at_row.at - lookback
            while active and active[0][0] < cutoff:
                total -= heappop(active)[2]
            if total < threshold:
                continue
            evidence = {
                record.record: record
                for _, _, _, required in active for record in required
            }
            results.append(finding(
                "egress", "EGRESS-HIGH-VOLUME",
                "high" if approved == "no" else "medium",
                f"{events[0][0].fields['SourceHost']} -> {target}", list(evidence.values()), [
                    f"{total} observed outbound incremental bytes in rolling 60-minute window",
                    "external destination classification is a synthetic annotation",
                    f"transfer authorization (synthetic annotation): {approved}",
                    "cumulative contributions require prior observed counter values",
                ],
            ))
            break  # one candidate for a host/destination/approval group
    return results, sorted(set(warnings))


def evaluate_extended(
    hunt: str,
    rows: list[Row],
    finding: Callable,
    error_type: type[Exception],
) -> tuple[list[dict], int, int, list[str]]:
    if hunt not in EXT_SCHEMAS:
        raise error_type(f"unknown extended hunt: {hunt}")
    unique, duplicate_count = _unique_rows(hunt, rows, error_type)
    if hunt == "lateral":
        findings, warnings = _lateral(unique, finding)
    elif hunt == "persistence":
        findings, warnings = _persistence(unique, finding)
    elif hunt == "cloud":
        findings, warnings = _cloud(unique, finding)
    else:
        findings, warnings = _egress(unique, finding, error_type)
    return findings, len(unique), duplicate_count, warnings
