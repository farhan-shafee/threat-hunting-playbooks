"""Regression cases for independently reviewed Phase 2 correlation semantics.

Expected results are asserted explicitly. No network, tenant, credentials,
remote response commands or generated expected-result fixtures.
"""
from __future__ import annotations

import csv
from itertools import permutations
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from huntlab import run_hunt
from huntlab.engine import SCHEMAS


def time(minute: int, suffix: str = "") -> str:
    return f"2026-05-01T08:{minute:02}:00{suffix}Z"


def persistence_event(identifier: str, timestamp: str, action: str,
                      approved: str = "no") -> dict[str, str]:
    return {
        "Timestamp": timestamp,
        "EventId": identifier,
        "Host": "LAB-1",
        "Actor": "analyst@lab.local",
        "ArtifactType": "run_key",
        "ArtifactPath": r"HKCU\Software\Lab\Autorun",
        "Action": action,
        "Executable": "-" if action == "deleted" else r"C:\Lab\agent.exe",
        "SignerStatus": "unknown" if action == "deleted" else "unsigned",
        "Approved": approved,
    }


def transfer_event(identifier: str, timestamp: str, bytes: int,
                   *, session: str = "s1", mode: str = "cumulative") -> dict[str, str]:
    return {
        "Timestamp": timestamp,
        "EventId": identifier,
        "SourceHost": "LAB-1",
        "DestinationIP": "203.0.113.18",
        "SessionId": session,
        "Direction": "outbound",
        "DestinationClass": "external",
        "CounterMode": mode,
        "Bytes": str(bytes),
        "Approved": "no",
    }


class ReviewCorrectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)

    def evaluate(self, hunt: str, rows: list[dict[str, str]]) -> dict:
        path = self.folder / "test.csv"
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=SCHEMAS[hunt], lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        return run_hunt(hunt, path)

    @staticmethod
    def recreated(report: dict) -> list[dict]:
        return [f for f in report["findings"] if f["rule_id"] == "PERSIST-RECREATION"]

    def test_tied_creation_does_not_consume_pending_deletion_in_either_order(self):
        deletion = persistence_event("delete", time(0), "deleted")
        tied = persistence_event("tied", time(0), "created")
        later = persistence_event("later", time(5), "created")
        for simultaneous in ((deletion, tied), (tied, deletion)):
            with self.subTest(order=[r["EventId"] for r in simultaneous]):
                result = self.evaluate("persistence", [*simultaneous, later])
                findings = self.recreated(result)
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]["first_seen_utc"], time(0))
                self.assertEqual(findings[0]["last_seen_utc"], time(5))
                expected_deletion_ordinal = (
                    2 if simultaneous[0]["EventId"] == "delete" else 3
                )
                self.assertEqual(
                    findings[0]["evidence_records"], [expected_deletion_ordinal, 4]
                )

    def test_tied_modification_cannot_precede_deletion(self):
        deletion = persistence_event("d", time(0), "deleted")
        modification = persistence_event("m", time(0), "modified")
        later = persistence_event("l", time(4), "modified")
        for simultaneous in ((deletion, modification), (modification, deletion)):
            self.assertEqual(
                len(self.recreated(self.evaluate("persistence", [*simultaneous, later]))),
                1,
            )

    def test_identical_timestamp_deletion_and_only_creation_never_correlate(self):
        first = persistence_event("d", time(0), "deleted")
        second = persistence_event("c", time(0), "created")
        for simultaneous in ((first, second), (second, first)):
            self.assertEqual(
                len(self.recreated(self.evaluate("persistence", list(simultaneous)))),
                0,
            )

    def test_tied_approved_change_cannot_erase_same_timestamp_deletion(self):
        deletion = persistence_event("d", time(0), "deleted")
        tied_approved = persistence_event("a", time(0), "created", "yes")
        later = persistence_event("l", time(6), "created")
        for pair in ((deletion, tied_approved), (tied_approved, deletion)):
            self.assertEqual(
                len(self.recreated(self.evaluate("persistence", [*pair, later]))),
                1,
            )

    def test_strictly_later_approved_change_does_consume_deletion(self):
        report = self.evaluate("persistence", [
            persistence_event("d", time(0), "deleted"),
            persistence_event("a", time(1), "created", "yes"),
            persistence_event("l", time(5), "modified"),
        ])
        self.assertEqual(self.recreated(report), [])
        self.assertEqual(report["rule_versions"]["PERSIST-RECREATION"], "1.0.1")

    def test_simultaneous_unapproved_changes_from_prior_deletion_are_one_case(self):
        deletion = persistence_event("d", time(0), "deleted")
        a = persistence_event("a", time(5), "created")
        b = persistence_event("b", time(5), "modified")
        for simultaneous in ((a, b), (b, a)):
            findings = self.recreated(self.evaluate(
                "persistence", [deletion, *simultaneous]
            ))
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["evidence_records"], [2, 3, 4])
            self.assertEqual(findings[0]["first_seen_utc"], time(0))
            self.assertEqual(findings[0]["last_seen_utc"], time(5))

    def test_multiple_tied_deletions_choose_stable_event_identity(self):
        deletes = (
            persistence_event("z", time(0), "deleted"),
            persistence_event("a", time(0), "deleted"),
        )
        later = persistence_event("later", time(1), "created")
        for pair in permutations(deletes):
            report = self.evaluate("persistence", [*pair, later])
            recreated = self.recreated(report)
            self.assertEqual(len(recreated), 1)
            # The selected deletion is always EventId="a", regardless of CSV order.
            ordinal_a = 2 if pair[0]["EventId"] == "a" else 3
            self.assertEqual(recreated[0]["evidence_records"], [ordinal_a, 4])

    def test_cumulative_two_hour_observation_is_not_one_hour_transfer(self):
        report = self.evaluate("egress", [
            transfer_event("baseline", time(0), 0),
            transfer_event("twohours", "2026-05-01T10:00:00Z", 600_000_000),
        ])
        self.assertEqual(report["findings_count"], 0)
        self.assertEqual(
            report["data_quality_warnings"],
            ["cumulative observation interval exceeds 60-minute window for session s1"],
        )
        self.assertEqual(report["rule_versions"]["EGRESS-HIGH-VOLUME"], "1.0.1")

    def test_cumulative_exact_60_minute_boundary_is_inclusive(self):
        base = transfer_event("baseline", time(0), 0)
        for final_time, expected in (
            ("2026-05-01T09:00:00Z", 1),
            ("2026-05-01T09:00:00.000001Z", 0),
        ):
            with self.subTest(final_time=final_time):
                report = self.evaluate("egress", [
                    base, transfer_event("reading", final_time, 500_000_000)
                ])
                self.assertEqual(report["findings_count"], expected)
                self.assertEqual(bool(report["data_quality_warnings"]), not bool(expected))

    def test_two_adjacent_fifty_minute_intervals_are_not_one_hour_volume(self):
        report = self.evaluate("egress", [
            transfer_event("zero", time(0), 0),
            transfer_event("first", time(50), 300_000_000),
            transfer_event("second", "2026-05-01T09:40:00Z", 600_000_000),
        ])
        self.assertEqual(report["findings_count"], 0)
        self.assertEqual(report["data_quality_warnings"], [])

    def test_two_adjacent_thirty_minute_intervals_are_in_same_hour(self):
        report = self.evaluate("egress", [
            transfer_event("zero", time(0), 0),
            transfer_event("first", time(30), 300_000_000),
            transfer_event("second", "2026-05-01T09:00:00Z", 600_000_000),
        ])
        self.assertEqual(report["findings_count"], 1)
        self.assertEqual(report["findings"][0]["evidence_records"], [2, 3, 4])
        self.assertEqual(report["findings"][0]["first_seen_utc"], time(0))

    def test_interleaved_sessions_expire_on_interval_start_not_end(self):
        report = self.evaluate("egress", [
            transfer_event("zeroA", time(0), 0, session="A"),
            transfer_event("a300", time(50), 300_000_000, session="A"),
            transfer_event("zeroB", time(51), 0, session="B"),
            transfer_event("b100", time(59), 100_000_000, session="B"),
            transfer_event("c200", "2026-05-01T09:10:00Z", 200_000_000,
                           session="C", mode="delta"),
        ])
        self.assertEqual(report["findings_count"], 0)
        self.assertEqual(report["data_quality_warnings"], [])

    def test_overlong_interval_can_be_followed_by_valid_short_one(self):
        report = self.evaluate("egress", [
            transfer_event("zero", time(0), 0),
            transfer_event("long", "2026-05-01T10:00:00Z", 600_000_000),
            transfer_event("short", "2026-05-01T10:10:00Z", 1_150_000_000),
        ])
        self.assertEqual(report["findings_count"], 1)
        self.assertEqual(report["findings"][0]["evidence_records"], [3, 4])
        self.assertEqual(
            report["data_quality_warnings"],
            ["cumulative observation interval exceeds 60-minute window for session s1"],
        )

    def test_delta_bucket_events_remain_independently_attributed(self):
        report = self.evaluate("egress", [
            transfer_event("first", time(0), 260_000_000, mode="delta"),
            transfer_event("second", "2026-05-01T09:00:00Z",
                           240_000_000, mode="delta"),
        ])
        self.assertEqual(report["findings_count"], 1)
        self.assertEqual(report["findings"][0]["evidence_records"], [2, 3])


if __name__ == "__main__":
    unittest.main()
