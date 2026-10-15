"""Independent outcomes and adversarial controls for the four new offline hunts."""
from __future__ import annotations

import csv
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from huntlab import HuntInputError, run_hunt
from huntlab.engine import SCHEMAS

ROOT = Path(__file__).resolve().parents[1]
HUNTS = ("lateral", "persistence", "cloud", "egress")
MANIFEST = json.loads(
    (ROOT / "tests" / "expected" / "phase2-v1.json").read_text(encoding="utf-8")
)


def stamp(minutes=0, seconds=0, micros=0):
    at = datetime(2026, 5, 1, 8, tzinfo=timezone.utc) + timedelta(
        minutes=minutes, seconds=seconds, microseconds=micros
    )
    return at.isoformat().replace("+00:00", "Z")


def lateral(kind, identifier, minutes=0, **updates):
    row = dict(
        Timestamp=stamp(minutes), EventId=identifier, EventType=kind,
        SourceHost="LAPTOP-1", TargetHost="SERVER-1", AccountName="lab@lab.local",
        Outcome="success", Detail={"connection": "tcp445", "logon": "network",
                                   "execution": "service"}[kind], Approved="no",
    )
    if kind == "connection":
        row["AccountName"] = "-"
    row.update(updates)
    return row


def persistence(action, identifier, minutes=0, **updates):
    row = dict(
        Timestamp=stamp(minutes), EventId=identifier, Host="LAB-1",
        Actor="analyst@lab.local", ArtifactType="run_key",
        ArtifactPath=r"HKCU\Software\Lab\Autorun", Action=action,
        Executable=r"C:\Users\Lab\agent.exe" if action != "deleted" else "-",
        SignerStatus="unsigned" if action != "deleted" else "unknown",
        Approved="no",
    )
    row.update(updates)
    return row


def cloud(operation, identifier, minutes=0, **updates):
    row = dict(
        Timestamp=stamp(minutes), EventId=identifier, Provider="entra",
        Actor="operator@lab.local", Target="role-1", Operation=operation,
        Outcome="success", Approved="no", Scope="admin",
    )
    row.update(updates)
    return row


def egress(identifier, minutes=0, **updates):
    row = dict(
        Timestamp=stamp(minutes), EventId=identifier, SourceHost="LAB-1",
        DestinationIP="203.0.113.18", SessionId="session-A",
        Direction="outbound", DestinationClass="external",
        CounterMode="delta", Bytes="300000000", Approved="no",
    )
    row.update(updates)
    return row


class Phase2Cases(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)

    def evaluate(self, hunt, rows):
        path = self.folder / f"{hunt}.csv"
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=SCHEMAS[hunt], lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        return run_hunt(hunt, path)

    def test_hand_authored_expected_fixture_outcomes(self):
        for hunt in HUNTS:
            with self.subTest(hunt=hunt):
                source = ROOT / "samples" / "logs" / f"{hunt}-lab-v1.csv"
                result = run_hunt(hunt, source)
                expected = MANIFEST[hunt]
                for key in ("events_evaluated", "events_unique",
                            "duplicate_events_suppressed", "time_window"):
                    self.assertEqual(result[key], expected[key])
                self.assertEqual(result["data_quality_warnings"], expected["warnings"])
                self.assertEqual(result["result_schema_version"], "1.1")
                self.assertEqual(result["findings_count"], len(expected["findings"]))
                self.assertEqual(len(result["rule_versions"]), len(set(
                    candidate["rule_id"] for candidate in expected["findings"]
                )))
                self.assertTrue(all(v == "1.0.0" for v in result["rule_versions"].values()))
                normalized = source.read_bytes().decode("utf-8-sig").replace("\r\n", "\n")
                digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
                self.assertEqual(result["input_sha256_normalized_utf8"], digest)
                for actual, authored in zip(result["findings"], expected["findings"]):
                    for key in (
                        "rule_id", "severity", "entity", "first_seen_utc",
                        "last_seen_utc", "evidence_records",
                    ):
                        self.assertEqual(actual[key], authored[key], f"{hunt} {key}")
                    self.assertEqual(actual["hunt_id"], hunt)
                    self.assertEqual(
                        actual["disposition"], "review required; not confirmed compromise"
                    )
                    for text in authored["signal_contains"]:
                        self.assertTrue(
                            any(text in signal for signal in actual["signals"]),
                            f"{hunt}: missing signal {text}",
                        )
                self.assertEqual(result, run_hunt(hunt, source))

    def test_cli_reports_match_independently_authored_cases(self):
        for hunt in HUNTS:
            with self.subTest(hunt=hunt):
                command = [sys.executable, "-B", str(ROOT / "scripts" / "run_hunt.py"),
                           "--hunt", hunt, "--input",
                           str(ROOT / "samples" / "logs" / f"{hunt}-lab-v1.csv")]
                runs = [subprocess.run(command, text=True, capture_output=True, check=False)
                        for _ in range(2)]
                self.assertTrue(all(item.returncode == 0 for item in runs))
                self.assertEqual(runs[0].stdout, runs[1].stdout)
                obj = json.loads(runs[0].stdout)
                self.assertEqual(obj["findings_count"], len(MANIFEST[hunt]["findings"]))

    def test_complete_ordered_lateral_chain(self):
        case = self.evaluate("lateral", [
            lateral("connection", "c", 0),
            lateral("logon", "l", 3),
            lateral("execution", "e", 7),
        ])
        self.assertEqual(case["findings_count"], 1)
        self.assertEqual(case["findings"][0]["evidence_records"], [2, 3, 4])
        self.assertEqual(case["findings"][0]["severity"], "high")

    def test_lateral_reverse_order_does_not_claim_chain(self):
        case = self.evaluate("lateral", [
            lateral("execution", "e", 1),
            lateral("logon", "l", 2),
            lateral("connection", "c", 3),
        ])
        self.assertEqual(case["findings_count"], 0)

    def test_lateral_equal_timestamps_are_not_temporal_evidence(self):
        events = [
            lateral("connection", "c", 0),
            lateral("logon", "l", 0),
            lateral("execution", "e", 0),
        ]
        for order in (events, list(reversed(events))):
            self.assertEqual(self.evaluate("lateral", order)["findings_count"], 0)

    def test_lateral_exact_600_second_boundary(self):
        prefix = [lateral("connection", "c"), lateral("logon", "l", 1)]
        for micros, expected in ((0, 1), (1, 0)):
            with self.subTest(micros=micros):
                exec_event = lateral("execution", "e", 10)
                exec_event["Timestamp"] = stamp(minutes=10, micros=micros)
                self.assertEqual(
                    self.evaluate("lateral", prefix + [exec_event])["findings_count"],
                    expected,
                )

    def test_lateral_same_time_logon_and_execution_cannot_use_stale_logon(self):
        known = [lateral("connection", "c", 0), lateral("logon", "l", 1)]
        tied = [
            lateral("logon", "new", 2, Outcome="denied"),
            lateral("execution", "exec", 2),
        ]
        for group in (tied, list(reversed(tied))):
            with self.subTest(order=[r["EventId"] for r in group]):
                self.assertEqual(self.evaluate("lateral", known + group)["findings_count"], 0)

    def test_lateral_simultaneous_connection_and_logon_not_joined(self):
        tied = [lateral("connection", "c", 0), lateral("logon", "l", 0)]
        for group in (tied, list(reversed(tied))):
            self.assertEqual(self.evaluate(
                "lateral", group + [lateral("execution", "e", 1)]
            )["findings_count"], 0)

    def test_lateral_requires_matching_target_and_account(self):
        prefix = [lateral("connection", "c"), lateral("logon", "l", 1)]
        for override in ({"TargetHost": "OTHER-SERVER"},
                         {"AccountName": "another@lab.local"}):
            case = self.evaluate("lateral", prefix + [
                lateral("execution", "e", 2, **override)
            ])
            self.assertEqual(case["findings_count"], 0)

    def test_lateral_failed_logon_and_unapproved_execution(self):
        events = [
            lateral("connection", "c"),
            lateral("logon", "l", 1, Outcome="denied"),
            lateral("execution", "e", 2),
        ]
        self.assertEqual(self.evaluate("lateral", events)["findings_count"], 0)
        events[1]["Outcome"] = "success"
        events[2]["Approved"] = "yes"
        self.assertEqual(self.evaluate("lateral", events)["findings_count"], 0)
        events[2]["Approved"] = "unknown"
        self.assertEqual(self.evaluate("lateral", events)["findings"][0]["severity"], "medium")

    def test_lateral_missing_sensor_telemetry_is_explicit(self):
        report = self.evaluate("lateral", [lateral("execution", "e", 0)])
        self.assertEqual(report["findings_count"], 0)
        self.assertEqual(len(report["data_quality_warnings"]), 2)
        self.assertIn("missing connection telemetry", report["data_quality_warnings"][0])

    def test_lateral_requires_account_field(self):
        with self.assertRaisesRegex(HuntInputError, "actor account required"):
            self.evaluate("lateral", [lateral("logon", "l", AccountName="-")])

    def test_persistence_unsigned_unapproved_is_high(self):
        report = self.evaluate("persistence", [persistence("created", "p")])
        self.assertEqual(report["findings"][0]["rule_id"], "PERSIST-UNAPPROVED-ENTRY")
        self.assertEqual(report["findings"][0]["severity"], "high")

    def test_persistence_signed_unapproved_still_reviewed(self):
        report = self.evaluate("persistence", [
            persistence("created", "p", SignerStatus="signed")
        ])
        self.assertEqual(report["findings"][0]["severity"], "medium")

    def test_persistence_approved_and_unknown_do_not_assert_unapproved(self):
        for approved in ("yes", "unknown"):
            with self.subTest(approved=approved):
                report = self.evaluate("persistence", [
                    persistence("created", "p", Approved=approved)
                ])
                self.assertEqual(report["findings_count"], 0)

    def test_persistence_recreation_exact_boundary_and_microsecond(self):
        earlier = persistence("deleted", "p", 0)
        for microseconds, expected in ((0, 1), (1, 0)):
            event = persistence("created", "q", 60)
            event["Timestamp"] = stamp(minutes=60, micros=microseconds)
            report = self.evaluate("persistence", [earlier, event])
            recreated = [x for x in report["findings"] if x["rule_id"] == "PERSIST-RECREATION"]
            self.assertEqual(len(recreated), expected)

    def test_persistence_recreation_requires_strictly_earlier_deletion(self):
        rows = [persistence("deleted", "p"), persistence("created", "q")]
        self.assertFalse(any(
            f["rule_id"] == "PERSIST-RECREATION"
            for f in self.evaluate("persistence", rows)["findings"]
        ))

    def test_persistence_authorized_recreation_consumes_deletion(self):
        events = [
            persistence("deleted", "del", 0),
            persistence("created", "approved", 1, Approved="yes"),
            persistence("modified", "later", 2, Approved="no"),
        ]
        findings = self.evaluate("persistence", events)["findings"]
        self.assertEqual([f["rule_id"] for f in findings],
                         ["PERSIST-UNAPPROVED-ENTRY"])

    def test_persistence_recreation_case_insensitive_key(self):
        old = persistence("deleted", "p", 0)
        new = persistence("created", "q", 2, Host="lab-1",
                          ArtifactPath=old["ArtifactPath"].lower())
        report = self.evaluate("persistence", [old, new])
        self.assertEqual(
            len([x for x in report["findings"] if x["rule_id"] == "PERSIST-RECREATION"]), 1
        )

    def test_persistence_deletion_alone_does_not_trigger(self):
        self.assertEqual(
            self.evaluate("persistence", [persistence("deleted", "p")])["findings_count"], 0
        )

    def test_persistence_missing_executable_rejected(self):
        with self.assertRaisesRegex(HuntInputError, "executable required"):
            self.evaluate("persistence", [persistence("created", "p", Executable="-")])

    def test_cloud_denied_grant_and_pim_request_do_not_imply_completion(self):
        rows = [
            cloud("role_grant", "a", 0, Outcome="denied"),
            cloud("pim_request", "b", 1),
            cloud("pim_activation", "c", 2, Outcome="pending"),
        ]
        self.assertEqual(self.evaluate("cloud", rows)["findings_count"], 0)

    def test_cloud_completed_pim_activation_requires_privileged_scope(self):
        expected = cloud("pim_activation", "x", 1, Scope="global_admin")
        self.assertEqual(self.evaluate("cloud", [expected])["findings_count"], 1)
        expected["Scope"] = "read_only"
        self.assertEqual(self.evaluate("cloud", [expected])["findings_count"], 0)

    def test_cloud_authorized_change_is_suppressed(self):
        case = cloud("role_grant", "x", Approved="yes", Scope="admin")
        self.assertEqual(self.evaluate("cloud", [case])["findings_count"], 0)

    def test_cloud_completed_unapproved_access_key_is_review_candidate(self):
        row = cloud("access_key_create", "x", Provider="aws", Scope="standard")
        case = self.evaluate("cloud", [row])
        self.assertEqual(case["findings"][0]["rule_id"], "CLOUD-UNAPPROVED-ACCESS-KEY")
        row["Outcome"] = "denied"
        self.assertEqual(self.evaluate("cloud", [row])["findings_count"], 0)

    def test_cloud_disallows_incompatible_provider_and_operation(self):
        for row in (
            cloud("pim_activation", "x", Provider="aws"),
            cloud("access_key_create", "x", Provider="entra"),
            cloud("app_consent", "x", Provider="aws"),
        ):
            with self.assertRaisesRegex(HuntInputError, "incompatible provider"):
                self.evaluate("cloud", [row])

    def test_cloud_invalid_outcome_fail_closed(self):
        with self.assertRaisesRegex(HuntInputError, "Outcome must be"):
            self.evaluate("cloud", [cloud("role_grant", "x", Outcome="approved")])

    def test_egress_threshold_exact_inclusive(self):
        for amount, count in ((499_999_999, 0), (500_000_000, 1)):
            with self.subTest(amount=amount):
                report = self.evaluate("egress", [
                    egress("n", Bytes=str(amount))
                ])
                self.assertEqual(report["findings_count"], count)

    def test_egress_two_sessions_with_same_pair_combine(self):
        report = self.evaluate("egress", [
            egress("n1", 0, Bytes="270000000", SessionId="A"),
            egress("n2", 5, Bytes="230000000", SessionId="B"),
        ])
        self.assertEqual(report["findings"][0]["evidence_records"], [2, 3])

    def test_egress_rolling_hour_boundary(self):
        for micros, count in ((0, 1), (1, 0)):
            event = egress("n2", 60, Bytes="240000000")
            event["Timestamp"] = stamp(minutes=60, micros=micros)
            report = self.evaluate("egress", [
                egress("n1", 0, Bytes="260000000"), event,
            ])
            self.assertEqual(report["findings_count"], count)

    def test_egress_approved_internal_inbound_are_negative_controls(self):
        samples = (
            {"Approved": "yes"},
            {"DestinationClass": "internal"},
            {"DestinationClass": "unknown"},
            {"Direction": "inbound"},
        )
        for attrs in samples:
            with self.subTest(attrs=attrs):
                report = self.evaluate("egress", [egress("n", Bytes="900000000", **attrs)])
                self.assertEqual(report["findings_count"], 0)

    def test_egress_unknown_approval_still_medium_candidate(self):
        report = self.evaluate("egress", [
            egress("n", Bytes="500000000", Approved="unknown")
        ])
        self.assertEqual(report["findings"][0]["severity"], "medium")

    def test_egress_cumulative_with_zero_baseline(self):
        report = self.evaluate("egress", [
            egress("n1", 0, CounterMode="cumulative", Bytes="0"),
            egress("n2", 1, CounterMode="cumulative", Bytes="310000000"),
            egress("n3", 2, CounterMode="cumulative", Bytes="520000000"),
        ])
        self.assertEqual(report["findings_count"], 1)
        self.assertEqual(report["findings"][0]["evidence_records"], [2, 3, 4])
        self.assertIn("520000000", report["findings"][0]["signals"][0])

    def test_egress_tied_cumulative_samples_cannot_imply_progress(self):
        events = [
            egress("baseline", 0, CounterMode="cumulative", Bytes="0"),
            egress("reading", 0, CounterMode="cumulative", Bytes="700000000"),
        ]
        for order in (events, list(reversed(events))):
            report = self.evaluate("egress", order)
            self.assertEqual(report["findings_count"], 0)
            self.assertTrue(any(
                "simultaneous counter samples" in warning
                or "missing zero baseline" in warning
                for warning in report["data_quality_warnings"]
            ))

    def test_egress_unsorted_source_observations_ordered_by_timestamp(self):
        observations = [
            egress("n2", 2, CounterMode="cumulative", Bytes="600000000"),
            egress("n1", 0, CounterMode="cumulative", Bytes="0"),
        ]
        report = self.evaluate("egress", observations)
        self.assertEqual(report["findings_count"], 1)
        self.assertEqual(report["findings"][0]["evidence_records"], [3, 2])

    def test_egress_nonzero_first_cumulative_observation_is_not_counted(self):
        report = self.evaluate("egress", [
            egress("n1", CounterMode="cumulative", Bytes="900000000"),
        ])
        self.assertEqual(report["findings_count"], 0)
        self.assertIn("missing zero baseline", report["data_quality_warnings"][0])

    def test_egress_counter_reset_marks_session_unknown(self):
        report = self.evaluate("egress", [
            egress("n1", 0, CounterMode="cumulative", Bytes="0"),
            egress("n2", 1, CounterMode="cumulative", Bytes="600000000"),
            egress("n3", 2, CounterMode="cumulative", Bytes="10000000"),
        ])
        self.assertEqual(report["findings_count"], 0)
        self.assertTrue(any("counter reset" in w for w in report["data_quality_warnings"]))

    def test_egress_mixed_counter_modes_fail_closed(self):
        with self.assertRaisesRegex(HuntInputError, "inconsistent counter"):
            self.evaluate("egress", [
                egress("n1", 0),
                egress("n2", 1, CounterMode="cumulative", Bytes="100000000"),
            ])

    def test_egress_unknown_or_missing_bytes_produce_quality_warning_or_error(self):
        report = self.evaluate("egress", [
            egress("n1", CounterMode="unknown", Bytes="?")
        ])
        self.assertEqual(report["findings_count"], 0)
        self.assertIn("unquantified", report["data_quality_warnings"][0])
        for bad in ("?", "-1", "NaN"):
            with self.subTest(bad=bad), self.assertRaisesRegex(
                HuntInputError, "Bytes must be"
            ):
                self.evaluate("egress", [egress("n1", Bytes=bad)])

    def test_egress_invalid_ip_rejected(self):
        with self.assertRaisesRegex(HuntInputError, "not an IP address"):
            self.evaluate("egress", [egress("n1", DestinationIP="bad.example")])

    def test_all_hunts_deduplicate_identical_event_ids(self):
        for hunt, row in (
            ("lateral", lateral("execution", "n")),
            ("persistence", persistence("created", "n")),
            ("cloud", cloud("role_grant", "n")),
            ("egress", egress("n", Bytes="500000000")),
        ):
            with self.subTest(hunt=hunt):
                result = self.evaluate(hunt, [row, dict(row)])
                self.assertEqual(result["events_evaluated"], 2)
                self.assertEqual(result["events_unique"], 1)
                self.assertEqual(result["duplicate_events_suppressed"], 1)
                self.assertLessEqual(result["findings_count"], 1)

    def test_all_hunts_reject_conflicting_reused_event_id(self):
        for hunt, row in (
            ("lateral", lateral("execution", "n")),
            ("persistence", persistence("created", "n")),
            ("cloud", cloud("role_grant", "n")),
            ("egress", egress("n")),
        ):
            with self.subTest(hunt=hunt):
                different = dict(row)
                different["Timestamp"] = stamp(1)
                with self.assertRaisesRegex(HuntInputError, "conflicting duplicate EventId"):
                    self.evaluate(hunt, [row, different])

    def test_all_new_hunts_reject_missing_schema_field(self):
        for hunt in HUNTS:
            with self.subTest(hunt=hunt):
                path = self.folder / "bad.csv"
                path.write_text("Timestamp,EventId\n2026-05-01T08:00:00Z,event-1\n",
                                encoding="utf-8")
                with self.assertRaisesRegex(HuntInputError, "missing required columns"):
                    run_hunt(hunt, path)

    def test_report_contains_full_evidence_and_escapes_untrusted_content(self):
        from scripts.render_reports import render
        report = self.evaluate("lateral", [
            lateral("connection", "n1", 0, SourceHost="<img src=x onerror=alert(1)>"),
            lateral("logon", "n2", 1, SourceHost="<img src=x onerror=alert(1)>"),
            lateral("execution", "n3", 2, SourceHost="<img src=x onerror=alert(1)>"),
        ])
        markdown = render(report)
        self.assertIn("## Data-quality warnings", markdown)
        self.assertIn("## Candidate rationale", markdown)
        self.assertIn("Unique event IDs", markdown)
        self.assertNotIn("<img", markdown)
        self.assertNotIn("onerror=", markdown)
        self.assertIn("review required", markdown)
        self.assertIn("2026&#45;05&#45;01T08", markdown)


if __name__ == "__main__":
    unittest.main()
