"""Independent regression cases for ordering, parser bounds, and provenance."""
from __future__ import annotations

import io
from itertools import permutations
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from huntlab import HuntInputError, run_hunt
from huntlab.engine import load_csv


AUTH_HEADER = "TimeGenerated,UserPrincipalName,IPAddress,ResultType\n"
PS_HEADER = (
    "Timestamp,DeviceName,AccountName,FileName,ProcessCommandLine,"
    "InitiatingProcessFileName\n"
)
ROOT = Path(__file__).resolve().parents[1]


class EngineCorrectionsTests(unittest.TestCase):
    def run_csv(self, hunt: str, data: str | bytes) -> dict:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "events.csv"
            path.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)
            return run_hunt(hunt, path)

    @staticmethod
    def auth_event(timestamp: str, result: str, user: str = "a@lab.local") -> str:
        return f"{timestamp},{user},192.0.2.1,{result}"

    @staticmethod
    def ps_event(timestamp: str, device: str) -> str:
        return f"{timestamp},{device},u,powershell.exe,powershell -enc Zg==,services.exe"

    @staticmethod
    def follow_through(report: dict) -> list[dict]:
        return [f for f in report["findings"] if f["rule_id"] == "AUTH-FAILED-THEN-SUCCESS"]

    def test_equal_time_failures_never_establish_before_success(self):
        failures = [self.auth_event("2026-04-20T08:00:00Z", "50126")] * 5
        success = self.auth_event("2026-04-20T08:00:00Z", "0")
        later = self.auth_event("2026-04-20T08:00:01Z", "0")
        for position in range(6):
            with self.subTest(success_position=position):
                events = failures[:position] + [success] + failures[position:] + [later]
                self.assertEqual(self.follow_through(self.run_csv(
                    "auth", AUTH_HEADER + "\n".join(events)
                )), [])

    def test_tied_success_group_does_not_seed_a_later_sequence(self):
        earlier = [self.auth_event(f"2026-04-20T08:0{i}:00Z", "50126") for i in range(5)]
        subsequent = [self.auth_event(f"2026-04-20T08:0{i}:00Z", "50126") for i in range(6, 10)]
        subsequent.append(self.auth_event("2026-04-20T08:10:00Z", "0"))
        cases = [
            (("50126", "0", "0"), [2, 3, 4, 5, 6, 8, 9]),
            (("0", "50126", "0"), [2, 3, 4, 5, 6, 7, 9]),
            (("0", "0", "50126"), [2, 3, 4, 5, 6, 7, 8]),
        ]
        for codes, expected_records in cases:
            group = [self.auth_event("2026-04-20T08:05:00Z", code) for code in codes]
            report = self.run_csv("auth", AUTH_HEADER + "\n".join(earlier + group + subsequent))
            found = self.follow_through(report)
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0]["first_seen_utc"], "2026-04-20T08:00:00Z")
            self.assertEqual(found[0]["last_seen_utc"], "2026-04-20T08:05:00Z")
            self.assertEqual(found[0]["evidence_records"], expected_records)

    def test_unrelated_outcome_resets_entire_timestamp_group(self):
        earlier = [self.auth_event(f"2026-04-20T08:0{i}:00Z", "50126") for i in range(5)]
        tied = [self.auth_event("2026-04-20T08:05:00Z", code) for code in ("50126", "0", "50074")]
        later = self.auth_event("2026-04-20T08:06:00Z", "0")
        for group in permutations(tied):
            with self.subTest(group=group):
                self.assertEqual(self.follow_through(self.run_csv(
                    "auth", AUTH_HEADER + "\n".join(earlier + list(group) + [later])
                )), [])

    def test_tied_failures_without_reset_count_for_later_success(self):
        events = [self.auth_event("2026-04-20T08:00:00Z", "50126")] * 5
        events.append(self.auth_event("2026-04-20T08:00:00.000001Z", "0"))
        finding = self.follow_through(self.run_csv("auth", AUTH_HEADER + "\n".join(events)))[0]
        self.assertEqual(finding["last_seen_utc"], "2026-04-20T08:00:00.000001Z")

    def test_follow_through_lookback_includes_exactly_900_seconds(self):
        failures = [self.auth_event("2026-04-20T08:00:00Z", "50126")] * 5
        for timestamp, expected in (("2026-04-20T08:15:00Z", 1),
                                    ("2026-04-20T08:15:00.000001Z", 0)):
            with self.subTest(success=timestamp):
                report = self.run_csv("auth", AUTH_HEADER + "\n".join(
                    failures + [self.auth_event(timestamp, "0")]
                ))
                self.assertEqual(len(self.follow_through(report)), expected)

    def test_spray_timestamp_groups_have_permutation_invariant_counts(self):
        events = [self.auth_event("2026-04-20T08:00:00Z", "50126", user)
                  for user in ("a", "a", "b", "b", "a", "b", "c")]
        for ordered in (events, list(reversed(events))):
            report = self.run_csv("auth", AUTH_HEADER + "\n".join(ordered))
            self.assertEqual(len(report["findings"]), 1)
            self.assertEqual(report["findings"][0]["evidence_records"], list(range(2, 9)))
            self.assertEqual(report["findings"][0]["signals"], [
                "7 invalid-password failures", "3 distinct identities within 15 minutes",
            ])

    def test_spray_window_includes_900_seconds_but_excludes_one_more_microsecond(self):
        earlier = [self.auth_event(f"2026-04-20T08:0{i}:00Z", "50126", user)
                   for i, user in enumerate(("a", "b", "c", "a", "b"))]
        for timestamp, expected in (("2026-04-20T08:15:00Z", 1),
                                    ("2026-04-20T08:15:00.000001Z", 0)):
            with self.subTest(latest_failure=timestamp):
                report = self.run_csv("auth", AUTH_HEADER + "\n".join(
                    earlier + [self.auth_event(timestamp, "50126", "c")]
                ))
                self.assertEqual(report["findings_count"], expected)
                if expected:
                    self.assertEqual(report["findings"][0]["rule_id"], "AUTH-SPRAY")
                    self.assertEqual(report["findings"][0]["evidence_records"], [2, 3, 4, 5, 6, 7])
                    self.assertEqual(report["findings"][0]["first_seen_utc"], "2026-04-20T08:00:00Z")
                    self.assertEqual(report["findings"][0]["last_seen_utc"], "2026-04-20T08:15:00Z")

    def test_fractional_and_whole_seconds_sort_chronologically(self):
        events = [self.ps_event("2026-04-20T08:00:00.100001Z", "Alpha"),
                  self.ps_event("2026-04-20T08:00:00Z", "Zulu"),
                  self.ps_event("2026-04-20T08:00:00.000001Z", "Beta")]
        findings = self.run_csv("powershell", PS_HEADER + "\n".join(events))["findings"]
        self.assertEqual([f["entity"] for f in findings], ["Zulu | u", "Beta | u", "Alpha | u"])
        self.assertEqual([f["first_seen_utc"] for f in findings], [
            "2026-04-20T08:00:00Z", "2026-04-20T08:00:00.000001Z", "2026-04-20T08:00:00.100001Z",
        ])

    def test_equivalent_offsets_preserve_fractional_utc_and_tie_semantics(self):
        events = [self.auth_event("2026-04-20T04:00:00.123456-04:00", "50126")] * 5
        events += [self.auth_event("2026-04-20T08:00:00.123456Z", "0"),
                   self.auth_event("2026-04-20T08:00:01Z", "0")]
        self.assertEqual(self.follow_through(self.run_csv("auth", AUTH_HEADER + "\n".join(events))), [])
        ps_events = [self.ps_event("2026-04-20T04:00:00.123456-04:00", "One"),
                     self.ps_event("2026-04-20T08:00:00.123456Z", "Two")]
        findings = self.run_csv("powershell", PS_HEADER + "\n".join(ps_events))["findings"]
        self.assertEqual([f["first_seen_utc"] for f in findings], [
            "2026-04-20T08:00:00.123456Z", "2026-04-20T08:00:00.123456Z",
        ])

    def test_timestamp_conversion_overflow_is_a_hunt_input_error(self):
        for timestamp in ("0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"):
            with self.subTest(timestamp=timestamp):
                try:
                    self.run_csv("auth", AUTH_HEADER + self.auth_event(timestamp, "0"))
                except Exception as exc:
                    self.assertIsInstance(exc, HuntInputError)
                else:
                    self.fail("UTC-overflowing timestamp was accepted")

    def test_malformed_quoted_header_is_a_hunt_input_error(self):
        try:
            self.run_csv("auth", '"TimeGenerated,UserPrincipalName,IPAddress,ResultType\n')
        except Exception as exc:
            self.assertIsInstance(exc, HuntInputError)
        else:
            self.fail("Unterminated header quote was accepted")

    def test_missing_optional_column_value_is_rejected(self):
        with self.assertRaisesRegex(HuntInputError, "malformed column count"):
            self.run_csv("auth", AUTH_HEADER.rstrip("\n") + ",Extra\n" +
                         self.auth_event("2026-04-20T08:00:00Z", "0"))

    def test_explicitly_blank_optional_column_is_allowed(self):
        report = self.run_csv("auth", AUTH_HEADER.rstrip("\n") + ",Extra\n" +
                              self.auth_event("2026-04-20T08:00:00Z", "0") + ",\n")
        self.assertEqual(report["events_evaluated"], 1)

    def test_read_requests_at_most_the_byte_limit_plus_one(self):
        data = (AUTH_HEADER + self.auth_event("2026-04-20T08:00:00Z", "0")).encode()

        class TrackedReader(io.BytesIO):
            def read(self, size=-1):
                self.requested_sizes.append(size)
                return super().read(size)

        class Source:
            def __init__(self):
                self.requested_sizes = []

            def is_file(self):
                return True

            def read_bytes(self):
                self.requested_sizes.append(-1)
                return data

            def open(self, mode):
                if mode != "rb":
                    raise AssertionError("Input must be opened as bytes")
                reader = TrackedReader(data)
                reader.requested_sizes = self.requested_sizes
                return reader

        source = Source()
        rows, _ = load_csv("auth", source)
        self.assertEqual(len(rows), 1)
        self.assertEqual(source.requested_sizes, [5_000_001])

    def test_byte_limit_is_inclusive(self):
        prefix = (AUTH_HEADER + self.auth_event("2026-04-20T08:00:00Z", "0") + "\n").encode()
        exact = prefix + b"\n" * (5_000_000 - len(prefix))
        self.assertEqual(self.run_csv("auth", exact)["events_evaluated"], 1)
        with self.assertRaisesRegex(HuntInputError, "5 MB"):
            self.run_csv("auth", exact + b"\n")

    def test_record_limit_is_inclusive(self):
        event = self.auth_event("2026-04-20T08:00:00Z", "0") + "\n"
        self.assertEqual(self.run_csv("auth", AUTH_HEADER + event * 20_000)["events_evaluated"], 20_000)
        with self.assertRaisesRegex(HuntInputError, "20,000-record"):
            self.run_csv("auth", AUTH_HEADER + event * 20_001)

    def test_report_exposes_effective_rule_provenance(self):
        auth = self.run_csv("auth", AUTH_HEADER + self.auth_event("2026-04-20T08:00:00Z", "0"))
        self.assertEqual(auth.get("result_schema_version"), "1.0")
        self.assertEqual(auth.get("rule_versions"), {
            "AUTH-FAILED-THEN-SUCCESS": "1.1.0", "AUTH-SPRAY": "1.1.0",
        })
        self.assertEqual(auth.get("effective_parameters"), {
            "AUTH-FAILED-THEN-SUCCESS": {
                "minimum_failures": 5, "lookback_seconds": 900, "lookback_inclusive": True,
                "failure_result": "50126", "success_result": "0", "temporal_order": "strictly_earlier",
                "timestamp_ties": "discard_failures_tied_with_success", "other_outcomes": "reset_sequence",
            },
            "AUTH-SPRAY": {
                "minimum_failures": 6, "minimum_distinct_identities": 3, "window_seconds": 900,
                "window_inclusive": True, "failure_result": "50126", "maximum_findings_per_ip": 1,
            },
        })
        ps = self.run_csv("powershell", PS_HEADER + self.ps_event("2026-04-20T08:00:00Z", "One"))
        self.assertEqual(ps.get("result_schema_version"), "1.0")
        self.assertEqual(ps.get("rule_versions"), {"PS-SUSPICIOUS-EXECUTION": "1.1.0"})
        self.assertEqual(ps.get("effective_parameters"), {
            "PS-SUSPICIOUS-EXECUTION": {
                "executable_names": ["powershell.exe", "pwsh.exe"],
                "encoded_flag_pattern": r"(?i)(?:^|\s)-(?:enc|encodedcommand)(?=\s|:|$)",
                "payload_markers": ["frombase64string", "invoke-expression", "iex(", "downloadstring("],
                "high_priority_parents": ["cscript.exe", "excel.exe", "mshta.exe", "outlook.exe", "winword.exe", "wscript.exe"],
            },
        })

    def test_cli_parser_failures_return_controlled_errors(self):
        valid = self.auth_event("2026-04-20T08:00:00Z", "0")
        optional_header = AUTH_HEADER.rstrip("\n") + ",Extra\n"
        cases = {
            "unterminated_header": '"TimeGenerated,UserPrincipalName,IPAddress,ResultType\n',
            "unterminated_optional_value": optional_header + valid + ',"unterminated\n',
            "missing_optional_value": optional_header + valid + "\n",
            "minimum_utc_overflow": AUTH_HEADER + self.auth_event("0001-01-01T00:00:00+01:00", "0"),
            "maximum_utc_overflow": AUTH_HEADER + self.auth_event("9999-12-31T23:59:59-01:00", "0"),
            "missing_required_value": AUTH_HEADER + "2026-04-20T08:00:00Z,,192.0.2.1,0\n",
            "invalid_utf8": AUTH_HEADER.encode() + b"\xff\n",
        }
        with TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.csv"
            for name, data in cases.items():
                with self.subTest(case=name):
                    path.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)
                    completed = subprocess.run([
                        sys.executable, "-B", str(ROOT / "scripts" / "run_hunt.py"),
                        "--hunt", "auth", "--input", str(path),
                    ], capture_output=True, text=True, check=False)
                    self.assertEqual(completed.returncode, 2, completed.stderr)
                    self.assertTrue(completed.stderr.startswith("[ERROR]"), completed.stderr)
                    self.assertNotIn("Traceback", completed.stderr)
                    self.assertEqual(completed.stdout, "")


if __name__ == "__main__":
    unittest.main()
