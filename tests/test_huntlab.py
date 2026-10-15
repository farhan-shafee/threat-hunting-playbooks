"""Offline unit tests. No SIEM, network, cloud, or production credentials."""
import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from huntlab.engine import HuntInputError, run_hunt

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples" / "logs"
AUTH_HEADERS = ["TimeGenerated", "UserPrincipalName", "IPAddress", "ResultType"]
PS_HEADERS = [
    "Timestamp", "DeviceName", "AccountName", "FileName",
    "ProcessCommandLine", "InitiatingProcessFileName",
]


class HuntLabTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def csv(self, name, headers, rows):
        path = self.dir / name
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(headers)
            writer.writerows(rows)
        return path

    def test_fixture_auth_has_high_and_medium_evidence(self):
        report = run_hunt("auth", SAMPLES / "auth-fixture-v1.csv")
        self.assertEqual(report["events_evaluated"], 18)
        self.assertEqual(report["findings_count"], 2)
        found = {f["rule_id"]: f for f in report["findings"]}
        self.assertEqual(found["AUTH-FAILED-THEN-SUCCESS"]["severity"], "high")
        self.assertEqual(len(found["AUTH-FAILED-THEN-SUCCESS"]["evidence_records"]), 6)
        self.assertEqual(found["AUTH-SPRAY"]["severity"], "medium")
        self.assertEqual(len(found["AUTH-SPRAY"]["evidence_records"]), 6)
        self.assertTrue(all("not confirmed compromise" in f["disposition"] for f in report["findings"]))

    def test_fixture_powershell_ranks_parent_context(self):
        report = run_hunt("powershell", SAMPLES / "powershell-fixture-v1.csv")
        self.assertEqual(report["events_evaluated"], 5)
        self.assertEqual(report["findings_count"], 2)
        self.assertEqual([f["severity"] for f in report["findings"]], ["high", "medium"])
        self.assertEqual(report["findings"][0]["evidence_records"], [2])
        self.assertEqual(report["findings"][1]["evidence_records"], [5])

    def test_deterministic_report_and_hash(self):
        path = SAMPLES / "auth-fixture-v1.csv"
        self.assertEqual(
            json.dumps(run_hunt("auth", path), sort_keys=True),
            json.dumps(run_hunt("auth", path), sort_keys=True),
        )
        self.assertEqual(len(run_hunt("auth", path)["input_sha256_normalized_utf8"]), 64)

    def test_fewer_than_five_failures_does_not_trigger(self):
        rows = [
            [f"2026-04-20T08:0{i}:00Z", "test@lab.invalid", "192.0.2.1", "50126"]
            for i in range(4)
        ] + [["2026-04-20T08:05:00Z", "test@lab.invalid", "192.0.2.1", "0"]]
        self.assertEqual(run_hunt("auth", self.csv("auth.csv", AUTH_HEADERS, rows))["findings_count"], 0)

    def test_five_failures_then_success_trigger(self):
        rows = [
            [f"2026-04-20T08:0{i}:00Z", "test@lab.invalid", "192.0.2.1", "50126"]
            for i in range(5)
        ] + [["2026-04-20T08:05:00Z", "test@lab.invalid", "192.0.2.1", "0"]]
        self.assertEqual(run_hunt("auth", self.csv("auth.csv", AUTH_HEADERS, rows))["findings_count"], 1)

    def test_success_before_failures_not_suspicious(self):
        rows = [["2026-04-20T08:00:00Z", "test@lab.invalid", "192.0.2.1", "0"]] + [
            [f"2026-04-20T08:0{i}:00Z", "test@lab.invalid", "192.0.2.1", "50126"]
            for i in range(1, 6)
        ]
        self.assertEqual(run_hunt("auth", self.csv("auth.csv", AUTH_HEADERS, rows))["findings_count"], 0)

    def test_mfa_failure_not_treated_as_bad_password(self):
        rows = [
            [f"2026-04-20T08:0{i}:00Z", "test@lab.invalid", "192.0.2.1", "50074"]
            for i in range(6)
        ] + [["2026-04-20T08:07:00Z", "test@lab.invalid", "192.0.2.1", "0"]]
        self.assertEqual(run_hunt("auth", self.csv("auth.csv", AUTH_HEADERS, rows))["findings_count"], 0)

    def test_failure_window_expires(self):
        rows = [
            [f"2026-04-20T08:0{i}:00Z", "test@lab.invalid", "192.0.2.1", "50126"]
            for i in range(5)
        ] + [["2026-04-20T08:25:00Z", "test@lab.invalid", "192.0.2.1", "0"]]
        self.assertEqual(run_hunt("auth", self.csv("auth.csv", AUTH_HEADERS, rows))["findings_count"], 0)

    def test_spray_requires_three_distinct_users(self):
        rows = [
            [f"2026-04-20T08:0{i}:00Z", "alice@lab.invalid" if i % 2 else "bob@lab.invalid",
             "192.0.2.1", "50126"]
            for i in range(6)
        ]
        self.assertEqual(run_hunt("auth", self.csv("auth.csv", AUTH_HEADERS, rows))["findings_count"], 0)

    def test_utc_offsets_are_normalized(self):
        rows = [
            ["2026-04-20T04:00:00-04:00", "test@lab.invalid", "192.0.2.1", "50126"],
            ["2026-04-20T08:01:00Z", "test@lab.invalid", "192.0.2.1", "50126"],
            ["2026-04-20T08:02:00Z", "test@lab.invalid", "192.0.2.1", "50126"],
            ["2026-04-20T08:03:00Z", "test@lab.invalid", "192.0.2.1", "50126"],
            ["2026-04-20T08:04:00Z", "test@lab.invalid", "192.0.2.1", "50126"],
            ["2026-04-20T08:05:00Z", "test@lab.invalid", "192.0.2.1", "0"],
        ]
        finding = run_hunt("auth", self.csv("auth.csv", AUTH_HEADERS, rows))["findings"][0]
        self.assertEqual(finding["first_seen_utc"], "2026-04-20T08:00:00Z")

    def test_no_false_positive_for_benign_powershell(self):
        rows = [
            ["2026-04-20T08:00:00Z", "LAB-1", "svc_patch", "powershell.exe",
             r"powershell.exe -File C:\Patch.ps1", "services.exe"],
        ]
        self.assertEqual(run_hunt("powershell", self.csv("ps.csv", PS_HEADERS, rows))["findings_count"], 0)

    def test_unknown_hunt_rejected(self):
        with self.assertRaisesRegex(HuntInputError, "unknown hunt"):
            run_hunt("something-else", SAMPLES / "auth-fixture-v1.csv")

    def test_missing_required_column_rejected(self):
        file = self.csv("auth.csv", ["TimeGenerated", "IPAddress", "ResultType"],
                        [["2026-04-20T08:00:00Z", "192.0.2.1", "50126"]])
        with self.assertRaisesRegex(HuntInputError, "missing required columns"):
            run_hunt("auth", file)

    def test_duplicate_header_rejected(self):
        path = self.dir / "auth.csv"
        path.write_text(
            "TimeGenerated,UserPrincipalName,IPAddress,ResultType,ResultType\n"
            "2026-04-20T08:00:00Z,u,192.0.2.1,50126,50126\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(HuntInputError, "duplicate"):
            run_hunt("auth", path)

    def test_naive_timestamp_rejected(self):
        path = self.csv("auth.csv", AUTH_HEADERS,
                        [["2026-04-20T08:00:00", "test@lab.invalid", "192.0.2.1", "0"]])
        with self.assertRaisesRegex(HuntInputError, "timezone-aware"):
            run_hunt("auth", path)

    def test_bad_result_code_rejected(self):
        path = self.csv("auth.csv", AUTH_HEADERS,
                        [["2026-04-20T08:00:00Z", "test@lab.invalid", "192.0.2.1", "x"]])
        with self.assertRaisesRegex(HuntInputError, "must be numeric"):
            run_hunt("auth", path)

    def test_bad_csv_record_rejected(self):
        path = self.dir / "auth.csv"
        path.write_text(
            "TimeGenerated,UserPrincipalName,IPAddress,ResultType\n"
            "2026-04-20T08:00:00Z,test@lab.invalid,192.0.2.1\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(HuntInputError, "malformed column count"):
            run_hunt("auth", path)

    def test_oversize_rejected(self):
        path = self.dir / "big.csv"
        path.write_bytes(b"x" * (5_000_001))
        with self.assertRaisesRegex(HuntInputError, "5 MB"):
            run_hunt("auth", path)

    def test_cli_report_matches_engine(self):
        out = self.dir / "report.json"
        completed = subprocess.run([
            sys.executable, str(ROOT / "scripts" / "run_hunt.py"),
            "--hunt", "auth", "--input", str(SAMPLES / "auth-fixture-v1.csv"),
            "--output", str(out),
        ], cwd=self.dir, capture_output=True, text=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(out.read_text(encoding="utf-8")),
                         run_hunt("auth", SAMPLES / "auth-fixture-v1.csv"))

    def test_report_markdown_escapes_entity_separator(self):
        from scripts.render_reports import render

        report = run_hunt("auth", SAMPLES / "auth-lab-v1.csv")
        markdown = render(report)
        self.assertIn("admin@lab.local \\| 203.0.113.44", markdown)
        self.assertIn("\n## Interpretation and limits\n", markdown)

    def test_cli_invalid_input_nonzero(self):
        completed = subprocess.run([
            sys.executable, str(ROOT / "scripts" / "run_hunt.py"),
            "--hunt", "auth", "--input", str(self.dir / "missing.csv"),
        ], cwd=self.dir, capture_output=True, text=True, check=False)
        self.assertEqual(completed.returncode, 2)
        self.assertIn("[ERROR]", completed.stderr)


if __name__ == "__main__":
    unittest.main()
