"""Regression tests for the offline engine; no credentials, network, or SIEM."""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from huntlab import HuntInputError, run_hunt
from huntlab.engine import load_csv

ROOT = Path(__file__).resolve().parents[1]
LOGS = ROOT / "samples" / "logs"
AUTH_HEADER = "TimeGenerated,UserPrincipalName,IPAddress,ResultType\n"
PS_HEADER = (
    "Timestamp,DeviceName,AccountName,FileName,ProcessCommandLine,"
    "InitiatingProcessFileName\n"
)


class EngineTests(unittest.TestCase):
    def run_csv(self, hunt: str, data: str) -> dict:
        with TemporaryDirectory() as temp:
            path = Path(temp) / "test.csv"
            path.write_text(data, encoding="utf-8", newline="\n")
            return run_hunt(hunt, path)

    def test_auth_fixture_is_reproducible(self):
        case = run_hunt("auth", LOGS / "auth-lab-v1.csv")
        self.assertEqual(case["events_evaluated"], 15)
        self.assertEqual(case["findings_count"], 2)
        self.assertEqual(
            [f["rule_id"] for f in case["findings"]],
            ["AUTH-SPRAY", "AUTH-FAILED-THEN-SUCCESS"],
        )
        self.assertEqual(case, run_hunt("auth", LOGS / "auth-lab-v1.csv"))

    def test_powershell_fixture_is_reproducible(self):
        case = run_hunt("powershell", LOGS / "powershell-lab-v1.csv")
        self.assertEqual(case["events_evaluated"], 6)
        self.assertEqual(case["findings_count"], 3)
        self.assertEqual([f["severity"] for f in case["findings"]],
                         ["high", "high", "medium"])
        # Outputs must never echo raw command lines from telemetry.
        self.assertNotIn("SQBFAFgA", str(case))

    def test_credential_result_50140_does_not_count_as_bad_password(self):
        events = [
            f"2026-04-20T08:0{i}:00Z,admin@lab.local,192.0.2.2,50140"
            for i in range(5)
        ] + ["2026-04-20T08:05:00Z,admin@lab.local,192.0.2.2,0"]
        self.assertEqual(self.run_csv("auth", AUTH_HEADER + "\n".join(events))[
            "findings_count"], 0)

    def test_bruteforce_crossing_window_not_reported(self):
        events = [
            f"2026-04-20T08:0{i}:00Z,a@lab.local,192.0.2.2,50126"
            for i in range(5)
        ] + ["2026-04-20T08:30:00Z,a@lab.local,192.0.2.2,0"]
        self.assertEqual(self.run_csv("auth", AUTH_HEADER + "\n".join(events))[
            "findings_count"], 0)

    def test_bruteforce_exact_boundary_is_included(self):
        events = [
            f"2026-04-20T08:0{i}:00Z,a@lab.local,192.0.2.2,50126"
            for i in range(5)
        ] + ["2026-04-20T08:15:00Z,a@lab.local,192.0.2.2,0"]
        result = self.run_csv("auth", AUTH_HEADER + "\n".join(events))
        self.assertEqual(result["findings"][0]["rule_id"], "AUTH-FAILED-THEN-SUCCESS")

    def test_reset_after_unrelated_auth_event(self):
        events = [
            f"2026-04-20T08:0{i}:00Z,a@lab.local,192.0.2.2,50126"
            for i in range(5)
        ] + [
            "2026-04-20T08:05:00Z,a@lab.local,192.0.2.2,50140",
            "2026-04-20T08:06:00Z,a@lab.local,192.0.2.2,0",
        ]
        self.assertEqual(self.run_csv("auth", AUTH_HEADER + "\n".join(events))[
            "findings_count"], 0)

    def test_bruteforce_requires_same_ip(self):
        events = [
            f"2026-04-20T08:0{i}:00Z,a@lab.local,192.0.2.2,50126"
            for i in range(5)
        ] + ["2026-04-20T08:05:00Z,a@lab.local,192.0.2.3,0"]
        self.assertEqual(self.run_csv("auth", AUTH_HEADER + "\n".join(events))[
            "findings_count"], 0)

    def test_spray_requires_distinct_identities(self):
        events = [
            f"2026-04-20T08:0{i}:00Z,one@lab.local,192.0.2.2,50126"
            for i in range(6)
        ]
        self.assertEqual(self.run_csv("auth", AUTH_HEADER + "\n".join(events))[
            "findings_count"], 0)

    def test_spray_requires_six_failures(self):
        events = [
            f"2026-04-20T08:0{i}:00Z,u{i%3}@lab.local,192.0.2.2,50126"
            for i in range(5)
        ]
        self.assertEqual(self.run_csv("auth", AUTH_HEADER + "\n".join(events))[
            "findings_count"], 0)

    def test_spray_window_not_all_history(self):
        events = [
            f"2026-04-20T08:{i*10:02}:00Z,u{i%3}@lab.local,192.0.2.2,50126"
            for i in range(6)
        ]
        self.assertEqual(self.run_csv("auth", AUTH_HEADER + "\n".join(events))[
            "findings_count"], 0)

    def test_unsorted_input_is_processed_by_event_time(self):
        events = [
            "2026-04-20T08:05:00Z,a@lab.local,192.0.2.2,0",
            *[f"2026-04-20T08:0{i}:00Z,a@lab.local,192.0.2.2,50126"
              for i in range(5)],
        ]
        report = self.run_csv("auth", AUTH_HEADER + "\n".join(events))
        self.assertEqual(report["findings_count"], 1)
        self.assertEqual(report["findings"][0]["first_seen_utc"],
                         "2026-04-20T08:00:00Z")

    def test_powershell_non_suspicious_or_encoding_is_ignored(self):
        events = [
            "2026-04-20T12:00:00Z,WKSTN-1,u,powershell.exe,powershell -encoding utf8,explorer.exe",
            "2026-04-20T12:00:01Z,WKSTN-1,u,cmd.exe,powershell -enc Zg==,winword.exe",
        ]
        self.assertEqual(self.run_csv("powershell", PS_HEADER + "\n".join(events))[
            "findings_count"], 0)

    def test_powershell_case_insensitive_parent_and_pwsh(self):
        data = PS_HEADER + (
            "2026-04-20T12:00:00Z,WKSTN-1,u,PWSH.EXE,pwsh -EncodedCommand Zg==,WinWord.EXE"
        )
        result = self.run_csv("powershell", data)
        self.assertEqual(result["findings"][0]["severity"], "high")

    def test_powershell_encoded_automation_is_review_not_high(self):
        data = PS_HEADER + (
            "2026-04-20T12:00:00Z,WKSTN-1,u,powershell.exe,powershell -enc Zg==,services.exe"
        )
        self.assertEqual(self.run_csv("powershell", data)["findings"][0]["severity"], "medium")

    def test_unknown_hunt_rejected(self):
        with self.assertRaises(HuntInputError):
            run_hunt("dns", LOGS / "auth-lab-v1.csv")

    def test_required_columns_enforced(self):
        with self.assertRaisesRegex(HuntInputError, "missing required columns"):
            self.run_csv("auth", "TimeGenerated,IPAddress\n2026-04-20T08:00:00Z,192.0.2.2")

    def test_duplicate_headers_rejected(self):
        with self.assertRaisesRegex(HuntInputError, "duplicate"):
            self.run_csv("auth", AUTH_HEADER.replace("ResultType", "IPAddress") +
                         "2026-04-20T08:00:00Z,u@lab.local,192.0.2.2,0")

    def test_extra_value_rejected(self):
        with self.assertRaisesRegex(HuntInputError, "malformed"):
            self.run_csv("auth", AUTH_HEADER +
                         "2026-04-20T08:00:00Z,u@lab.local,192.0.2.2,50126,extra")

    def test_naive_timestamps_rejected(self):
        with self.assertRaisesRegex(HuntInputError, "timezone-aware"):
            self.run_csv("auth", AUTH_HEADER +
                         "2026-04-20T08:00:00,u@lab.local,192.0.2.2,50126")

    def test_non_numeric_result_type_rejected(self):
        with self.assertRaisesRegex(HuntInputError, "numeric"):
            self.run_csv("auth", AUTH_HEADER +
                         "2026-04-20T08:00:00Z,u@lab.local,192.0.2.2,wrong")

    def test_empty_body_rejected(self):
        with self.assertRaisesRegex(HuntInputError, "no events"):
            self.run_csv("auth", AUTH_HEADER)

    def test_newline_digest_platform_independent(self):
        with TemporaryDirectory() as temp:
            p = Path(temp) / "x.csv"
            text = AUTH_HEADER + "2026-04-20T08:00:00Z,u@lab.local,192.0.2.2,0\n"
            p.write_bytes(text.encode())
            first = load_csv("auth", p)[1]
            p.write_bytes(text.replace("\n", "\r\n").encode())
            second = load_csv("auth", p)[1]
            self.assertEqual(first, second)

    def test_cli_failure_returns_code_2(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "run_hunt.py"),
             "--hunt", "auth", "--input", "does-not-exist.csv"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("[ERROR]", proc.stderr)


if __name__ == "__main__":
    unittest.main()
