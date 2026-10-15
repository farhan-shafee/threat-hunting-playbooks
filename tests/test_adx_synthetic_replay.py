"""Regression checks for reproducible ADX synthetic execution evidence.

These do not execute KQL, contact ADX, or independently certify the human-
observed GUI receipt. The official Kusto.Language static analyzer separately
compiles the generated KQL bundles under the existing CI matrix.
"""
from __future__ import annotations

import hashlib
import io
from contextlib import redirect_stderr
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts import build_adx_synthetic_queries as lab


class AdxSyntheticReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.receipt = lab.read_receipt()

    def test_exactly_seven_observed_scenarios_and_scope_controls(self):
        self.assertEqual(len(self.receipt["scenarios"]), 7)
        self.assertEqual(
            {s["file"] for s in self.receipt["scenarios"]},
            {s.name for s in lab.NATIVE.glob("*.kql")},
        )
        scope = self.receipt["scope"]
        self.assertTrue(scope["azure_data_explorer_synthetic_execution"])
        for field in (
            "sentinel_tenant_execution", "defender_xdr_tenant_execution",
            "persistent_tables_or_ingestion", "billing_changes",
            "real_incident_or_efficacy_claim",
        ):
            self.assertIs(scope[field], False)
        self.assertIn("human-transcribed", self.receipt["method"])
        self.assertIn("not API-exported", self.receipt["method"])

    def test_each_original_capture_matches_its_immutable_receipt_hash(self):
        for scenario in self.receipt["scenarios"]:
            with self.subTest(file=scenario["file"]):
                recorded = (lab.RAW / scenario["file"]).read_bytes()
                self.assertEqual(
                    hashlib.sha256(recorded).hexdigest(),
                    scenario["captured_query_sha256"],
                )
                self.assertFalse(lab.SENSITIVE.search(recorded.decode("utf-8")))
                self.assertFalse(lab.MUTATING.search(recorded.decode("utf-8")))
                self.assertRegex(recorded.decode("utf-8"), r"(?i)\bdatatable\s*\(")
                self.assertEqual(
                    len(lab.capture_parts(scenario)[3]),
                    scenario["fixture_rows"],
                )

    def test_replay_query_preserves_native_kql_byte_for_byte(self):
        for scenario in self.receipt["scenarios"]:
            with self.subTest(file=scenario["file"]):
                replay, assertion = lab.build(scenario)
                canonical = (lab.NATIVE / scenario["file"]).read_text(encoding="utf-8")
                self.assertTrue(replay.endswith(canonical.rstrip() + "\n"))
                self.assertIn('let __SyntheticAnchor = bin(now() - 2h, ', replay)
                self.assertIn(f'let {scenario["table"]} = datatable(', replay)
                self.assertIn("| project-away FixtureMinute", replay)
                self.assertNotIn("datetime(2026-10-15T", replay)
                self.assertNotIn("kusto.windows.net", replay)
                self.assertIn("let __SyntheticResults = materialize(", assertion)
                self.assertIn("Verdict=iff(", assertion)
                self.assertIn(scenario["match"], assertion)
                self.assertIn("IdentityMatch=set_equals(", assertion)
                self.assertIn(
                    "make_set(" + scenario["identity_field"] + ")", assertion
                )
                self.assertIn("Expected=" + str(scenario["expected_rows"]), assertion)
                self.assertFalse(lab.MUTATING.search(replay))
                self.assertFalse(lab.MUTATING.search(assertion))

    def test_generated_files_are_exactly_reproducible(self):
        expected = lab.expected_queries()
        self.assertEqual(len(expected), 14)
        self.assertEqual(sorted(expected), sorted(x.name for x in lab.REPLAY.glob("*.kql")))
        for filename, rendered in expected.items():
            with self.subTest(file=filename):
                self.assertEqual((lab.REPLAY / filename).read_text(encoding="utf-8"), rendered)
                self.assertTrue(filename.endswith(".kql"))

    def test_read_only_check_does_not_change_executed_files(self):
        before = {
            source.name: hashlib.sha256(source.read_bytes()).hexdigest()
            for source in lab.RAW.glob("*.kql")
        }
        result = subprocess.run(
            [sys.executable, "-B", str(lab.ROOT / "scripts" /
                                       "build_adx_synthetic_queries.py"), "--check"],
            check=False, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("7 executable PASS/FAIL assertions", result.stdout)
        after = {
            source.name: hashlib.sha256(source.read_bytes()).hexdigest()
            for source in lab.RAW.glob("*.kql")
        }
        self.assertEqual(before, after)

    def test_missing_replay_file_blocks_check(self):
        with TemporaryDirectory() as td, patch.object(lab, "REPLAY", Path(td)):
            with redirect_stderr(io.StringIO()):
                self.assertEqual(lab.main(["--check"]), 1)

    def test_tampered_executed_query_is_rejected(self):
        with TemporaryDirectory() as td:
            fake = Path(td)
            scenario = self.receipt["scenarios"][0]
            text = (lab.RAW / scenario["file"]).read_text(encoding="utf-8")
            (fake / scenario["file"]).write_text(text.replace(
                "FailureTime < SuccessTime", "FailureTime <= SuccessTime",
            ), encoding="utf-8")
            with patch.object(lab, "RAW", fake):
                with self.assertRaisesRegex(ValueError, "hash mismatch"):
                    lab.capture_parts(scenario)

    def test_tampered_canonical_source_is_rejected(self):
        with TemporaryDirectory() as td:
            fake = Path(td)
            scenario = self.receipt["scenarios"][0]
            original = (lab.NATIVE / scenario["file"]).read_text(encoding="utf-8")
            (fake / scenario["file"]).write_text(original.replace(
                "FailureTime < SuccessTime", "FailureTime <= SuccessTime"
            ), encoding="utf-8")
            with patch.object(lab, "NATIVE", fake):
                with self.assertRaisesRegex(ValueError, "differs from current canonical"):
                    lab.capture_parts(scenario)

    def test_native_query_comments_containing_semicolons_are_safe(self):
        native = (
            "// A comment; no statement ends here.\n"
            "DeviceRegistryEvents\n| where isnotempty(RegistryKey)\n"
        )
        preamble, final = lab.separate_native_query(native)
        self.assertEqual(preamble, "")
        self.assertEqual(final, native.strip())

    def test_compound_auth_query_preserves_intermediate_lets(self):
        source = (lab.NATIVE / "auth-failure-success.kql").read_text(encoding="utf-8")
        head, final = lab.separate_native_query(source)
        self.assertIn("let Logins =", head)
        self.assertIn("let Successful =", head)
        self.assertTrue(final.startswith("Successful\n| join"))

    def test_fixed_timestamp_capture_requires_time_reanchoring(self):
        for scenario in self.receipt["scenarios"]:
            with self.subTest(file=scenario["file"]):
                captured = (lab.RAW / scenario["file"]).read_text(encoding="utf-8")
                self.assertIn("datetime(2026-10-15T", captured)
                current, assertions = lab.build(scenario)
                self.assertNotIn("datetime(2026-10-15T", current)
                self.assertNotIn("datetime(2026-10-15T", assertions)

    def test_manifest_preserves_query_semantics_distinctions(self):
        limits = {
            s["file"]: s["observations"]
            for s in self.receipt["scenarios"]
        }
        self.assertTrue(any("No cross-sensor" in x
                            for x in limits["lateral-execution-pivot.kql"]))
        self.assertTrue(any("Calendar-hour" in x
                            for x in limits["egress-byte-volume.kql"]))
        self.assertTrue(any("Failed grant" in x
                            for x in limits["cloud-entra-changes.kql"]))
        self.assertTrue(all(
            s["expected_rows"] == len(s["expected_identity_values"])
            for s in self.receipt["scenarios"]
        ))


if __name__ == "__main__":
    unittest.main()
