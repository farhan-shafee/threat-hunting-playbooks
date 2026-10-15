"""Documentation, evidence, and privacy-quality contract tests."""
from __future__ import annotations

import csv
import ipaddress
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from scripts.render_reports import CASES, render
from scripts.validate_playbooks import ROOT, validate_file
from huntlab import run_hunt


class EvidenceContractTests(unittest.TestCase):
    def test_committed_reports_match_computed_evidence(self):
        for hunt, (sample, output) in CASES.items():
            with self.subTest(hunt=hunt):
                result = run_hunt(hunt, ROOT / "samples" / "logs" / sample)
                expected = render(result)
                actual = (ROOT / "samples" / "reports" / "reproduced" / output).read_text(
                    encoding="utf-8"
                ).replace("\r\n", "\n")
                self.assertEqual(actual, expected)

    def test_synthetic_identity_and_ip_contract(self):
        reserved = [
            ipaddress.ip_network("192.0.2.0/24"),
            ipaddress.ip_network("198.51.100.0/24"),
            ipaddress.ip_network("203.0.113.0/24"),
        ]
        with (ROOT / "samples" / "logs" / "auth-lab-v1.csv").open(
            encoding="utf-8", newline=""
        ) as file:
            for row in csv.DictReader(file):
                self.assertTrue(row["UserPrincipalName"].endswith("@lab.local"))
                self.assertTrue(any(
                    ipaddress.ip_address(row["IPAddress"]) in network
                    for network in reserved
                ))

    def test_validator_works_outside_repo(self):
        with TemporaryDirectory() as temp:
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "validate_playbooks.py")],
                cwd=temp, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_validator_rejects_bare_kql_marker(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "bad.md"
            path.write_text("# Example\nkql\nDeviceProcessEvents\n", encoding="utf-8")
            self.assertTrue(validate_file(path))

    def test_validator_rejects_unclosed_fence(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "bad.md"
            path.write_text("# Example\n" + "```kql\n" + "Data\n", encoding="utf-8")
            self.assertIn("unbalanced Markdown code fences", validate_file(path))

    def test_fixture_is_never_described_as_live_telemetry(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("synthetic", readme.lower())
        contract = (ROOT / "docs" / "query-contract.md").read_text(encoding="utf-8")
        self.assertIn("unverified", contract.lower())


if __name__ == "__main__":
    unittest.main()
