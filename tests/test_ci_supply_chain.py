"""Negative controls for the offline GitHub Actions supply-chain guard."""
from __future__ import annotations

import unittest

from scripts.check_ci_supply_chain import ROOT, verify_workflow


class CISupplyChainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    def test_checked_in_workflow_has_expected_controls(self):
        self.assertEqual(verify_workflow(self.workflow), [])

    def test_mutable_tag_is_rejected(self):
        candidate = self.workflow.replace(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", "actions/checkout@v7"
        )
        self.assertTrue(verify_workflow(candidate))

    def test_additional_action_is_rejected(self):
        candidate = self.workflow.replace(
            "      - name: Compile code without live connections",
            "      - uses: untrusted/third-party@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
            "      - name: Compile code without live connections",
        )
        self.assertTrue(verify_workflow(candidate))

    def test_unknown_action_commit_is_rejected(self):
        candidate = self.workflow.replace(
            "6d4fd22b20465ccc0f7354476588e8df7c9ca0e0", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        self.assertTrue(verify_workflow(candidate))

    def test_checkout_credentials_cannot_persist(self):
        self.assertTrue(
            verify_workflow(self.workflow.replace("persist-credentials: false", "persist-credentials: true"))
        )

    def test_write_permissions_are_rejected(self):
        self.assertTrue(verify_workflow(self.workflow.replace("contents: read", "contents: write")))
        self.assertTrue(verify_workflow(self.workflow + "\n    permissions:\n      id-token: write\n"))

    def test_privileged_events_are_rejected(self):
        self.assertTrue(verify_workflow(self.workflow.replace("  pull_request:", "  pull_request_target:")))
        self.assertTrue(verify_workflow(self.workflow + "\n  workflow_run:\n"))

    def test_secret_usage_is_rejected(self):
        candidate = self.workflow + "\n        env:\n          ACCESS: " + "$" + "{{ secrets.API_KEY }}\n"
        self.assertTrue(verify_workflow(candidate))


if __name__ == "__main__":
    unittest.main()
