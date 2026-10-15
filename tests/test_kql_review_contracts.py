"""Read-only source-reviewed KQL inventory and canonical-snippet regression tests.

KQL grammar and schema semantics are checked separately by Microsoft's
Kusto.Language in scripts/validate_kql_schemas.ps1. These Python tests do
not run queries in a tenant or evaluate their detection behavior.
"""
from __future__ import annotations

import re
import subprocess
import sys
import unittest

from scripts.sync_kql_examples import (
    PACK, ROOT, load_manifest, render_playbook, snippets_for_playbook,
)

FORBIDDEN = re.compile(
    r"(?im)^\s*\.(?:drop|delete|ingest|set|append|alter|create|export|clear)\b"
)


class KqlReviewContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = load_manifest()

    def test_query_manifest_is_explicit_and_complete(self):
        entries = self.manifest["queries"]
        self.assertEqual(len(entries), 7)
        self.assertEqual(len({x["file"] for x in entries}), 7)
        self.assertEqual(len({x["playbook"] for x in entries}), 6)
        self.assertEqual({x["table"] for x in entries}, set(
            self.manifest["tables"]
        ))
        self.assertEqual(
            sorted(x["file"] for x in entries),
            sorted(x.name for x in PACK.glob("*.kql")),
        )
        self.assertTrue(all(x["file"].endswith(".kql") for x in entries))

    def test_every_table_has_a_curated_vendor_schema_reference(self):
        for name, table in self.manifest["tables"].items():
            with self.subTest(table=name):
                self.assertTrue(
                    table["reference"].startswith("https://learn.microsoft.com/"),
                    table["reference"],
                )
                self.assertTrue(table["schema"].startswith("("))
                self.assertIn(":", table["schema"])
                self.assertIn("datetime", table["schema"])
                self.assertTrue(table["schema"].endswith(")"))

    def test_all_queries_are_read_only_and_bounded(self):
        for entry in self.manifest["queries"]:
            with self.subTest(query=entry["file"]):
                query = (PACK / entry["file"]).read_text(encoding="utf-8")
                self.assertIsNone(FORBIDDEN.search(query))
                self.assertRegex(query, r"\|\s*where\s+(TimeGenerated|Timestamp)\s*>=\s*ago\(")
                self.assertIn(entry["table"], query)
                for fragment in entry["required_fragments"]:
                    self.assertIn(fragment, query)
                self.assertNotIn("DeviceNetworkEvents.SentBytes", query)
                self.assertNotIn("DeviceTvmSoftwareInventoryChangeEvents", query)
                self.assertNotIn("ProcessCommandLine has_any", query)

    def test_vendor_parser_package_is_version_and_digest_pinned(self):
        package = self.manifest["kusto_language_package"]
        self.assertEqual(package["id"], "Microsoft.Azure.Kusto.Language")
        self.assertEqual(package["version"], "12.4.1")
        self.assertRegex(package["archive_sha256"], r"^[0-9a-f]{64}$")

    def test_playbooks_embed_the_exact_canonical_query_text(self):
        grouped = {}
        for entry in self.manifest["queries"]:
            grouped.setdefault(entry["playbook"], []).append(entry)
        for relative, entries in grouped.items():
            with self.subTest(playbook=relative):
                text = (ROOT / relative).read_text(encoding="utf-8")
                self.assertEqual(render_playbook(text, entries), text)
                section = snippets_for_playbook(entries)
                self.assertIn(section, text)
                self.assertEqual(
                    len(re.findall(r"(?m)^" + re.escape(chr(96) * 3) + r"kql$", section)),
                    len(entries),
                )

    def test_check_command_passes_without_writes(self):
        output = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts" / "sync_kql_examples.py"), "--check"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(output.returncode, 0, output.stdout + output.stderr)
        self.assertEqual(output.stderr, "")

    def test_query_mismatches_produce_a_different_rendered_section(self):
        entry = next(x for x in self.manifest["queries"] if x["hunt"] == "cloud")
        path = ROOT / entry["playbook"]
        original = path.read_text(encoding="utf-8")
        changed = original.replace("## Investigation Steps", "## Investigation Steps\nAnalyst note.", 1)
        # Ensure canonical section remains sourced from the KQL inventory,
        # not arbitrary analyst prose; no repository file is written.
        self.assertEqual(render_playbook(changed, [entry]), changed)
        corrupted = original.replace(
            'tostring(Result) =~ "success"',
            'tostring(Result) =~ "failure"',
        )
        self.assertNotEqual(render_playbook(corrupted, [entry]), corrupted)

    def test_critical_behavioral_contracts_are_distinct(self):
        text = {
            entry["file"]: (PACK / entry["file"]).read_text(encoding="utf-8")
            for entry in self.manifest["queries"]
        }
        self.assertIn("FailureTime < SuccessTime", text["auth-failure-success.kql"])
        self.assertIn("IsInteractive == true", text["auth-failure-success.kql"])
        self.assertIn("count_distinct(UserKey)", text["auth-spray.kql"])
        self.assertIn("pwsh.exe", text["powershell-execution.kql"])
        self.assertIn("RegistryKey contains", text["persistence-autoruns.kql"])
        self.assertNotIn("RegistryValueData has_any", text["persistence-autoruns.kql"])
        self.assertIn('"Add member to role"', text["cloud-entra-changes.kql"])
        self.assertIn('tostring(Result) =~ "success"', text["cloud-entra-changes.kql"])
        self.assertIn("bin(TimeGenerated, 1h)", text["egress-byte-volume.kql"])
        self.assertIn("SentBytes", text["egress-byte-volume.kql"])

    def test_explicit_no_tenant_execution_disclaimer(self):
        contract = (ROOT / "docs" / "query-contract.md").read_text(encoding="utf-8").lower()
        self.assertIn("unverified", contract)
        self.assertIn("tenant", contract)
        readme = (ROOT / "README.md").read_text(encoding="utf-8").lower()
        self.assertIn("offline", readme)
        self.assertIn("synthetic", readme)


if __name__ == "__main__":
    unittest.main()
