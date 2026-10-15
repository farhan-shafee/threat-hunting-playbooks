"""Report output preserves evidence while treating telemetry as literal text."""
from __future__ import annotations

from copy import deepcopy
import html
import json
import unittest

from scripts.render_reports import render, table_cell


def example_report() -> dict:
    """A hand-authored result contract, independent of evaluator output."""
    return {
        "result_schema_version": "1.0",
        "rule_versions": {"AUTH-SPRAY": "1.1.0", "AUTH-FAILED-THEN-SUCCESS": "1.1.0"},
        "effective_parameters": {
            "AUTH-SPRAY": {"window_seconds": 900, "minimum_users": 3, "minimum_failures": 6},
            "AUTH-FAILED-THEN-SUCCESS": {"window_seconds": 900, "minimum_failures": 5},
        },
        "lab_scope": "synthetic offline telemetry; no live SIEM execution",
        "hunt_id": "auth",
        "input_sha256_normalized_utf8": "a" * 64,
        "events_evaluated": 6,
        "findings_count": 1,
        "time_window": "15 minutes",
        "findings": [{
            "hunt_id": "auth",
            "rule_id": "AUTH-FAILED-THEN-SUCCESS",
            "severity": "high",
            "entity": "admin@lab.local | 203.0.113.44",
            "first_seen_utc": "2026-04-20T08:00:00.000001Z",
            "last_seen_utc": "2026-04-20T08:05:00.999999Z",
            "evidence_records": [2, 3, 4, 5, 6, 7],
            "signals": [
                "5 invalid-password failures before success",
                "same identity and source IP within 15 minutes",
            ],
            "disposition": "review required; not confirmed compromise",
            "ProcessCommandLine": "RAW_COMMAND_MUST_NOT_APPEAR",
        }],
    }


class LiteralRenderingTests(unittest.TestCase):
    def test_bare_urls_and_email_addresses_cannot_become_autolinks(self):
        cases = [
            ("https://evil.invalid/a", "https&#58;&#47;&#47;evil&#46;invalid&#47;a"),
            ("www.evil.invalid", "www&#46;evil&#46;invalid"),
            ("admin@lab.local", "admin&#64;lab&#46;local"),
        ]
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(table_cell(value), expected)

    def test_markdown_and_html_payloads_are_literal(self):
        cases = [
            ("<img src=x onerror=alert(1)>",
             "&#60;img src&#61;x onerror&#61;alert&#40;1&#41;&#62;"),
            ("[click](https://evil.invalid)",
             "&#91;click&#93;&#40;https&#58;&#47;&#47;evil&#46;invalid&#41;"),
            ("![pixel](https://evil.invalid/image)",
             "&#33;&#91;pixel&#93;&#40;https&#58;&#47;&#47;evil&#46;invalid&#47;image&#41;"),
            ("`code` *bold* _em_ ~~gone~~ $math$",
             "&#96;code&#96; &#42;bold&#42; &#95;em&#95; &#126;&#126;gone&#126;&#126; &#36;math&#36;"),
            ("&#60;script&#62;", "&#38;&#35;60&#59;script&#38;&#35;62&#59;"),
            (r"left\|right", "left&#92;\\|right"),
            ("left\nright\r\nlast\tcell", "left&#10;right&#13;&#10;last&#9;cell"),
        ]
        for value, expected in cases:
            with self.subTest(value=value):
                actual = table_cell(value)
                self.assertEqual(actual, expected)
                # CommonMark decodes references after recognizing Markdown syntax.
                self.assertEqual(html.unescape(actual.replace(r"\|", "|")), value)

    def test_backslashes_cannot_cancel_table_pipe_escapes(self):
        for value in (r"\|", r"\\|", r"\\\|"):
            with self.subTest(value=value):
                actual = table_cell(value)
                self.assertNotIn("\\\\", actual)
                self.assertTrue(actual.endswith(r"\|"))
                self.assertEqual(html.unescape(actual.replace(r"\|", "|")), value)

    def test_all_untrusted_report_fields_use_literal_rendering(self):
        report = example_report()
        hostile = "![pixel](https://evil.invalid) <img src=x> `code` *bold* \\|\n# forged"
        for key in ("hunt_id", "input_sha256_normalized_utf8", "time_window", "lab_scope"):
            report[key] = hostile
        finding = report["findings"][0]
        for key in ("hunt_id", "rule_id", "severity", "entity", "first_seen_utc", "last_seen_utc", "disposition"):
            finding[key] = hostile
        finding["signals"] = [hostile]
        finding["evidence_records"] = [hostile]
        document = render(report)
        self.assertNotIn("![pixel]", document)
        self.assertNotIn("<img", document)
        self.assertNotIn("`code`", document)
        self.assertNotIn("*bold*", document)
        self.assertNotIn("\n# forged", document)
        self.assertIn("&#33;&#91;pixel&#93;&#40;https&#58;&#47;&#47;evil&#46;invalid&#41;", document)
        self.assertIn("&#92;\\|&#10;&#35; forged", document)


class CompleteEvidenceRenderingTests(unittest.TestCase):
    def test_report_contains_versioned_parameters_and_complete_rationale(self):
        document = render(example_report())
        text = html.unescape(document.replace(r"\|", "|"))
        self.assertIn("Result schema version: 1.0", text)
        self.assertIn('"AUTH-FAILED-THEN-SUCCESS": "1.1.0"', document)
        self.assertIn('"minimum_users": 3', document)
        self.assertIn("a" * 64, document)
        self.assertIn("Input events: **6**", document)
        self.assertIn("Review candidates: **1**", document)
        self.assertIn("2026-04-20T08:00:00.000001Z", text)
        self.assertIn("2026-04-20T08:05:00.999999Z", text)
        self.assertIn("2, 3, 4, 5, 6, 7", text)
        self.assertIn("5 invalid-password failures before success", text)
        self.assertIn("same identity and source IP within 15 minutes", text)
        self.assertIn("review required; not confirmed compromise", text)
        self.assertIn("admin&#64;lab&#46;local \\| 203&#46;0&#46;113&#46;44", document)
        self.assertNotIn("RAW_COMMAND_MUST_NOT_APPEAR", document)

    def test_configuration_order_is_canonical_and_render_is_repeatable(self):
        first = example_report()
        second = deepcopy(first)
        second["rule_versions"] = dict(reversed(list(first["rule_versions"].items())))
        second["effective_parameters"] = {
            key: dict(reversed(list(value.items())))
            for key, value in reversed(list(first["effective_parameters"].items()))
        }
        document = render(first)
        self.assertEqual(document, render(first))
        self.assertEqual(document, render(second))
        blocks = document.split("```json\n")
        self.assertEqual(len(blocks), 2)
        configuration = json.loads(blocks[1].split("\n```", 1)[0])
        self.assertEqual(configuration, {
            "rule_versions": first["rule_versions"],
            "effective_parameters": first["effective_parameters"],
        })
        self.assertLess(document.index('"AUTH-FAILED-THEN-SUCCESS": "1.1.0"'),
                        document.index('"AUTH-SPRAY": "1.1.0"'))

    def test_empty_result_retains_configuration_and_disposition_column(self):
        report = example_report()
        report["findings"] = []
        report["findings_count"] = 0
        document = render(report)
        self.assertIn("Result schema version: 1.0", html.unescape(document))
        self.assertIn('"rule_versions"', document)
        self.assertIn('"effective_parameters"', document)
        self.assertIn("Last seen (UTC)", document)
        self.assertIn("Disposition", document)
        self.assertIn("| None |", document)


if __name__ == "__main__":
    unittest.main()
