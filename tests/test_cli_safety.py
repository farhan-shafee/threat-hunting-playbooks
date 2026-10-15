"""CLI output must never overwrite source telemetry or expose partial reports."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import run_hunt as cli


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run_hunt.py"
FIXTURE = ROOT / "samples" / "logs" / "auth-lab-v1.csv"


class CliOutputSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.source = self.directory / "input.csv"
        self.original = FIXTURE.read_bytes()
        self.source.write_bytes(self.original)
        self.output = self.directory / "report.json"

    def subprocess_cli(self, source=None, output=None):
        command = [
            sys.executable, str(RUNNER), "--hunt", "auth", "--input",
            str(self.source if source is None else source),
        ]
        if output is not None:
            command += ["--output", str(output)]
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        return subprocess.run(
            command, cwd=self.directory, env=environment,
            capture_output=True, text=True, check=False,
        )

    def main_cli(self, output=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        arguments = ["--hunt", "auth", "--input", str(self.source)]
        if output is not None:
            arguments += ["--output", str(output)]
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = cli.main(arguments)
        return code, stdout.getvalue(), stderr.getvalue()

    def assert_source_preserved(self):
        self.assertTrue(self.source.read_bytes() == self.original,
                        "CLI changed source telemetry bytes")

    def assert_alias_rejected(self, output, source=None):
        before = set(self.directory.iterdir())
        result = self.subprocess_cli(source=source, output=output)
        self.assert_source_preserved()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("[ERROR]", result.stderr)
        self.assertEqual(set(self.directory.iterdir()), before)

    def test_output_cannot_be_exact_input_path(self):
        self.assert_alias_rejected(self.source)

    def test_alias_is_rejected_before_creating_temporary_output(self):
        with patch("tempfile.NamedTemporaryFile", side_effect=AssertionError("temp created")):
            code, _, stderr = self.main_cli(self.source)
        self.assert_source_preserved()
        self.assertEqual(code, 2)
        self.assertIn("[ERROR]", stderr)
        self.assertEqual(set(self.directory.iterdir()), {self.source})

    def test_output_cannot_be_relative_alias_of_input(self):
        self.assert_alias_rejected(Path(".") / self.source.name,
                                   source=self.source.name)

    def test_output_cannot_resolve_through_dotdot_to_input(self):
        child = self.directory / "child"
        child.mkdir()
        self.assert_alias_rejected(child / ".." / self.source.name)

    def test_output_cannot_be_hardlink_to_input(self):
        try:
            os.link(self.source, self.output)
        except OSError as exc:
            self.skipTest(f"hardlinks unavailable: {exc}")
        self.assert_alias_rejected(self.output)
        self.assertEqual(self.output.read_bytes(), self.original)

    def test_output_cannot_be_symlink_to_input(self):
        try:
            self.output.symlink_to(self.source)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        self.assert_alias_rejected(self.output)
        self.assertTrue(self.output.is_symlink())

    def test_real_output_cannot_alias_a_symlink_input(self):
        linked_source = self.directory / "linked-input.csv"
        try:
            linked_source.symlink_to(self.source)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        self.assert_alias_rejected(self.source, source=linked_source)

    def test_invalid_input_preserves_existing_output(self):
        self.source.write_bytes(b"invalid CSV\n")
        self.original = self.source.read_bytes()
        self.output.write_bytes(b"previous complete report\n")
        before = set(self.directory.iterdir())
        result = self.subprocess_cli(output=self.output)
        self.assertEqual(result.returncode, 2)
        self.assertIn("[ERROR]", result.stderr)
        self.assert_source_preserved()
        self.assertEqual(self.output.read_bytes(), b"previous complete report\n")
        self.assertEqual(set(self.directory.iterdir()), before)

    def test_missing_output_directory_is_not_created(self):
        missing = self.directory / "missing" / "report.json"
        result = self.subprocess_cli(output=missing)
        self.assertEqual(result.returncode, 2)
        self.assert_source_preserved()
        self.assertFalse(missing.parent.exists())

    def test_temporary_creation_failure_preserves_existing_output(self):
        self.output.write_bytes(b"previous complete report\n")
        before = set(self.directory.iterdir())
        with patch("tempfile.NamedTemporaryFile", side_effect=PermissionError("temp denied")):
            code, _, stderr = self.main_cli(self.output)
        self.assertEqual(code, 2)
        self.assertIn("[ERROR]", stderr)
        self.assert_source_preserved()
        self.assertEqual(self.output.read_bytes(), b"previous complete report\n")
        self.assertEqual(set(self.directory.iterdir()), before)

    def test_partial_temporary_write_failure_preserves_existing_output(self):
        self.output.write_bytes(b"previous complete report\n")
        before = set(self.directory.iterdir())
        real_temporary_file = tempfile.NamedTemporaryFile

        def fail_after_partial_write(*args, **kwargs):
            handle = real_temporary_file(*args, **kwargs)
            real_write = handle.write

            def partial_write(document):
                real_write(document[:12])
                raise OSError("simulated disk write failure")

            handle.write = partial_write
            return handle

        with patch("tempfile.NamedTemporaryFile", side_effect=fail_after_partial_write):
            code, _, stderr = self.main_cli(self.output)
        self.assertEqual(code, 2)
        self.assertIn("[ERROR]", stderr)
        self.assert_source_preserved()
        self.assertEqual(self.output.read_bytes(), b"previous complete report\n")
        self.assertEqual(set(self.directory.iterdir()), before)

    def test_replace_failure_preserves_existing_output_and_cleans_temporary(self):
        self.output.write_bytes(b"previous complete report\n")
        before = set(self.directory.iterdir())
        with patch("os.replace", side_effect=PermissionError("replace denied")):
            code, _, stderr = self.main_cli(self.output)
        self.assertEqual(code, 2)
        self.assertIn("[ERROR]", stderr)
        self.assert_source_preserved()
        self.assertEqual(self.output.read_bytes(), b"previous complete report\n")
        self.assertEqual(set(self.directory.iterdir()), before)

    def test_replace_failure_never_creates_partial_destination(self):
        before = set(self.directory.iterdir())
        with patch("os.replace", side_effect=PermissionError("replace denied")):
            code, _, _ = self.main_cli(self.output)
        self.assertEqual(code, 2)
        self.assert_source_preserved()
        self.assertFalse(self.output.exists())
        self.assertEqual(set(self.directory.iterdir()), before)

    def test_success_replaces_only_after_complete_same_directory_write(self):
        self.output.write_bytes(b"previous complete report\n")
        before = set(self.directory.iterdir())
        real_replace = os.replace
        replacements = []

        def inspect_then_replace(source, destination):
            temporary = Path(source)
            replacements.append(temporary)
            self.assertEqual(temporary.parent.resolve(), self.output.parent.resolve())
            self.assertEqual(self.output.read_bytes(), b"previous complete report\n")
            self.assertEqual(json.loads(temporary.read_bytes())["findings_count"], 2)
            self.assert_source_preserved()
            real_replace(source, destination)

        with patch("os.replace", side_effect=inspect_then_replace):
            code, _, stderr = self.main_cli(self.output)
        self.assertEqual(code, 0, stderr)
        self.assertEqual(len(replacements), 1, "report was not atomically replaced")
        self.assertEqual(json.loads(self.output.read_bytes())["findings_count"], 2)
        self.assertEqual(set(self.directory.iterdir()), before)
        self.assert_source_preserved()

    def test_success_has_deterministic_utf8_json_bytes(self):
        stdout_result = self.subprocess_cli()
        self.assertEqual(stdout_result.returncode, 0, stdout_result.stderr)
        result = self.subprocess_cli(output=self.output)
        self.assertEqual(result.returncode, 0, result.stderr)
        first = self.output.read_bytes()
        self.assertEqual(first, stdout_result.stdout.encode("utf-8"))
        self.assertTrue(first.endswith(b"\n"))
        self.assertNotIn(b"\r", first)
        self.assertEqual(json.loads(first)["findings_count"], 2)
        result = self.subprocess_cli(output=self.output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.read_bytes(), first)
        self.assert_source_preserved()
        self.assertEqual(set(self.directory.iterdir()), {self.source, self.output})

    def test_programming_errors_are_not_converted_to_input_errors(self):
        self.output.write_bytes(b"previous complete report\n")
        before = set(self.directory.iterdir())
        with patch.object(cli, "run_hunt", side_effect=TypeError("programming defect")):
            with self.assertRaisesRegex(TypeError, "programming defect"):
                self.main_cli(self.output)
        self.assert_source_preserved()
        self.assertEqual(self.output.read_bytes(), b"previous complete report\n")
        self.assertEqual(set(self.directory.iterdir()), before)


if __name__ == "__main__":
    unittest.main()
