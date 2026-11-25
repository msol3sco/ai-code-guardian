import json
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from ai_code_guardian.audit import audit_requirements, read_pins, run_pip_audit
from ai_code_guardian.model import GuardianError, Report
from ai_code_guardian.reporting import render


class AuditTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "requirements.txt"

    def test_plain_pins_and_line_numbers(self):
        self.path.write_text("# fixture\nSample_Package==1.2.3 # comment\nOther==2.0\n", encoding="utf-8")
        self.assertEqual(read_pins(self.path), {"sample-package": ("1.2.3", 2), "other": ("2.0", 3)})

    def test_untrusted_requirements_directives_rejected_without_echo(self):
        for requirement in (
            "-r another.txt", "pkg>=1.0", "--index-url https://example.invalid",
            "pkg @ https://example.invalid/payload", "pkg==1.0; sys_platform == 'win32'",
            "pkg==1.*", "pkg==1.0\nPkg==2.0",
        ):
            with self.subTest(requirement=requirement):
                self.path.write_text(requirement, encoding="utf-8")
                with self.assertRaises(GuardianError) as raised:
                    read_pins(self.path)
                self.assertNotIn(requirement, str(raised.exception))

    @patch("ai_code_guardian.audit.importlib.util.find_spec", return_value=None)
    def test_missing_auditor_has_actionable_error(self, _find):
        with self.assertRaisesRegex(GuardianError, r"\.\[audit\]"):
            run_pip_audit({"sample": ("1.2", 1)})

    @patch("ai_code_guardian.audit.run_pip_audit")
    def test_audit_maps_advisories_and_incomplete_audit(self, run):
        self.path.write_text("# heading\none==1.0\ntwo==2.0", encoding="utf-8")
        run.return_value = [
            {"name": "One", "version": "1.0", "vulns": [
                {"id": "CVE-2099-0309", "description": "forbidden raw content"},
            ]},
            {"name": "Two", "skip_reason": "forbidden raw content"},
        ]
        report = Report()
        audit_requirements(report, self.path)
        self.assertEqual(report.exit_code, 2)
        self.assertEqual([(item.rule_id, item.line) for item in report.findings], [("ACG201", 2)])
        output = render(report, "json")
        self.assertIn("CVE-2099-0309", output)
        self.assertNotIn("forbidden raw content", output)

    @patch("ai_code_guardian.audit.importlib.util.find_spec", return_value=True)
    @patch("ai_code_guardian.audit.subprocess.run")
    def test_pip_audit_vulnerability_exit_code_and_input(self, invoke, _find):
        def fake_run(args, **kwargs):
            manifest = Path(args[args.index("-r") + 1])
            self.assertEqual(manifest.read_text(encoding="utf-8"), "sample==1.2\n")
            self.assertIn("--no-deps", args)
            self.assertIn("--disable-pip", args)
            self.assertIn("-I", args)
            self.assertTrue(kwargs["capture_output"])
            return subprocess.CompletedProcess(
                args, 1, json.dumps({"dependencies": [{"name": "sample"}]}).encode("utf-8"), b"",
            )

        invoke.side_effect = fake_run
        self.assertEqual(run_pip_audit({"sample": ("1.2", 1)}), [{"name": "sample"}])

    @patch("ai_code_guardian.audit.importlib.util.find_spec", return_value=True)
    @patch("ai_code_guardian.audit.subprocess.run")
    def test_failed_analyzer_output_is_not_echoed(self, invoke, _find):
        invoke.return_value = subprocess.CompletedProcess([], 1, b"invalid", b"private-output")
        with self.assertRaises(GuardianError) as raised:
            run_pip_audit({"sample": ("1.2", 1)})
        self.assertNotIn("private-output", str(raised.exception))
