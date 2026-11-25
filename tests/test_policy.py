import unittest
from datetime import date
from unittest.mock import patch

from ai_code_guardian.model import Finding, GuardianError, Report
from ai_code_guardian.policy import read_policy
from ai_code_guardian.reporting import render


class PolicyTests(unittest.TestCase):
    def test_levels_and_recursive_and_line_scoped_exceptions(self):
        policy = read_policy(b"""{
          "rules": {"ACG001": "warning", "ACG104": "off"},
          "suppressions": [
            {"rule": "ACG003", "path": "tests/**/*.txt", "line": 2,
             "reason": "private fixture note", "expires": "2027-01-01"},
            {"rule": "ACG102", "path": "tests/*.py",
             "reason": "one directory", "expires": "2027-01-01"}
          ]
        }""")
        report = Report(findings=[
            Finding("tests/key", 1, "ACG001"),
            Finding("tests/tls.py", 1, "ACG104"),
            Finding("tests/input.txt", 2, "ACG003"),
            Finding("tests/deep/input.txt", 2, "ACG003"),
            Finding("tests/deep/input.txt", 3, "ACG003"),
            Finding("tests/deep/input.py", 2, "ACG102"),
            Finding("Tests/deep/input.txt", 2, "ACG003"),
        ])
        with patch("ai_code_guardian.policy.datetime") as clock:
            clock.now.return_value.date.return_value = date(2027, 1, 1)
            policy.apply(report)
        self.assertEqual(report.suppressed_findings, 3)
        self.assertEqual(report.findings[0].severity, "warning")
        self.assertEqual(len(report.findings), 4)
        self.assertEqual(report.exit_code, 1)
        self.assertEqual(report.notes, [])
        for format_ in ("text", "json", "sarif"):
            result = render(report, format_)
            self.assertNotIn("private fixture note", result)
            self.assertIn("suppressed", result)

    def test_expired_exceptions_reactivate_findings(self):
        policy = read_policy(b"""{"suppressions": [
          {"rule": "ACG003", "path": "file.txt", "reason": "temporary", "expires": "2027-01-01"}
        ]}""")
        report = Report(findings=[Finding("file.txt", 1, "ACG003")])
        with patch("ai_code_guardian.policy.datetime") as clock:
            clock.now.return_value.date.return_value = date(2027, 1, 2)
            policy.apply(report)
        self.assertEqual(report.suppressed_findings, 0)
        self.assertEqual(len(report.findings), 1)
        self.assertIn("expired", report.notes[0])

    def test_invalid_policies_fail_without_echoing_input(self):
        for data in (
            b'[]', b'{"rules": {}, "rules": {}}', b'{"private-fixture-marker": true}',
            b'{"rules": {"ACG201": "off"}}', b'{"rules": {"ACG104": []}}',
            b'{"suppressions": {}}',
            b'{"suppressions": [{"rule":"ACG001","path":"../outside","reason":"abc","expires":"2027-01-01"}]}',
            b'{"suppressions": [{"rule":"ACG001","path":"code.py","reason":" ","expires":"2027-01-01"}]}',
            b'{"suppressions": [{"rule":"ACG001","path":"code.py","reason":"abc","expires":"2027-02-30"}]}',
            b'{"suppressions": [{"rule":"ACG001","path":"code.py","reason":"abc","expires":"2027-01-01","line":true}]}',
            b' ' * 65537,
        ):
            with self.subTest(data=data[:150]), self.assertRaises(GuardianError) as error:
                read_policy(data)
            self.assertNotIn("private-fixture-marker", str(error.exception))
