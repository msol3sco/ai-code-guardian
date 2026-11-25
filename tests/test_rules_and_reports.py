import json
import unittest

from ai_code_guardian.model import Report
from ai_code_guardian.reporting import render
from ai_code_guardian.rules import inspect_source


class RuleTests(unittest.TestCase):
    def test_secret_redaction_and_locations(self):
        token = "gh" + "p_" + "Xq9" * 12
        credential = "A1b2" + "C3d4e5"
        marker = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
        report = Report()
        inspect_source(
            report, "dir/.env ex ample#1",
            f"TOKEN={token}\nDB_PASSWORD={credential}\n{marker}\n",
        )
        self.assertEqual(
            [(item.rule_id, item.line) for item in report.findings],
            [("ACG002", 1), ("ACG003", 2), ("ACG001", 3)],
        )
        for format_ in ("text", "json", "sarif"):
            output = render(report, format_)
            for value in (token, credential, marker, "DB_PASSWORD="):
                self.assertNotIn(value, output)
        sarif = json.loads(render(report, "sarif"))
        location = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        self.assertEqual(location["artifactLocation"]["uri"], "dir/.env%20ex%20ample%231")
        self.assertEqual(sarif["version"], "2.1.0")

    def test_known_formats_and_placeholder(self):
        report = Report()
        sample = "\n".join([
            "AS" + "IA" + "A9" * 8,
            "xox" + "b-demo-" + "A9" * 10,
            "sk-" + "proj-" + "A9_j" * 12,
            "sk_" + "live_" + "A9j" * 12,
            'password = "example-password123"',
            "TOKEN=$TOKEN",
            'password = "aaaaaaaab"',
            'password = "{credential}"',
        ])
        inspect_source(report, ".env.local", sample)
        self.assertEqual([item.line for item in report.findings], [1, 2, 3, 4])

    def test_python_import_aliases_and_safe_calls(self):
        report = Report()
        inspect_source(
            report, "code.py",
            "from pickle import loads as unpack\n"
            "import subprocess as sp\nimport requests as req\n"
            "eval(text)\nunpack(blob)\nsp.run(args, shell=True)\n"
            "req.get(url, verify=False)\nsp.run(args, shell=False)\n"
            "req.get(url, verify=True)\n'os.system(thing)'\n",
        )
        self.assertEqual(
            [(item.rule_id, item.line) for item in report.findings],
            [("ACG101", 4), ("ACG103", 5), ("ACG102", 6), ("ACG104", 7)],
        )

    def test_finding_can_point_to_changed_multiline_keyword(self):
        source = "import subprocess\nsubprocess.run(\n    command,\n    shell=True,\n)\n"
        for changed_line, expected in ((3, []), (4, [4]), (2, [2])):
            report = Report()
            inspect_source(report, "code.py", source, [(changed_line, changed_line)])
            self.assertEqual([item.line for item in report.findings], expected)

    def test_malformed_python_still_gets_secret_checks(self):
        report = Report()
        credential = "A1b2" + "C3d4e5"
        inspect_source(report, "code.py", f"password = '{credential}'\nif (\n")
        result = render(report, "text")
        self.assertEqual(report.exit_code, 1)
        self.assertEqual(len(report.notes), 1)
        self.assertNotIn(credential, result)

    def test_control_characters_in_text_paths(self):
        report = Report()
        inspect_source(report, "line\nbreak.py", "eval(code)")
        text = render(report, "text")
        self.assertIn("line\\nbreak.py:1:", text)
        self.assertEqual(len(text.splitlines()), 2)
