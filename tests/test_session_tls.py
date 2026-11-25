import unittest
from textwrap import dedent

from ai_code_guardian.model import Report
from ai_code_guardian.rules import inspect_source


class SessionTLSTests(unittest.TestCase):
    def findings(self, source, changed=None):
        report = Report()
        inspect_source(report, "client.py", dedent(source).lstrip("\n"), changed)
        return [(item.rule_id, item.line) for item in report.findings]

    def test_session_methods_and_default_verification_flag(self):
        self.assertEqual(self.findings("""
            import requests as http
            from requests import Session as HTTPSession
            from requests.sessions import session as open_session

            client = http.Session()
            client.get(url, verify=False)
            client.verify = False
            alias = client
            alias.send(prepared, verify=False)
            alias.post(url, verify=False)
            http.Session().head(url, verify=False)
            with HTTPSession() as other:
                other.verify: bool = False
                other.request("GET", url, verify=False)
            open_session().get(url, verify=False)
        """), [("ACG104", line) for line in (6, 7, 9, 10, 11, 13, 14, 15)])

    def test_ignores_safe_ca_settings_and_lookalike_clients(self):
        self.assertEqual(self.findings("""
            import requests

            def probe():
                client = requests.Session()
                client.verify = "/etc/ssl/ca.pem"
                client.get(url, verify="/etc/ssl/ca.pem")
                client.verify = True
                client.get(url, verify=True)
                client.get(url, verify=setting)

            def third_party(client):
                client.verify = False
                client.get(url, verify=False)

            def replaced():
                client = requests.Session()
                client = external_client()
                client.verify = False

            def shadowed(requests):
                client = requests.Session()
                client.get(url, verify=False)
        """), [])

    def test_isolates_bindings_in_sibling_functions(self):
        self.assertEqual(self.findings("""
            import requests
            client = requests.Session()

            def known():
                return client.get(url, verify=False)

            def unknown(client):
                return client.get(url, verify=False)

            def inner():
                from requests import Session
                with Session() as handled:
                    handled.verify = False

            def unrelated():
                return handled.get(url, verify=False)
        """), [("ACG104", 5), ("ACG104", 13)])

    def test_respects_changed_keyword_and_assignment_evidence(self):
        source = """
            import requests
            client = requests.Session()
            client.verify = (
                False
            )
            client.get(
                url,
                verify=False,
            )
        """
        for line, expected in ((2, []), (3, [3]), (4, [4]), (6, [6]), (7, []), (8, [8])):
            with self.subTest(line=line):
                self.assertEqual(
                    self.findings(source, [(line, line)]),
                    [("ACG104", number) for number in expected],
                )
