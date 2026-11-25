import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


class CliTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.env = {
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_COUNT": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }

    def git(self, *args):
        subprocess.run(
            ["git", *args], cwd=self.root, env=self.env, check=True, capture_output=True,
        )

    def init_repo(self):
        if not shutil.which("git"):
            self.skipTest("Git is not installed")
        self.git("init", "--initial-branch=main")
        self.git("config", "user.name", "Guardian Tests")
        self.git("config", "user.email", "guardian@example.invalid")
        self.git("config", "core.autocrlf", "false")
        self.git("config", "commit.gpgsign", "false")

    def cli(self, *args, cwd=None):
        return subprocess.run(
            [sys.executable, "-m", "ai_code_guardian", *args],
            cwd=cwd or self.root, env=self.env, capture_output=True, encoding="utf-8", check=False,
        )

    def scan(self, *args, status, cwd=None):
        result = self.cli("scan", *args, "--format", "json", cwd=cwd)
        self.assertEqual(result.returncode, status, result.stderr + result.stdout)
        return json.loads(result.stdout)

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode("utf-8"))

    def commit(self):
        self.git("add", "--all")
        self.git("commit", "-m", "Fixture")

    def test_unborn_index_excludes_worktree_and_untracked(self):
        self.init_repo()
        self.write("snow ñ #.py", "eval(staged)\n")
        self.git("add", "--", "snow ñ #.py")
        self.write("snow ñ #.py", "safe = True\n")
        self.write("untracked.py", "exec(source)\n")
        (self.root / "nested").mkdir()
        report = self.scan("--staged", status=1, cwd=self.root / "nested")
        self.assertEqual([(item["path"], item["line"]) for item in report["findings"]], [("snow ñ #.py", 1)])

    def test_staged_reports_only_new_evidence_across_hunks(self):
        self.init_repo()
        before = "eval(old)\n" + "safe_call()\n" * 20 + "tail = 1\n"
        self.write("review.py", before)
        self.commit()
        self.write("review.py", before.replace("safe_call()", "exec(new)", 1) + "eval(new)\n")
        self.git("add", "review.py")
        self.write("review.py", before)
        report = self.scan("--staged", status=1)
        self.assertEqual([item["line"] for item in report["findings"]], [2, 23])

    def test_intent_to_add_does_not_scan_unstaged_content(self):
        self.init_repo()
        self.write("pending.py", "eval(uncommitted)\n")
        self.git("add", "--intent-to-add", "pending.py")
        self.assertEqual(self.scan("--staged", status=0)["findings"], [])

    def test_pure_rename_ignored_and_edit_reported_at_destination(self):
        self.init_repo()
        content = "eval(old)\n" + "safe_call()\n" * 25
        self.write("old.py", content)
        self.commit()
        self.git("mv", "old.py", "renamed file.py")
        self.assertEqual(self.scan("--staged", status=0)["findings"], [])
        self.write("renamed file.py", content + "eval(new)\n")
        self.git("add", "renamed file.py")
        report = self.scan("--staged", status=1)
        self.assertEqual([(item["path"], item["line"]) for item in report["findings"]], [("renamed file.py", 27)])

    def test_diff_uses_merge_base_and_committed_tip(self):
        self.init_repo()
        self.write("old.py", "eval(old)\n")
        self.commit()
        self.git("checkout", "-b", "topic")
        self.write("topic.py", "exec(new)\n")
        self.commit()
        self.git("checkout", "main")
        self.write("main.py", "eval(other_branch)\n")
        self.commit()
        self.write("topic.py", "eval(worktree)\n")
        report = self.scan("--diff", "main", "--head", "topic", status=1)
        self.assertEqual([item["path"] for item in report["findings"]], ["topic.py"])
        error = self.scan("--diff", "missing", status=2)
        self.assertIn("Cannot resolve", error["errors"][0])

    def test_deletion_does_not_report_removed_or_surviving_lines(self):
        self.init_repo()
        self.write("review.py", "eval(remove_me)\nexec(survivor)\n")
        self.commit()
        self.write("review.py", "exec(survivor)\n")
        self.git("add", "review.py")
        self.assertEqual(self.scan("--staged", status=0)["findings"], [])

    def test_conflicted_index_is_an_error(self):
        self.init_repo()
        self.write("review.py", "base = 0\n")
        self.commit()
        self.git("checkout", "-b", "topic")
        self.write("review.py", "base = 1\n")
        self.commit()
        self.git("checkout", "main")
        self.write("review.py", "base = 2\n")
        self.commit()
        merge = subprocess.run(["git", "merge", "topic"], cwd=self.root, env=self.env, capture_output=True)
        self.assertEqual(merge.returncode, 1)
        self.assertTrue(self.scan("--staged", status=2)["errors"])

    def test_full_scan_skips_unsupported_files_and_generated_dirs(self):
        self.write("src/code.py", "import os\nos.system(command)\n")
        self.write(".git/leak.py", "eval(old)\n")
        self.write("build/generated.py", "eval(old)\n")
        (self.root / "binary").write_bytes(b"\0invalid")
        (self.root / "non-utf8").write_bytes(b"\xff")
        (self.root / "huge").write_bytes(b"A" * (1024 * 1024 + 1))
        report = self.scan(status=1)
        self.assertEqual(report["files_scanned"], 1)
        self.assertEqual(report["files_skipped"], 3)
        self.assertEqual(report["findings"][0]["path"], "src/code.py")

    def test_full_scan_does_not_follow_a_link(self):
        self.write("elsewhere/secret.py", "eval(code)\n")
        (self.root / "target").mkdir()
        link = self.root / "target" / "link.py"
        try:
            link.symlink_to(self.root / "elsewhere" / "secret.py")
        except OSError:
            self.skipTest("This machine does not permit creation of symbolic links")
        report = self.scan("--path", "target", status=0)
        self.assertEqual(report["files_skipped"], 1)
        self.assertEqual(report["findings"], [])
        self.scan("--path", "target/link.py", status=2)

    def test_output_file_is_exclusive_and_exit_code_is_preserved(self):
        self.write("review.py", "eval(code)\n")
        args = ("scan", "--path", "review.py", "--format", "sarif", "--output", "guardian.sarif")
        result = self.cli(*args)
        self.assertEqual(result.returncode, 1)
        original = (self.root / "guardian.sarif").read_bytes()
        self.assertEqual(json.loads(original)["version"], "2.1.0")
        failed = self.cli(*args)
        self.assertEqual(failed.returncode, 2)
        self.assertIn("Could not write", failed.stderr)
        self.assertEqual((self.root / "guardian.sarif").read_bytes(), original)

    def test_head_requires_diff(self):
        result = self.cli("scan", "--head", "HEAD")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--head requires --diff", result.stderr)

    def test_path_policy_uses_current_directory_as_pattern_anchor(self):
        self.write("src/code.py", "eval(text)\nexec(text)\n")
        self.write(".ai-code-guardian.json", json.dumps({
            "suppressions": [{
                "rule": "ACG101", "path": "src/*.py", "line": 2,
                "reason": "known review fixture", "expires": "2099-01-01",
            }],
        }))
        for target, reported in (("src", "code.py"), ("src/code.py", "code.py"), (".", "src/code.py")):
            with self.subTest(target=target):
                report = self.scan("--path", target, status=1)
                self.assertEqual(report["suppressed_findings"], 1)
                self.assertEqual([(item["path"], item["line"]) for item in report["findings"]], [(reported, 1)])
        error = self.scan("--config", "missing.json", status=2)
        self.assertIn("policy file does not exist", error["errors"][0])

    def test_staged_policy_comes_from_index_even_on_first_commit(self):
        self.init_repo()
        self.write("code.py", "eval(text)\n")
        self.write(".ai-code-guardian.json", '{"rules":{"ACG101":"off"}}')
        self.git("add", "--all")
        self.write(".ai-code-guardian.json", "{}")
        report = self.scan("--staged", status=0)
        self.assertEqual(report["suppressed_findings"], 1)
        self.assertEqual(self.scan("--staged", "--config", ".ai-code-guardian.json", status=1)["suppressed_findings"], 0)

    def test_intent_to_add_policy_is_ignored_but_an_empty_staged_policy_fails(self):
        self.init_repo()
        self.write("code.py", "eval(text)\n")
        self.write(".ai-code-guardian.json", '{"rules":{"ACG101":"off"}}')
        self.git("add", "code.py")
        self.git("add", "--intent-to-add", ".ai-code-guardian.json")
        self.assertEqual(self.scan("--staged", status=1)["suppressed_findings"], 0)
        self.write(".ai-code-guardian.json", "")
        self.git("add", ".ai-code-guardian.json")
        self.assertIn("valid UTF-8 JSON", self.scan("--staged", status=2)["errors"][0])

    def test_diff_annotations_use_latest_base_policy_and_keep_full_report(self):
        self.init_repo()
        self.write("base.txt", "initial\n")
        self.commit()
        self.git("checkout", "-b", "feature")
        self.write(".ai-code-guardian.json", '{"rules":{"ACG101":"off"}}')
        self.write("review.py", "eval(text)\n")
        self.commit()
        self.git("checkout", "main")
        self.write(".ai-code-guardian.json", '{"rules":{"ACG101":"error"}}')
        self.commit()
        self.write(".ai-code-guardian.json", "private invalid worktree policy")
        run = self.cli(
            "scan", "--diff", "main", "--head", "feature", "--github-annotations",
            "--format", "sarif", "--output", "guardian.sarif",
        )
        self.assertEqual(run.returncode, 1, run.stdout + run.stderr)
        self.assertIn("::error file=review.py,line=1,title=ACG101", run.stdout)
        sarif = json.loads((self.root / "guardian.sarif").read_bytes())
        hits = sarif["runs"][0]["results"]
        self.assertEqual([(item["ruleId"], item["level"]) for item in hits], [("ACG101", "error")])

    def test_annotation_mode_requires_a_separate_report_file(self):
        result = self.cli("scan", "--diff", "main", "--github-annotations")
        self.assertEqual(result.returncode, 2)
        self.assertIn("requires --diff BASE and --output FILE", result.stderr)

    def test_staged_session_default_comes_from_index(self):
        self.init_repo()
        source = "import requests\nclient = requests.Session()\nclient.verify = (\n    True\n)\n"
        self.write("probe.py", source)
        self.commit()
        self.write("probe.py", source.replace("True", "False"))
        self.git("add", "probe.py")
        self.write("probe.py", source)
        report = self.scan("--staged", status=1)
        self.assertEqual(
            [(item["rule_id"], item["line"]) for item in report["findings"]],
            [("ACG104", 4)],
        )

    def test_error_threshold_retains_warnings_and_sarif_exit_code(self):
        self.write("probe.py", "import requests\ns = requests.Session()\ns.get(url, verify=False)\n")
        strict = self.scan("--path", "probe.py", status=1)
        self.assertEqual(strict["findings"][0]["severity"], "warning")

        result = self.cli("scan", "--path", "probe.py", "--fail-on", "error", "--format", "sarif")
        self.assertEqual(result.returncode, 0, result.stderr)
        sarif = json.loads(result.stdout)["runs"][0]
        self.assertEqual(sarif["invocations"][0]["exitCode"], 0)
        self.assertEqual([(item["ruleId"], item["level"]) for item in sarif["results"]], [("ACG104", "warning")])

    def test_error_threshold_respects_staged_policy_and_operational_errors(self):
        self.init_repo()
        self.write("probe.py", "import requests\ns = requests.Session()\ns.verify = False\n")
        self.write(".ai-code-guardian.json", "{}")
        self.git("add", "--all")
        self.assertEqual(self.scan("--staged", "--fail-on", "error", status=0)["findings"][0]["severity"], "warning")

        self.write(".ai-code-guardian.json", '{"rules":{"ACG104":"error"}}')
        self.git("add", ".ai-code-guardian.json")
        self.assertEqual(self.scan("--staged", "--fail-on", "error", status=1)["findings"][0]["severity"], "error")

        self.write(".ai-code-guardian.json", "{")
        self.git("add", ".ai-code-guardian.json")
        self.assertTrue(self.scan("--staged", "--fail-on", "error", status=2)["errors"])
