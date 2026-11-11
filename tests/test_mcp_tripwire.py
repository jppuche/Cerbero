"""Tests for the runtime tripwire and the reminder in hooks/mcp-audit.py.

The hook compares the tool being called with the tool names stored in a
cerbero-mcp-snapshot/1 baseline. It warns through one JSON object on stdout
("systemMessage"), because Claude Code discards the stderr of a hook that
exits 0. It must never block on its own and never fail closed.

Also here: static checks on the new files (stdlib-only imports, Python 3.8
syntax).
"""
import ast
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK_SRC = os.path.join(REPO_ROOT, "hooks", "mcp-audit.py")

BASELINE = {
    "format": "cerbero-mcp-snapshot/1",
    "servers": {
        "wiki": {"status": "ok", "tools": {"search_docs": {"hash": "sha256:x", "def": {}},
                                             "read.page": {"hash": "sha256:y", "def": {}}}},
        "my server": {"status": "ok", "tools": {"ping": {"hash": "sha256:z", "def": {}}}},
        "remote": {"status": "skipped", "reason": "oauth"},
    },
}


class TripwireCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.project = os.path.join(self.tmp, "proj")
        self.security = os.path.join(self.project, ".claude", "security")
        hooks = os.path.join(self.project, ".claude", "hooks")
        os.makedirs(self.security)
        os.makedirs(hooks)
        self.hook = os.path.join(hooks, "mcp-audit.py")
        shutil.copy(HOOK_SRC, self.hook)

    def write_baseline(self, content=BASELINE):
        with open(os.path.join(self.security, "mcp-inventory.json"), "w", encoding="utf-8") as f:
            f.write(content if isinstance(content, str) else json.dumps(content))

    def call(self, tool, session="s1", mode=None, mcp_server=None, extra_env=None):
        env = {k: v for k, v in os.environ.items()
               if k not in ("CLAUDE_PROJECT_DIR", "CERBERO_LOG_DIR", "CERBERO_TRIPWIRE")}
        env["PYTHONIOENCODING"] = "cp1252"
        if mode:
            env["CERBERO_TRIPWIRE"] = mode
        env.update(extra_env or {})
        payload = {"tool_name": tool, "tool_input": {"q": "x"}, "session_id": session, "cwd": self.project}
        if mcp_server:
            payload["mcp_server"] = mcp_server
        p = subprocess.run([sys.executable, self.hook], input=json.dumps(payload).encode("utf-8"),
                           cwd=self.project, env=env, capture_output=True, timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stderr, b"")
        out = p.stdout.decode("ascii")       # ASCII only: safe on any console code page
        if not out.strip():
            return None
        self.assertEqual(len(out.strip().splitlines()), 1, "more than one line on stdout")
        obj = json.loads(out)
        self.assertIsInstance(obj, dict)
        return obj

    def log_entries(self):
        with open(os.path.join(self.security, "mcp-audit.log"), encoding="utf-8") as f:
            return [json.loads(line) for line in f]


class TestTripwire(TripwireCase):
    def test_known_tool_is_silent(self):
        self.write_baseline()
        self.assertIsNone(self.call("mcp__wiki__search_docs"))
        self.assertEqual(len(self.log_entries()), 1)

    def test_names_are_matched_in_claude_code_form(self):
        # "read.page" is called as read_page, "my server" as my_server.
        self.write_baseline()
        self.assertIsNone(self.call("mcp__wiki__read_page"))
        self.assertIsNone(self.call("mcp__my_server__ping"))
        self.assertIsNone(self.call("mcp__my_server__ping", mcp_server={"name": "my server", "source": "user"}))

    def test_unknown_tool_warns_once_per_session(self):
        self.write_baseline()
        out = self.call("mcp__wiki__export_all")
        self.assertEqual(list(out), ["systemMessage"])
        self.assertIn("export_all", out["systemMessage"])
        self.assertIn("wiki", out["systemMessage"])
        self.assertIsNone(self.call("mcp__wiki__export_all"))             # same session: once
        self.assertIsNotNone(self.call("mcp__wiki__export_all", session="s2"))
        self.assertEqual(len(self.log_entries()), 3)                     # every call is still logged

    def test_unknown_server_warns_once_per_session(self):
        self.write_baseline()
        out = self.call("mcp__plugin_docs_search__query")
        self.assertIn("not in the approved baseline", out["systemMessage"])
        self.assertNotIn("hookSpecificOutput", out)
        self.assertIsNone(self.call("mcp__plugin_docs_search__other_tool"))

    def test_server_whose_tools_were_not_read(self):
        self.write_baseline()
        out = self.call("mcp__remote__anything")
        self.assertIn("oauth", out["systemMessage"])

    def test_ask_mode_is_opt_in_and_only_for_unknown_tools(self):
        self.write_baseline()
        out = self.call("mcp__wiki__export_all", mode="ask")
        self.assertEqual(out["hookSpecificOutput"]["hookEventName"], "PreToolUse")
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "ask")
        self.assertIn("export_all", out["hookSpecificOutput"]["permissionDecisionReason"])
        again = self.call("mcp__wiki__export_all", mode="ask")           # asks on every call
        self.assertEqual(again["hookSpecificOutput"]["permissionDecision"], "ask")
        self.assertIsNone(self.call("mcp__wiki__search_docs", mode="ask"))
        unknown_server = self.call("mcp__somewhere__tool", mode="ask")
        self.assertNotIn("hookSpecificOutput", unknown_server)           # warn only

    def test_off_mode(self):
        self.write_baseline()
        self.assertIsNone(self.call("mcp__wiki__export_all", mode="off"))

    def test_no_decision_is_ever_allow_or_deny(self):
        self.write_baseline()
        for mode in (None, "warn", "ask", "off", "nonsense"):
            for tool in ("mcp__wiki__search_docs", "mcp__wiki__export_all", "mcp__nowhere__x"):
                with self.subTest(mode=mode, tool=tool):
                    out = self.call(tool, session="%s-%s" % (mode, tool), mode=mode) or {}
                    decision = out.get("hookSpecificOutput", {}).get("permissionDecision")
                    self.assertIn(decision, (None, "ask"))

    def test_fails_open_without_output(self):
        cases = {
            "no baseline": None,
            "corrupt baseline": "{not json",
            "empty baseline": "",
            "legacy text baseline": "wiki: npx wiki - connected\n",
            "legacy json baseline": json.dumps([{"name": "wiki", "status": "connected"}]),
            "wrong shapes": json.dumps({"format": "cerbero-mcp-snapshot/1", "servers": {"wiki": 7, "x": {"tools": 3}}}),
        }
        for label, content in cases.items():
            with self.subTest(label):
                path = os.path.join(self.security, "mcp-inventory.json")
                if content is None:
                    if os.path.exists(path):
                        os.remove(path)
                else:
                    self.write_baseline(content)
                if label == "wrong shapes":
                    self.call("mcp__wiki__export_all", session=label)   # must not crash; output not asserted
                else:
                    self.assertIsNone(self.call("mcp__wiki__export_all", session=label))

    def test_corrupt_cache_is_rebuilt(self):
        self.write_baseline()
        with open(os.path.join(self.security, "mcp-tripwire-cache.json"), "w") as f:
            f.write("[broken")
        self.assertIsNotNone(self.call("mcp__wiki__export_all"))
        self.assertIsNone(self.call("mcp__wiki__search_docs"))

    def test_new_baseline_replaces_the_cached_tool_set(self):
        self.write_baseline()
        self.assertIsNotNone(self.call("mcp__wiki__export_all"))
        newer = json.loads(json.dumps(BASELINE))
        newer["servers"]["wiki"]["tools"]["export_all"] = {"hash": "sha256:n", "def": {}}
        self.write_baseline(newer)
        self.assertIsNone(self.call("mcp__wiki__export_all", session="s9"))

    def test_baseline_is_read_from_the_project_even_with_a_central_log_dir(self):
        self.write_baseline()
        central = os.path.join(self.tmp, "central")
        out = self.call("mcp__wiki__export_all", extra_env={"CERBERO_LOG_DIR": central})
        self.assertIsNotNone(out)
        self.assertTrue(os.path.isfile(os.path.join(central, "mcp-audit.log")))

    def test_non_mcp_tool_is_ignored(self):
        self.write_baseline()
        self.assertIsNone(self.call("Bash"))


class TestReminder(TripwireCase):
    def test_reminder_reaches_the_user_through_system_message(self):
        with open(os.path.join(self.security, "invocation-counter.txt"), "w") as f:
            f.write("49")
        out = self.call("mcp__wiki__search_docs")
        self.assertIn("50 MCP invocations", out["systemMessage"])
        self.assertIn("/cerbero verify", out["systemMessage"])
        self.assertIsNone(self.call("mcp__wiki__search_docs"))           # call 51

    def test_reminder_and_warning_share_one_object(self):
        self.write_baseline()
        with open(os.path.join(self.security, "invocation-counter.txt"), "w") as f:
            f.write("99")
        out = self.call("mcp__wiki__export_all")
        self.assertIn("export_all", out["systemMessage"])
        self.assertIn("100 MCP invocations", out["systemMessage"])


class TestStatic(unittest.TestCase):
    """Case 12: the new code stays stdlib-only and parses as Python 3.8."""

    FILES = [
        os.path.join("hooks", "cerbero-mcp-snapshot.py"),
        os.path.join("hooks", "mcp-audit.py"),
        os.path.join("tests", "fixtures", "fake_mcp_server.py"),
        os.path.join("tests", "fixtures", "fake_mcp_http.py"),
    ]
    STDLIB = {"argparse", "hashlib", "json", "os", "queue", "re", "shutil", "signal", "subprocess", "sys",
              "tempfile", "threading", "time", "urllib", "datetime", "random", "http"}

    def _tree(self, rel, **kw):
        with open(os.path.join(REPO_ROOT, rel), encoding="utf-8") as f:
            return ast.parse(f.read(), rel, **kw)

    def test_imports_are_stdlib_only(self):
        for rel in self.FILES:
            for node in ast.walk(self._tree(rel)):
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    self.assertEqual(node.level, 0, "%s: relative import" % rel)
                    names = [node.module]
                for name in names:
                    with self.subTest(file=rel, module=name):
                        self.assertIn(name.split(".")[0], self.STDLIB)

    def test_python_38_syntax(self):
        for rel in self.FILES:
            with self.subTest(file=rel):
                self._tree(rel, feature_version=(3, 8))

    def test_snapshot_script_never_uses_a_shell(self):
        with open(os.path.join(REPO_ROOT, self.FILES[0]), encoding="utf-8") as f:
            src = f.read()
        self.assertNotIn("shell=True", src)
        self.assertNotIn("os.system", src)


if __name__ == "__main__":
    unittest.main()
