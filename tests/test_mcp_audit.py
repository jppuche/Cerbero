"""Tests for hooks/mcp-audit.py log location.

The hook input's "cwd" follows Claude's `cd`, so the audit log is
anchored to the project root, not to that cwd. Each test copies the hook
into a throwaway directory tree that mimics a deployment and runs it as
a real subprocess. CLAUDE_PROJECT_DIR is stripped from the environment
unless a test sets it, since these tests may themselves run inside a
Claude Code session.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK_SRC = os.path.join(REPO_ROOT, "hooks", "mcp-audit.py")


def _run_hook(hook_path, payload_cwd, project_dir_env=None, extra_env=None, raw=None):
    env = {k: v for k, v in os.environ.items()
           if k not in ("CLAUDE_PROJECT_DIR", "CERBERO_LOG_DIR")}
    env["PYTHONIOENCODING"] = "cp1252"  # see test_hooks_io.py
    if project_dir_env is not None:
        env["CLAUDE_PROJECT_DIR"] = project_dir_env
    env.update(extra_env or {})
    payload = {
        "tool_name": "mcp__demo__ping",
        "tool_input": {"query": "Árbol"},
        "session_id": "test",
        "cwd": payload_cwd,
    }
    data = raw if raw is not None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return subprocess.run(
        [sys.executable, hook_path],
        input=data,
        cwd=payload_cwd,
        env=env,
        capture_output=True,
        timeout=30,
    )


def _deploy(dest_dir):
    os.makedirs(dest_dir)
    hook = os.path.join(dest_dir, "mcp-audit.py")
    shutil.copy(HOOK_SRC, hook)
    return hook


class TestMcpAuditLogLocation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.project = os.path.join(self.tmp, "proj")
        self.sub = os.path.join(self.project, "src", "pkg")
        os.makedirs(self.sub)

    def _log(self, root):
        return os.path.join(root, ".claude", "security", "mcp-audit.log")

    def _assert_logged_at_root_only(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(os.path.isfile(self._log(self.project)))
        self.assertFalse(os.path.exists(os.path.join(self.sub, ".claude")))

    def test_project_hooks_dir_cwd_in_subfolder(self):
        hook = _deploy(os.path.join(self.project, ".claude", "hooks"))
        self._assert_logged_at_root_only(_run_hook(hook, self.sub))

    def test_skill_hooks_dir_cwd_in_subfolder(self):
        hook = _deploy(os.path.join(self.project, ".claude", "skills", "cerbero", "hooks"))
        self._assert_logged_at_root_only(_run_hook(hook, self.sub))

    def test_global_install_uses_claude_project_dir(self):
        # Hook under a fake ~/.claude/hooks/: CLAUDE_PROJECT_DIR wins over
        # the script location, so the log stays per project.
        fake_home = os.path.join(self.tmp, "home")
        hook = _deploy(os.path.join(fake_home, ".claude", "hooks"))
        self._assert_logged_at_root_only(_run_hook(hook, self.sub, self.project))
        self.assertFalse(os.path.exists(os.path.join(fake_home, ".claude", "security")))

    def test_no_claude_ancestor_falls_back_to_input_cwd(self):
        # Running from a checkout of this repo (hooks/ not under .claude/)
        # keeps the pre-fix behavior.
        hook = _deploy(os.path.join(self.tmp, "checkout", "hooks"))
        result = _run_hook(hook, self.project)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(os.path.isfile(self._log(self.project)))

    def test_cerbero_log_dir_override_records_project(self):
        hook = _deploy(os.path.join(self.project, ".claude", "hooks"))
        custom = os.path.join(self.tmp, "central")
        result = _run_hook(hook, self.sub, extra_env={"CERBERO_LOG_DIR": custom})
        self.assertEqual(result.returncode, 0, result.stderr)
        with open(os.path.join(custom, "mcp-audit.log"), encoding="utf-8") as f:
            entry = json.loads(f.readline())
        self.assertEqual(os.path.normcase(entry["project"]), os.path.normcase(self.project))
        self.assertEqual(entry["input_keys"], ["query"])
        self.assertFalse(os.path.exists(os.path.join(self.project, ".claude", "security")))

    def test_fails_open(self):
        hook = _deploy(os.path.join(self.project, ".claude", "hooks"))
        cases = [
            ("malformed input", {}, b"garbage"),
            ("non-object input", {}, b"[1, 2]"),
            ("log dir is a file", {"CERBERO_LOG_DIR": hook}, None),
        ]
        for label, env, raw in cases:
            with self.subTest(label):
                result = _run_hook(hook, self.sub, extra_env=env, raw=raw)
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
