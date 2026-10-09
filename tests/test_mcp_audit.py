"""Tests for hooks/mcp-audit.py log location.

The hook input's "cwd" follows Claude's `cd`, so the audit log must be
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


def _run_hook(hook_path, payload_cwd, project_dir_env=None):
    env = {k: v for k, v in os.environ.items() if k != "CLAUDE_PROJECT_DIR"}
    if project_dir_env is not None:
        env["CLAUDE_PROJECT_DIR"] = project_dir_env
    payload = {
        "tool_name": "mcp__demo__ping",
        "tool_input": {"a": 1},
        "session_id": "test",
        "cwd": payload_cwd,
    }
    return subprocess.run(
        [sys.executable, hook_path],
        input=json.dumps(payload),
        cwd=payload_cwd,
        env=env,
        capture_output=True,
        text=True,
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


if __name__ == "__main__":
    unittest.main()
