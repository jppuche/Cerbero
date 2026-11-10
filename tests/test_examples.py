"""Checks on examples/settings.local.json, the hook wiring users copy.

Matcher rules (Claude Code hooks reference): a matcher made only of letters,
digits, '_', '-', spaces, ',' and '|' is an exact-name list; anything else is
an unanchored JavaScript regular expression. Python's re is close enough for
the patterns used here.
"""
import json
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLE = os.path.join(ROOT, "examples", "settings.local.json")


def _load():
    with open(EXAMPLE, encoding="utf-8") as f:
        return json.load(f)


def _matches(matcher, tool):
    if re.fullmatch(r"[A-Za-z0-9_\-, |]+", matcher):
        return tool in [m.strip() for m in re.split(r"[|,]", matcher)]
    return re.search(matcher, tool) is not None


def _matchers_for(hooks, event, script):
    return [entry.get("matcher", "") for entry in hooks.get(event, [])
            if any(script in h.get("command", "") for h in entry.get("hooks", []))]


class TestExampleSettings(unittest.TestCase):
    def setUp(self):
        self.hooks = _load()["hooks"]

    def test_pre_tool_security_covers_both_shell_tools(self):
        matchers = _matchers_for(self.hooks, "PreToolUse", "pre-tool-security.py")
        self.assertTrue(matchers)
        for tool in ("Bash", "PowerShell"):
            with self.subTest(tool=tool):
                self.assertTrue(any(_matches(m, tool) for m in matchers))
        self.assertFalse(any(_matches(m, "Read") for m in matchers))

    def test_no_glob_style_mcp_matcher(self):
        # "mcp__*" is a regex ("mcp_" then any number of "_"), not a glob.
        for event, entries in self.hooks.items():
            for entry in entries:
                with self.subTest(event=event, matcher=entry.get("matcher")):
                    self.assertNotEqual(entry.get("matcher"), "mcp__*")

    def test_user_prompt_submit_has_no_matcher(self):
        # UserPromptSubmit does not support matchers; a key there is ignored.
        for entry in self.hooks.get("UserPromptSubmit", []):
            self.assertNotIn("matcher", entry)

    def test_external_content_hooks_cover_exactly_external_tools(self):
        for event, script in (("PreToolUse", "untrusted-source-reminder.py"),
                              ("PostToolUse", "validate-tool-output.py")):
            matchers = _matchers_for(self.hooks, event, script)
            self.assertTrue(matchers, script)
            for tool, want in (("WebFetch", True), ("WebSearch", True),
                               ("mcp__github__search", True), ("Bash", False),
                               ("Read", False), ("xmcp_tool", False)):
                with self.subTest(script=script, tool=tool):
                    self.assertEqual(any(_matches(m, tool) for m in matchers), want)


if __name__ == "__main__":
    unittest.main()
