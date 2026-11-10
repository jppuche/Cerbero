"""Consistency checks for the skill documents in .claude/skills/cerbero/.

They guard the reconciliation of the three diverging copies (1.3.0): stale
guidance that must not come back, rules that must stay, and links between
the documents that must resolve. Stdlib unittest only.
"""
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILL_DIR = os.path.join(ROOT, ".claude", "skills", "cerbero")
DOCS = sorted(f for f in os.listdir(SKILL_DIR) if f.endswith(".md"))


def _read(name):
    with open(os.path.join(SKILL_DIR, name), encoding="utf-8") as f:
        return f.read()


def _slug(heading):
    """GitHub's heading anchor: lowercase, drop punctuation, spaces to '-'."""
    text = heading.strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def _anchors(text):
    anchors = set()
    in_code = False
    for line in text.splitlines():
        if line.startswith("```"):
            in_code = not in_code
            continue
        m = re.match(r"^#{1,6}\s+(.*)$", line)
        if m and not in_code:
            anchors.add(_slug(m.group(1)))
    return anchors


class TestStaleGuidanceAbsent(unittest.TestCase):
    """Strings that described removed steps, wrong flags or internal IDs."""

    ABSENT = [
        "mcp-scan@latest",          # mcp-scan step dropped (Snyk cloud transmission)
        "no esta disponible",       # user-facing templates are English, translated at delivery
        "Ejecutar con",
        "baseline actualizado",
        "Fecha anterior",
        "(I-1)",                    # internal audit IDs
        "(I-3)",
        "C-SEC-",
        "Sentinel",                 # Ignite agent name
        "v0.3.2",                   # agent-ops kit version, not a Cerbero version
        "Sandbox compliance",       # replaced by "Isolation compliance"
        "Sandbox enforcement",
    ]

    def test_absent(self):
        for name in DOCS:
            text = _read(name)
            for s in self.ABSENT:
                with self.subTest(doc=name, string=s):
                    self.assertNotIn(s, text)

    def test_no_claude_sandbox_flag_recommended(self):
        # The flag does not exist; the only allowed mention says so.
        for name in DOCS:
            for m in re.finditer(r"claude --sandbox", _read(name)):
                ctx = _read(name)[max(0, m.start() - 12):m.start()]
                with self.subTest(doc=name, pos=m.start()):
                    self.assertIn("no `", ctx)


class TestRequiredGuidancePresent(unittest.TestCase):

    PRESENT = {
        "SKILL.md": [
            "without whole-process isolation",
            "10. Talk to the user in the language they write in.",
            "**Isolation enforcement:**",
            "The built-in `/sandbox` alone is not enough.",
        ],
        "op-evaluate-mcp.md": [
            "### Isolation enforcement (before installation)",
            "| Risk is HIGH or CRITICAL (Step 5) | REQUIRES HUMAN REVIEW |",
            "| External scanner (YARA) detection in Step 4 (if run) | REQUIRES HUMAN REVIEW |",
        ],
        "op-evaluate-skill.md": [
            "| The Skill folder holds any non-Markdown file (Step 1.3) | REQUIRES HUMAN REVIEW |",
        ],
        "op-full-audit.md": [
            "**Isolation compliance:**",
            "<previous year> OR <current year>",
        ],
        "op-verify-existing.md": [
            "NOT RUN",
            "A check that did not run is never reported as `UNCHANGED`.",
        ],
    }

    def test_present(self):
        for name, strings in self.PRESENT.items():
            text = _read(name)
            for s in strings:
                with self.subTest(doc=name, string=s):
                    self.assertIn(s, text)


class TestLinksResolve(unittest.TestCase):
    """Every (#anchor), (file.md) and (file.md#anchor) link points somewhere."""

    LINK = re.compile(r"\]\(([^)\s]+)\)")

    def test_links(self):
        anchors = {name: _anchors(_read(name)) for name in DOCS}
        checked = 0
        for name in DOCS:
            for target in self.LINK.findall(_read(name)):
                if re.match(r"^[a-z]+://", target):
                    continue
                path, _, frag = target.partition("#")
                doc = path or name
                with self.subTest(doc=name, link=target):
                    self.assertIn(doc, anchors, "link to a missing file")
                    if frag:
                        self.assertIn(frag, anchors[doc], "anchor not found")
                checked += 1
        self.assertGreater(checked, 0)


if __name__ == "__main__":
    unittest.main()
