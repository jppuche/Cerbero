"""The five version markers of a release must agree.

Release checklist: SKILL.md `Version:` (canonical), README badge, the newest
numbered CHANGELOG section (an `[Unreleased]` section is not a marker),
SCANNER_VERSION in hooks/cerbero-scanner.py and TOOL_VERSION in
hooks/cerbero-mcp-snapshot.py. At 1.2.2 SKILL.md still said 1.2.0.
"""
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


def _versions():
    return {
        "SKILL.md": re.search(r"^Version: (\S+)$", _read(".claude", "skills", "cerbero", "SKILL.md"), re.M).group(1),
        "README badge": re.search(r"badge/version-([0-9.]+)-", _read("README.md")).group(1),
        "CHANGELOG": re.search(r"^## \[([0-9.]+)\]", _read("CHANGELOG.md"), re.M).group(1),
        "SCANNER_VERSION": re.search(r'^SCANNER_VERSION = "([^"]+)"', _read("hooks", "cerbero-scanner.py"), re.M).group(1),
        "snapshot TOOL_VERSION": re.search(r'^TOOL_VERSION = "([^"]+)"', _read("hooks", "cerbero-mcp-snapshot.py"), re.M).group(1),
    }


class TestVersions(unittest.TestCase):
    def test_markers_agree(self):
        versions = _versions()
        self.assertEqual(len(set(versions.values())), 1, versions)


if __name__ == "__main__":
    unittest.main()
