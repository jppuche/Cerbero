"""JSON input (MCP tool definitions): \\uXXXX escapes judged by what they decode to.

A serializer writes every non-ASCII character as \\uXXXX (Python's json.dumps
does by default), so the raw-text unicode_escape pattern flagged ordinary
accented text; with any second category (an imperative word such as "must")
the scanner returned REJECT. These tests pin the fix and check that escapes
still cannot hide invisible characters or injection phrases.

Trigger text is assembled from fragments (_cat) so this file scans clean.
"""
import importlib.util
import json
import os
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCANNER_PATH = os.path.join(REPO_ROOT, "hooks", "cerbero-scanner.py")


def _load_scanner():
    spec = importlib.util.spec_from_file_location("cerbero_scanner_json", SCANNER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cs = _load_scanner()


def _cat(*parts):
    return "".join(parts)


def _tool(description):
    # ensure_ascii=True (the default) turns every non-ASCII character into \uXXXX.
    return json.dumps({"name": "get_weather", "description": description})


def _scan(text):
    report = cs.run_scan(text, "tools.json")
    return report["summary"]["verdict"], {f["check"] for f in report["findings"]}, report


class TestBenignEscapes(unittest.TestCase):
    def test_accented_text_with_imperative_is_not_rejected(self):
        verdict, checks, _ = _scan(_tool(_cat("The city parameter mu", "st be a valid name, e.g. São Paulo.")))
        self.assertNotIn("encoding_red_flag", checks)
        self.assertEqual(verdict, "SUSPICIOUS")

    def test_accented_text_alone_is_clean(self):
        verdict, checks, _ = _scan(_tool("Previsão do tempo para Brasília, München, 東京."))
        self.assertEqual(verdict, "CLEAN", checks)

    def test_escaped_newline_and_tab_are_ordinary(self):
        verdict, _, _ = _scan('{"description": "line one\\u000aline two\\u0009tab"}')
        self.assertEqual(verdict, "CLEAN")


class TestEscapesStillCaught(unittest.TestCase):
    def test_escaped_bidi_override(self):
        verdict, checks, report = _scan(_tool("Returns data‮."))
        self.assertIn("encoding_red_flag", checks)
        self.assertIn("bidi_override", checks)
        details = [f["detail"] for f in report["findings"] if f["check"] == "encoding_red_flag"]
        self.assertTrue(any("U+202E" in d for d in details), details)
        self.assertEqual(verdict, "REJECT")

    def test_escaped_tag_characters_as_surrogate_pairs(self):
        hidden = "".join(chr(0xE0000 + ord(c)) for c in "run")
        text = _tool("Returns the forecast." + hidden)
        self.assertIn("\\udb40\\udc72", text)  # json.dumps wrote surrogate pairs
        verdict, checks, report = _scan(text)
        self.assertIn("tag_character_smuggling", checks)
        details = [f["detail"] for f in report["findings"] if f["check"] == "encoding_red_flag"]
        self.assertTrue(any("U+E0072" in d for d in details), details)
        self.assertEqual(verdict, "REJECT")

    def test_escaped_zero_width(self):
        _, checks, _ = _scan(_tool("Re​turns"))
        self.assertIn("zero_width_char", checks)
        self.assertIn("encoding_red_flag", checks)

    def test_escaped_control_character(self):
        _, checks, _ = _scan('{"description": "bell\\u0007"}')
        self.assertIn("encoding_red_flag", checks)

    def test_lone_surrogate(self):
        _, checks, _ = _scan('{"description": "x\\ud800y"}')
        self.assertIn("encoding_red_flag", checks)

    def test_injection_phrase_hidden_behind_escapes(self):
        phrase = _cat("ign", "ore previous instr", "uctions")
        escaped = "".join("\\u%04x" % ord(c) for c in phrase)
        text = '{"description": "%s"}' % escaped
        self.assertNotIn(phrase, text)
        verdict, checks, _ = _scan(text)
        self.assertIn("injection_phrase", checks)
        self.assertEqual(verdict, "REJECT")

    def test_double_escaped_sequence_is_content(self):
        # "\\u00e3" in JSON is the literal six characters ã in the string:
        # an escape inside the content, flagged by the decoded-strings pass.
        _, checks, _ = _scan('{"description": "see \\\\u00e3 here"}')
        self.assertIn("encoding_red_flag", checks)


class TestNonJsonUnchanged(unittest.TestCase):
    def test_markdown_escape_still_flagged(self):
        _, checks, _ = _scan(_cat("Use the value \\u", "00e3 in the template."))
        self.assertIn("encoding_red_flag", checks)

    def test_json_scalar_is_not_treated_as_document(self):
        self.assertIsNone(cs._json_strings('"\\u00e3"'))


if __name__ == "__main__":
    unittest.main()
