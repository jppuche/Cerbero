"""Cerbero: standalone external scanner for Tier 0 checks.

Runs BEFORE Claude reads potentially hostile content.
All checks use stdlib only — no external dependencies.

Usage:
    python cerbero-scanner.py --file <path>              # Scan a file
    python cerbero-scanner.py --stdin                     # Read from stdin
    python cerbero-scanner.py --file <path> --strip-only  # Pre-processor for Tier 3
"""
import sys
import json
import re
import base64
import argparse
import os
import unicodedata
from datetime import datetime, timezone

SCANNER_VERSION = "1.1.0"

# --- Suppression annotation detection (H-SEC-003) ---
# Suppression annotations in scanned content are treated as evasion attempts.
# The scanner evaluates UNTRUSTED content — self-suppression is a bypass vector.

_SUPPRESS_ANNOTATION = re.compile(
    r"(?:#|//|<!--)\s*cerbero:ignore-next-line\s*(?:-->)?\s*$"
)


def scan_suppression_annotations(text):
    """Flag suppression annotations as scanner evasion attempts."""
    findings = []
    for i, line in enumerate(text.splitlines(), 1):
        if _SUPPRESS_ANNOTATION.search(line.strip()):
            findings.append({
                "check": "suppression_attempt",
                "severity": "CRITICAL",
                "detail": "Scanner evasion: suppression annotation in scanned content",
                "line": i,
                "context": line.strip()[:80],
            })
    return findings


# --- Tier 1: Injection phrase patterns ---

INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"ignore\s+(all\s+)?prior\s+instructions",
    r"disregard\s+(all\s+)?previous",
    r"forget\s+(all\s+)?previous",
    r"override\s+(all\s+)?previous",
    r"you\s+are\s+now\s+(a|an)\s+",
    r"new\s+system\s+prompt",
    r"act\s+as\s+(a|an|my)\s+",
    r"pretend\s+you\s+are",
    r"from\s+now\s+on\s+you\s+(will|must|should|are)",
    r"<\s*system\s*>",
    r"\[INST\]",
    r"\[/INST\]",
    r"BEGIN\s+SYSTEM\s+MESSAGE",
]

# --- Tier 1: Zero-width character codepoints ---

ZERO_WIDTH_CHARS = {
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0xFEFF: "BYTE ORDER MARK / ZERO WIDTH NO-BREAK SPACE",
    0x00AD: "SOFT HYPHEN",
    0x2060: "WORD JOINER",
    0x180E: "MONGOLIAN VOWEL SEPARATOR",
}

# Tag characters (U+E0000-U+E007F) — 100% ASR for smuggling (Rehberger 2024).
# 3+ consecutive = suspicious. Full block includes U+E0001 (LANGUAGE TAG).
# Used in emoji tag sequences but exploited for instruction smuggling
# in MCP tool descriptions (confirmed: Claude, Copilot, Cursor).
TAG_CHAR_PATTERN = re.compile(r"[\U000E0000-\U000E007F]{3,}")

# Bidi override characters — make text render in misleading order during review.
BIDI_OVERRIDE_PATTERN = re.compile(
    r"[\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069]"
)

# Variation Selectors — VS1-16 (U+FE00-FE0F) + VS17-256 (U+E0100-E01EF).
# Glassworm campaign (Mar 2026, 400+ repos) used VS for binary encoding.
# 2+ consecutive = suspicious (1 VS after base char is legitimate emoji modifier).
VS_PATTERN = re.compile(r"[\uFE00-\uFE0F\U000E0100-\U000E01EF]{2,}")

# Sneaky Bits — U+2062 (invisible times) / U+2064 (invisible plus).
# Binary encoding technique (Rehberger, Mar 2025). 3+ consecutive = suspicious.
SNEAKY_BITS_PATTERN = re.compile(r"[\u2062\u2064]{3,}")

# Cyrillic/Greek→Latin confusables for normalization before injection scan.
# Synced from validate-prompt.py.
CONFUSABLES = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u04bb": "h",
    "\u0456": "i", "\u0458": "j", "\u043a": "k", "\u043c": "m",
    "\u043d": "n", "\u0442": "t", "\u0432": "v", "\u0437": "z",
    "\u0410": "A", "\u0415": "E", "\u041e": "O", "\u0420": "P",
    "\u0421": "C", "\u0423": "Y", "\u0425": "X", "\u0406": "I",
    "\u041a": "K", "\u041c": "M", "\u041d": "N", "\u0422": "T",
    "\u0412": "V",
    "\u03B1": "a", "\u03BF": "o", "\u03B5": "e", "\u03B9": "i",
    "\u03C1": "p",
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0397": "H",
    "\u0399": "I", "\u039A": "K", "\u039C": "M", "\u039D": "N",
    "\u039F": "O", "\u03A1": "P", "\u03A4": "T", "\u03A5": "Y",
    "\u03A7": "X",
})

# --- Tier 1: CSS hiding patterns ---

CSS_HIDING_PATTERNS = [
    (r"display\s*:\s*none", "display:none"),
    (r"visibility\s*:\s*hidden", "visibility:hidden"),
    (r"font-size\s*:\s*0", "font-size:0"),
]

# --- Tier 1: Encoding red flags ---

ENCODING_PATTERNS = [
    (r"\\x[0-9a-fA-F]{2}", "hex_escape"),
    (r"\\u[0-9a-fA-F]{4}", "unicode_escape"),
    (r"&#x[0-9a-fA-F]+;", "html_hex_entity"),
    (r"&#\d+;", "html_decimal_entity"),
]

# --- Tier 2: Tool schema red flags ---

IMPERATIVE_WORDS = [
    r"\balways\b", r"\bnever\b", r"\bmust\b", r"\boverride\b",
    r"\bignore\b", r"\bforget\b",
]

MODEL_REFERENCES = [
    r"system\s+prompt",
    r"previous\s+instructions",
    r"assistant\s+instructions",
]

# --- Tier 2: Data acquisition patterns ---

DATA_ACQUISITION_PATTERNS = [
    (r"curl\s+.*-o\s", "download", "curl -o download"),
    (r"curl\s+.*--output\s", "download", "curl --output download"),
    (r"wget\s+.*-O\s", "download", "wget -O download"),
    (r"wget\s+.*--output-document", "download", "wget --output-document download"),
    (r"Invoke-WebRequest\s+.*-OutFile", "download", "Invoke-WebRequest -OutFile download"),
    (r"mongodb://", "db_connection", "MongoDB connection string"),
    (r"postgres://", "db_connection", "PostgreSQL connection string"),
    (r"mysql://", "db_connection", "MySQL connection string"),
    (r"jdbc:", "db_connection", "JDBC connection string"),
    (r"SELECT\s+.*\s+FROM\s+", "sql", "SQL SELECT query"),
    (r"INSERT\s+INTO\s+", "sql", "SQL INSERT query"),
    (r"DROP\s+TABLE", "sql", "SQL DROP TABLE"),
]

# --- Scanner functions ---


def scan_injection_phrases(text):
    """Tier 1: Detect direct prompt injection phrases."""
    findings = []
    for i, line in enumerate(text.splitlines(), 1):
        for pattern in INJECTION_PATTERNS:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 25)
                end = min(len(line), match.end() + 25)
                findings.append({
                    "check": "injection_phrase",
                    "severity": "CRITICAL",
                    "detail": f"Pattern: {pattern}",
                    "line": i,
                    "context": line[start:end],
                })
    return findings


def scan_base64_payloads(text, max_depth=3):
    """Tier 1: Detect base64-encoded payloads and recursively decode."""
    findings = []
    b64_pattern = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

    for i, line in enumerate(text.splitlines(), 1):
        for match in b64_pattern.finditer(line):
            encoded = match.group()
            decoded_chain = _recursive_decode(encoded, max_depth)
            if decoded_chain is None:
                continue

            decoded_text = decoded_chain[-1]
            injection_findings = scan_injection_phrases(decoded_text)

            findings.append({
                "check": "base64_payload",
                "severity": "CRITICAL" if injection_findings else "HIGH",
                "detail": f"Encoded: {encoded[:40]}...",
                "line": i,
                "context": decoded_text[:100],
                "recursive_depth": len(decoded_chain),
                "contains_injection": bool(injection_findings),
            })
    return findings


def _recursive_decode(text, depth):
    """Attempt recursive base64 decoding up to max depth."""
    if depth <= 0:
        return None
    try:
        decoded = base64.b64decode(text).decode("utf-8", errors="strict")
    except Exception:
        return None

    if not decoded.isprintable() and not any(c in decoded for c in "\n\r\t"):
        return None

    deeper = _recursive_decode(decoded.strip(), depth - 1)
    if deeper is not None:
        return [decoded] + deeper
    return [decoded]


def scan_zero_width_chars(text):
    """Tier 1: Detect invisible zero-width Unicode characters."""
    findings = []
    for i, line in enumerate(text.splitlines(), 1):
        for pos, char in enumerate(line):
            cp = ord(char)
            if cp in ZERO_WIDTH_CHARS:
                findings.append({
                    "check": "zero_width_char",
                    "severity": "HIGH",
                    "detail": f"U+{cp:04X} ({ZERO_WIDTH_CHARS[cp]})",
                    "line": i,
                    "context": f"position {pos}",
                })
    return findings


def scan_tag_characters(text):
    """Tier 1: Detect Unicode tag character sequences (C-SEC-003).

    Tag chars (U+E0000-E007F) have 100% ASR for instruction smuggling
    (Rehberger 2024, confirmed against Claude, Copilot, Cursor).
    """
    findings = []
    for match in TAG_CHAR_PATTERN.finditer(text):
        line_num = text[:match.start()].count("\n") + 1
        length = len(match.group())
        # Attempt decode: tag chars map to ASCII (U+E0041 = 'A')
        decoded = "".join(chr(ord(c) - 0xE0000) for c in match.group()
                         if 0xE0000 <= ord(c) <= 0xE007F)
        findings.append({
            "check": "tag_character_smuggling",
            "severity": "CRITICAL",
            "detail": f"{length} tag chars" + (f", decoded: '{decoded[:80]}'" if decoded.strip() else ""),
            "line": line_num,
            "context": decoded[:80] if decoded.strip() else f"[{length} invisible chars]",
        })
    return findings


def scan_bidi_overrides(text):
    """Tier 1: Detect bidirectional override characters (C-SEC-004)."""
    findings = []
    bidi_names = {
        0x202A: "LRE", 0x202B: "RLE", 0x202C: "PDF", 0x202D: "LRO", 0x202E: "RLO",
        0x2066: "LRI", 0x2067: "RLI", 0x2068: "FSI", 0x2069: "PDI",
    }
    for i, line in enumerate(text.splitlines(), 1):
        for pos, char in enumerate(line):
            cp = ord(char)
            if cp in bidi_names:
                findings.append({
                    "check": "bidi_override",
                    "severity": "HIGH",
                    "detail": f"U+{cp:04X} ({bidi_names[cp]})",
                    "line": i,
                    "context": f"position {pos}",
                })
    return findings


def _decode_variation_selectors(text):
    """Decode Glassworm-style Variation Selector encoding.

    Algorithm: VS1-16 (U+FE00-FE0F) → byte 0x00-0x0F
               VS17-256 (U+E0100-E01EF) → byte 0x10-0xFF
    Returns decoded bytes as string, or empty string if decode fails.
    """
    raw_bytes = []
    for char in text:
        cp = ord(char)
        if 0xFE00 <= cp <= 0xFE0F:
            raw_bytes.append(cp - 0xFE00)
        elif 0xE0100 <= cp <= 0xE01EF:
            raw_bytes.append(cp - 0xE0100 + 16)
    if not raw_bytes:
        return ""
    try:
        return bytes(raw_bytes).decode("utf-8", errors="replace")
    except Exception:
        return ""


def scan_variation_selectors(text):
    """Tier 1: Detect Variation Selector clusters + Glassworm decode (C-SEC-003, S-SEC-013).

    Glassworm campaign (Mar 2026, 400+ repos): VS codepoints encode arbitrary bytes.
    """
    findings = []
    for match in VS_PATTERN.finditer(text):
        line_num = text[:match.start()].count("\n") + 1
        length = len(match.group())
        decoded = _decode_variation_selectors(match.group())
        detail = f"{length} variation selectors"
        if decoded.strip() and decoded.isprintable():
            detail += f", Glassworm decode: '{decoded[:80]}'"
            # Rescan decoded content for injection phrases
            injection_hits = scan_injection_phrases(decoded)
            if injection_hits:
                detail += " [CONTAINS INJECTION]"
        findings.append({
            "check": "variation_selector_encoding",
            "severity": "CRITICAL",
            "detail": detail,
            "line": line_num,
            "context": decoded[:80] if decoded.strip() else f"[{length} VS chars]",
            "contains_injection": bool(decoded.strip() and scan_injection_phrases(decoded)),
        })
    return findings


def scan_sneaky_bits(text):
    """Tier 1: Detect Sneaky Bits binary encoding (C-SEC-003).

    U+2062 (invisible times) / U+2064 (invisible plus) used as 0/1 bits.
    Technique demonstrated by Rehberger (Mar 2025).
    """
    findings = []
    for match in SNEAKY_BITS_PATTERN.finditer(text):
        line_num = text[:match.start()].count("\n") + 1
        length = len(match.group())
        # Attempt binary decode: U+2062=0, U+2064=1
        bits = "".join("0" if ord(c) == 0x2062 else "1" for c in match.group())
        decoded = ""
        if len(bits) >= 8:
            try:
                decoded = "".join(chr(int(bits[i:i+8], 2))
                                  for i in range(0, len(bits) - 7, 8)
                                  if int(bits[i:i+8], 2) > 0)
            except (ValueError, OverflowError):
                pass
        detail = f"{length} sneaky bits chars"
        if decoded.strip() and decoded.isprintable():
            detail += f", decoded: '{decoded[:80]}'"
        findings.append({
            "check": "sneaky_bits_encoding",
            "severity": "HIGH",
            "detail": detail,
            "line": line_num,
            "context": decoded[:80] if decoded.strip() else f"[{length} invisible chars]",
        })
    return findings


def _normalize_for_injection_scan(text):
    """Normalize text for injection phrase detection (C-SEC-005).

    Strips ZW chars, applies NFKC, translates confusables.
    Used to catch obfuscated injection phrases.
    """
    # Strip all known invisible characters
    zw_re = re.compile(
        r"[\u200b\u200c\u200d\ufeff\u00ad\u2060\u180e"
        r"\uFE00-\uFE0F\U000E0100-\U000E01EF"
        r"\u2062\u2064"
        r"\U000E0000-\U000E007F]"
    )
    cleaned = zw_re.sub("", text)
    nfkc = unicodedata.normalize("NFKC", cleaned)
    return nfkc.translate(CONFUSABLES)


def scan_html_comments(text):
    """Tier 1: Detect HTML comments containing instructions."""
    findings = []
    for match in re.finditer(r"<!--([\s\S]*?)-->", text):
        comment = match.group(1)
        start = text[:match.start()].count("\n") + 1

        injection_findings = scan_injection_phrases(comment)

        preview = comment.strip()[:100]
        findings.append({
            "check": "html_comment",
            "severity": "CRITICAL" if injection_findings else "MEDIUM",
            "detail": f"Comment: {preview}",
            "line": start,
            "context": preview,
            "contains_injection": bool(injection_findings),
        })
    return findings


def scan_css_hiding(text, file_path=""):
    """Tier 1: Detect CSS techniques for hiding content.
    M-1: Skips actual stylesheets where these patterns are expected."""
    if file_path:
        ext = os.path.splitext(file_path)[1].lower()
        if ext in (".css", ".html", ".htm", ".scss", ".sass", ".less", ".svelte", ".vue"):
            return []
    findings = []
    for i, line in enumerate(text.splitlines(), 1):
        for pattern, desc in CSS_HIDING_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "check": "css_hiding",
                    "severity": "MEDIUM",
                    "detail": desc,
                    "line": i,
                    "context": line.strip()[:50],
                })
    return findings


def scan_encoding_red_flags(text):
    """Tier 1: Detect suspicious encoding patterns."""
    findings = []
    for i, line in enumerate(text.splitlines(), 1):
        for pattern, enc_type in ENCODING_PATTERNS:
            for match in re.finditer(pattern, line):
                findings.append({
                    "check": "encoding_red_flag",
                    "severity": "MEDIUM",
                    "detail": f"{enc_type}: {match.group()}",
                    "line": i,
                    "context": line.strip()[:50],
                })
    return findings


def scan_tool_schema_red_flags(text):
    """Tier 2: Detect suspicious patterns in tool schemas/descriptions."""
    findings = []
    for i, line in enumerate(text.splitlines(), 1):
        for pattern in IMPERATIVE_WORDS:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "check": "tool_schema_imperative",
                    "severity": "MEDIUM",
                    "detail": f"Imperative word: {pattern}",
                    "line": i,
                    "context": line.strip()[:50],
                })

        for pattern in MODEL_REFERENCES:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "check": "tool_schema_model_ref",
                    "severity": "HIGH",
                    "detail": f"Model reference: {pattern}",
                    "line": i,
                    "context": line.strip()[:50],
                })

    # Check for overly long descriptions (>500 chars per field)
    for match in re.finditer(r'"description"\s*:\s*"([^"]*)"', text):
        desc = match.group(1)
        if len(desc) > 500:
            line_num = text[:match.start()].count("\n") + 1
            findings.append({
                "check": "tool_schema_long_desc",
                "severity": "MEDIUM",
                "detail": f"Description length: {len(desc)} chars (>500)",
                "line": line_num,
                "context": desc[:50] + "...",
            })

    return findings


def scan_data_acquisition(text):
    """Tier 2: Detect download commands, DB connections, and SQL."""
    findings = []
    for i, line in enumerate(text.splitlines(), 1):
        for pattern, acq_type, desc in DATA_ACQUISITION_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "check": "data_acquisition",
                    "severity": "MEDIUM",
                    "detail": desc,
                    "line": i,
                    "context": line.strip()[:50],
                    "type": acq_type,
                })
    return findings


def strip_comments_and_strings(text):
    """Pre-processor for Tier 3: remove comments and string literals.

    Preserves: function signatures, imports, tool registrations.
    Removes: //, #, /* */, string literals, docstrings.
    """
    # Remove multi-line comments /* ... */
    result = re.sub(r"/\*[\s\S]*?\*/", " ", text)

    # Remove docstrings (triple quotes)
    result = re.sub(r'"""[\s\S]*?"""', ' ""', result)
    result = re.sub(r"'''[\s\S]*?'''", " ''", result)

    # Remove single-line string literals (preserve the quotes as markers)
    result = re.sub(r'"[^"\n]*"', '""', result)
    result = re.sub(r"'[^'\n]*'", "''", result)

    # Remove single-line comments (// and #) but preserve shebangs
    lines = result.splitlines()
    cleaned = []
    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith("#!"):
            cleaned.append(line)
            continue
        # Remove // comments
        line = re.sub(r"//.*$", "", line)
        # Remove # comments (but not in shebangs or imports)
        if not stripped.startswith("import") and not stripped.startswith("from"):
            line = re.sub(r"#.*$", "", line)
        cleaned.append(line)

    return "\n".join(cleaned)


# --- Main logic ---


def compute_verdict(findings):
    """Determine overall verdict from findings."""
    if not findings:
        return "CLEAN"

    has_injection = any(f["check"] == "injection_phrase" for f in findings)
    has_base64_injection = any(
        f["check"] == "base64_payload" and f.get("contains_injection")
        for f in findings
    )
    has_html_injection = any(
        f["check"] == "html_comment" and f.get("contains_injection")
        for f in findings
    )
    has_tag_smuggling = any(f["check"] == "tag_character_smuggling" for f in findings)
    has_vs_injection = any(
        f["check"] == "variation_selector_encoding" and f.get("contains_injection")
        for f in findings
    )

    if (has_injection or has_base64_injection or has_html_injection
            or has_tag_smuggling or has_vs_injection):
        return "REJECT"

    # Count distinct check categories
    categories = set(f["check"] for f in findings)
    if len(categories) >= 2:
        return "REJECT"

    return "SUSPICIOUS"


def run_scan(text, target_name):
    """Run all scanner checks and produce JSON report."""
    all_findings = []
    all_findings.extend(scan_suppression_annotations(text))
    all_findings.extend(scan_injection_phrases(text))
    all_findings.extend(scan_base64_payloads(text))
    all_findings.extend(scan_zero_width_chars(text))
    # Unicode attack detection (C-SEC-003/004/005, S-SEC-013)
    all_findings.extend(scan_tag_characters(text))
    all_findings.extend(scan_bidi_overrides(text))
    all_findings.extend(scan_variation_selectors(text))
    all_findings.extend(scan_sneaky_bits(text))
    all_findings.extend(scan_html_comments(text))
    all_findings.extend(scan_css_hiding(text))
    all_findings.extend(scan_encoding_red_flags(text))
    all_findings.extend(scan_tool_schema_red_flags(text))
    all_findings.extend(scan_data_acquisition(text))

    # C-SEC-005: Also scan NORMALIZED text for obfuscated injection phrases
    normalized = _normalize_for_injection_scan(text)
    if normalized != text:
        norm_injections = scan_injection_phrases(normalized)
        # Only add if they weren't already caught in raw scan
        raw_injection_lines = {f["line"] for f in all_findings if f["check"] == "injection_phrase"}
        for finding in norm_injections:
            if finding["line"] not in raw_injection_lines:
                finding["detail"] += " (detected after Unicode normalization)"
                all_findings.append(finding)

    critical = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in all_findings if f["severity"] == "HIGH")
    medium = sum(1 for f in all_findings if f["severity"] == "MEDIUM")

    report = {
        "scanner_version": SCANNER_VERSION,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": target_name,
        "findings": all_findings,
        "summary": {
            "total_findings": len(all_findings),
            "critical": critical,
            "high": high,
            "medium": medium,
            "verdict": compute_verdict(all_findings),
        },
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="Cerbero external scanner (Tier 0)")
    parser.add_argument("--file", help="Path to file to scan")
    parser.add_argument("--stdin", action="store_true", help="Read from stdin")
    parser.add_argument(
        "--strip-only",
        action="store_true",
        help="Pre-processor mode: strip comments and strings, output to stdout",
    )
    args = parser.parse_args()

    if not args.file and not args.stdin:
        parser.print_help()
        sys.exit(1)

    if args.file:
        if not os.path.isfile(args.file):
            print(json.dumps({"error": f"File not found: {args.file}"}))
            sys.exit(1)
        with open(args.file, "r", encoding="utf-8") as f:
            text = f.read()
        target_name = args.file
    else:
        text = sys.stdin.read()
        target_name = "stdin"

    if args.strip_only:
        print(strip_comments_and_strings(text))
        sys.exit(0)

    report = run_scan(text, target_name)
    print(json.dumps(report, indent=2))
    sys.exit(0)


if __name__ == "__main__":
    main()
