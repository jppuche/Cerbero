"""Cerbero hook: UserPromptSubmit — scan user input for injection patterns.

Defense pipeline: normalize-then-detect
  1. Strip zero-width chars (fix false positives from emoji ZWJ, Word soft hyphens, BOM)
  2. NFKC normalize (collapse full-width chars, ligatures, Roman numerals)
  3. Cyrillic→Latin confusables table (defeat homoglyph attacks)
  4. Flexible whitespace regex (defeat space-insertion bypasses)
  5. Token proximity detection (defeat paraphrase attacks)
  6. Comment extraction + rescan (defeat HTML/code comment smuggling)
  7. Base64 decode-and-rescan (defeat encoding bypasses)

Language coverage (M-2):
  - EN: full patterns (identity hijack, instruction override, proximity pairs)
  - ES: full patterns (identity hijack, instruction override, proximity pairs)
  - PT: proximity pairs only
  - FR: proximity pairs only
  - DE/IT/other: no coverage
  To add a language: add patterns to IDENTITY_HIJACK + INSTRUCTION_OVERRIDE + SUSPICIOUS_PAIRS
"""
import sys
import json
import re
import unicodedata
import base64

# ---------------------------------------------------------------------------
# Normalization tables
# ---------------------------------------------------------------------------

# Zero-width / invisible characters — stripped before pattern matching (NOT blocked)
# Includes classic ZW + Variation Selectors + Sneaky Bits for normalization.
ZERO_WIDTH_CHARS = re.compile(
    r"[\u200b\u200c\u200d\ufeff\u00ad\u2060\u180e"
    r"\uFE00-\uFE0F"               # Variation Selectors 1-16
    r"\U000E0100-\U000E01EF"       # Variation Selectors 17-256
    r"\u2062\u2064]"               # Sneaky Bits (invisible times/plus)
)
ZW_WARN_THRESHOLD = 5

# Cyrillic→Latin confusables (visually identical characters)
CONFUSABLES = str.maketrans({
    # Cyrillic lowercase
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u04bb": "h",
    "\u0456": "i", "\u0458": "j", "\u043a": "k", "\u043c": "m",
    "\u043d": "n", "\u0442": "t", "\u0432": "v", "\u0437": "z",
    # Cyrillic uppercase
    "\u0410": "A", "\u0415": "E", "\u041e": "O", "\u0420": "P",
    "\u0421": "C", "\u0423": "Y", "\u0425": "X", "\u0406": "I",
    "\u041a": "K", "\u041c": "M", "\u041d": "N", "\u0422": "T",
    "\u0412": "V",
    # Greek lowercase (M-SEC-002)
    "\u03B1": "a", "\u03BF": "o", "\u03B5": "e", "\u03B9": "i",
    "\u03C1": "p",
    # Greek uppercase (M-SEC-002)
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0397": "H",
    "\u0399": "I", "\u039A": "K", "\u039C": "M", "\u039D": "N",
    "\u039F": "O", "\u03A1": "P", "\u03A4": "T", "\u03A5": "Y",
    "\u03A7": "X",
})

# ---------------------------------------------------------------------------
# Injection patterns — organized by category, all use \s+ for flexibility
# ---------------------------------------------------------------------------

IDENTITY_HIJACK = [
    r"you\s+are\s+now\b",
    r"pretend\s+you\s+are",
    r"act\s+as\s+if",
    r"from\s+now\s+on\s+you",
    r"roleplay\s+as",
    r"simulate\s+being",
    r"assume\s+the\s+role",
    r"switch\s+to\s.{0,20}\smode",
    # Spanish
    r"ahora\s+eres",
    r"actua\s+como\s+si",
    r"a\s+partir\s+de\s+ahora",
]

INSTRUCTION_OVERRIDE = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"override\s+system\s+prompt",
    r"forget\s+your\s+rules",
    r"new\s+system\s+prompt",
    r"disregard\s+(the\s+|all\s+)?(above|instructions)",
    r"ignore\s+(the\s+)?above",
    r"bypass\s+safety",
    r"ignore\s+all\s+constraints",
    # Spanish
    r"ignora\s+(las\s+)?instrucciones",
    r"olvida\s+tus\s+reglas",
    r"ignora\s+todo\s+lo\s+anterior",
]

SECRECY_PATTERNS = [
    r"do\s+not\s+tell\s+the\s+user",
    r"do\s+not\s+report",
    r"do\s+not\s+share",
    r"hide\s+this\s+from",
    r"don'?t\s+mention",
    r"keep\s+this\s+secret",
    r"do\s+not\s+reveal",
    r"never\s+disclose",
]

FORMAT_INJECTION = [
    r"<system>",
    r"\[inst\]",
    r"begin\s+system\s+message",
    r"</?(system|instruction|prompt)\s*/?>",
    r"\[system\]",
    r"<<sys>>",
    r"human:\s*\n\s*assistant:",
]

INJECTION_PATTERNS = (
    IDENTITY_HIJACK + INSTRUCTION_OVERRIDE
    + SECRECY_PATTERNS + FORMAT_INJECTION
)

# Category lookup for better error messages
_PATTERN_CATEGORY = {}
for _p in IDENTITY_HIJACK:
    _PATTERN_CATEGORY[_p] = "identity hijack"
for _p in INSTRUCTION_OVERRIDE:
    _PATTERN_CATEGORY[_p] = "instruction override"
for _p in SECRECY_PATTERNS:
    _PATTERN_CATEGORY[_p] = "secrecy/exfiltration"
for _p in FORMAT_INJECTION:
    _PATTERN_CATEGORY[_p] = "format injection"

# ---------------------------------------------------------------------------
# Token proximity detection — catches paraphrases without exact phrases
# ---------------------------------------------------------------------------

PROXIMITY_WINDOW = 7

# H-SEC-001: prefix matching for morphological variants (forgetting, overriding, etc.)
CRITICAL_PREFIXES = ("forget", "ignor", "bypass", "overrid", "discard", "disregard", "skip")

SUSPICIOUS_PAIRS = [
    (
        {"ignore", "disregard", "forget", "discard", "override",
         "reset", "revoke", "bypass", "skip", "remove",
         # FR/PT
         "ignorez", "ignorer", "oubliez", "esqueca", "descarte"},
        {"instructions", "rules", "guidelines", "prompt", "constraints",
         "configuration", "restrictions", "safety", "filters",
         # ES/FR/PT
         "instrucciones", "reglas", "instrucoes", "regras", "regles"},
    ),
    (
        {"pretend", "roleplay", "simulate", "become", "transform"},
        {"unrestricted", "unfiltered", "unlimited", "uncensored", "jailbreak"},
    ),
]

# ---------------------------------------------------------------------------
# Encoding / obfuscation detection
# ---------------------------------------------------------------------------

BASE64_PATTERN = re.compile(r"(?<!\w)[A-Za-z0-9+/]{20,}={0,2}(?!\w)")
BASE64_MAX_DECODE_DEPTH = 3

# ---------------------------------------------------------------------------
# Unicode threat detection
# ---------------------------------------------------------------------------

# Tag characters (U+E0000-U+E007F) — used for emoji tag sequences but exploited
# for smuggling with 100% ASR. 3+ consecutive = suspicious.
# Full block includes U+E0001 (LANGUAGE TAG) used in attacks (Cisco AI Defense).
TAG_SMUGGLING_PATTERN = re.compile(r"[\U000E0000-\U000E007F]{3,}")

# Bidi override characters — can make text render in misleading order
BIDI_OVERRIDE_PATTERN = re.compile(
    r"[\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069]"
)

# Variation Selectors — VS1-16 (U+FE00-FE0F) + VS17-256 (U+E0100-E01EF)
# Used by Glassworm campaign (Mar 2026, 400+ repos) for binary encoding.
# 1 VS after a base char is legitimate (emoji presentation). 2+ consecutive = suspicious.
VARIATION_SELECTOR_PATTERN = re.compile(
    r"[\uFE00-\uFE0F\U000E0100-\U000E01EF]{2,}"
)

# Sneaky Bits — U+2062 (invisible times) / U+2064 (invisible plus)
# Binary encoding technique (Rehberger, Mar 2025). 3+ consecutive = suspicious.
SNEAKY_BITS_PATTERN = re.compile(r"[\u2062\u2064]{3,}")

# ---------------------------------------------------------------------------
# Comment extraction — scan for injection hidden in comments
# ---------------------------------------------------------------------------

# Known limitation (L-SEC-001): Non-greedy match means nested comments like
# <!-- <!-- injection --> --> extract up to the first -->. The inner injection
# text IS captured (with extra <!-- prefix as noise), so injection patterns
# still match against the extracted content. Accepted edge case.
COMMENT_PATTERN = re.compile(
    r"<!--.*?-->|/\*.*?\*/",
    re.DOTALL,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize(prompt):
    """Strip ZW chars, NFKC normalize, apply confusables table.

    Returns (normalized_text, zero_width_count).
    """
    zw_count = len(ZERO_WIDTH_CHARS.findall(prompt))
    cleaned = ZERO_WIDTH_CHARS.sub("", prompt)
    nfkc = unicodedata.normalize("NFKC", cleaned)
    deconfused = nfkc.translate(CONFUSABLES)
    return deconfused, zw_count


def _extract_comment_content(text):
    """Extract text hidden inside HTML/code comments, lowercased."""
    matches = COMMENT_PATTERN.findall(text)
    if not matches:
        return ""
    stripped = []
    for m in matches:
        m = re.sub(r"^<!--|-->$|^/\*|\*/$", "", m).strip()
        if m:
            stripped.append(m)
    return " ".join(stripped).lower()


def _check_patterns(text):
    """Check INJECTION_PATTERNS against text. Returns (pattern, category) or None."""
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, text):
            category = _PATTERN_CATEGORY.get(pattern, "injection")
            return pattern, category
    return None


def _check_proximity(words):
    """Sliding window check for suspicious word pairs.

    Matches exact words in set_a/set_b, plus morphological variants via
    CRITICAL_PREFIXES (e.g., 'forgetting' matches prefix 'forget').
    """
    for i in range(len(words)):
        window = words[i:i + PROXIMITY_WINDOW]
        window_set = set(window)
        for set_a, set_b in SUSPICIOUS_PAIRS:
            # Exact matches
            matched_a = window_set & set_a
            matched_b = window_set & set_b
            # Prefix matches for set_a (H-SEC-001)
            if not matched_a:
                for w in window:
                    if any(w.startswith(p) for p in CRITICAL_PREFIXES):
                        matched_a = {w}
                        break
            if matched_a and matched_b:
                return matched_a.pop(), matched_b.pop()
    return None


def _decode_and_rescan_base64(text, depth=0):
    """Try to decode base64 matches and scan decoded content for injection.

    Returns (decoded_text, pattern, category) if injection found, else None.
    """
    if depth >= BASE64_MAX_DECODE_DEPTH:
        return None

    for match in BASE64_PATTERN.finditer(text):
        candidate = match.group()
        try:
            decoded = base64.b64decode(candidate).decode("utf-8", errors="ignore")
        except Exception:
            continue

        if not decoded or len(decoded) < 5:
            continue

        lower_decoded = decoded.lower()
        result = _check_patterns(lower_decoded)
        if result:
            return decoded, result[0], result[1]

        # Recursive: check for nested base64
        nested = _decode_and_rescan_base64(lower_decoded, depth + 1)
        if nested:
            return nested

    return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        print("Cerbero: could not parse hook input — failing open", file=sys.stderr)
        sys.exit(0)

    prompt = data.get("prompt", "")
    if not prompt:
        sys.exit(0)

    # --- Step 1: Normalize ---
    normalized, zw_count = _normalize(prompt)
    lower = normalized.lower()

    # --- Step 2: Injection patterns on normalized text (BLOCK) ---
    result = _check_patterns(lower)
    if result:
        pattern, category = result
        print(
            f"Cerbero: blocked prompt — {category} pattern detected: '{pattern}'",
            file=sys.stderr,
        )
        sys.exit(2)

    # --- Step 3: Injection patterns inside comments (BLOCK) ---
    comment_text = _extract_comment_content(normalized)
    if comment_text:
        result = _check_patterns(comment_text)
        if result:
            pattern, category = result
            print(
                f"Cerbero: blocked prompt — {category} hidden in comment: '{pattern}'",
                file=sys.stderr,
            )
            sys.exit(2)

    # --- Step 4: Token proximity detection (BLOCK) ---
    words = re.findall(r"\b\w+\b", lower)
    prox = _check_proximity(words)
    if prox:
        print(
            f"Cerbero: blocked prompt — suspicious word proximity: "
            f"'{prox[0]}' near '{prox[1]}'",
            file=sys.stderr,
        )
        sys.exit(2)

    # --- Step 5: Tag character smuggling (BLOCK) ---
    if TAG_SMUGGLING_PATTERN.search(prompt):
        print(
            "Cerbero: blocked prompt — tag character sequence detected "
            "(possible smuggling)",
            file=sys.stderr,
        )
        sys.exit(2)

    # --- Step 5b: Variation Selector encoding (BLOCK) ---
    if VARIATION_SELECTOR_PATTERN.search(prompt):
        print(
            "Cerbero: blocked prompt — variation selector sequence detected "
            "(possible Glassworm-style encoding)",
            file=sys.stderr,
        )
        sys.exit(2)

    # --- Step 5c: Sneaky Bits binary encoding (BLOCK) ---
    if SNEAKY_BITS_PATTERN.search(prompt):
        print(
            "Cerbero: blocked prompt — sneaky bits sequence detected "
            "(possible binary encoding via invisible math operators)",
            file=sys.stderr,
        )
        sys.exit(2)

    # --- Step 6: Base64 decode-and-rescan (BLOCK if injection found) ---
    b64_result = _decode_and_rescan_base64(prompt)
    if b64_result:
        decoded_text, pattern, category = b64_result
        print(
            f"Cerbero: blocked prompt — {category} pattern in Base64 payload: "
            f"'{pattern}'",
            file=sys.stderr,
        )
        sys.exit(2)

    # --- Step 7: Warnings (non-blocking) ---

    if BIDI_OVERRIDE_PATTERN.search(prompt):
        print(
            "Cerbero warning: bidirectional override characters detected. "
            "Text may render differently than intended.",
            file=sys.stderr,
        )

    if zw_count > ZW_WARN_THRESHOLD:
        print(
            f"Cerbero warning: {zw_count} zero-width characters stripped "
            "from prompt. May indicate hidden content.",
            file=sys.stderr,
        )

    if BASE64_PATTERN.search(prompt) and not b64_result:
        print(
            "Cerbero warning: suspicious Base64 payload detected in prompt. "
            "Verify source before proceeding.",
            file=sys.stderr,
        )

    sys.exit(0)


if __name__ == "__main__":
    main()
