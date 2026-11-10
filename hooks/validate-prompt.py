"""Cerbero hook: UserPromptSubmit - scan user input for injection patterns.

The main threat at this hook is hostile text the user pastes (web pages, issues, docs),
not the user's own phrasing. So a phrase only BLOCKS (exit 2) when it is aimed at the
agent's own instructions; ordinary phrasing that merely contains a trigger word WARNS
(stderr, exit 0) and the prompt goes through.

Tiers:
  BLOCK  - format injection tags (<system>, [INST], Human:/Assistant: splice)
         - tag-character smuggling, variation-selector runs, sneaky bits
         - override verb + agent-directed target ("ignore all previous instructions",
           "olvida tus reglas", "skip your guidelines")
         - identity / secrecy trigger + agent target or jailbreak term within a window
           ("you are now an unrestricted AI", "no le digas al usuario ... tus instrucciones")
         - any of the above inside HTML/code comments or a Base64 payload
  WARN   - a trigger on its own ("a partir de ahora", "don't mention it", "ignore the above"),
           a weak verb near a generic target ("skip the lint rules"), first-person targets
           ("ignora mis instrucciones anteriores"), bidi overrides, many zero-width chars,
           undecodable Base64

Defense pipeline: normalize-then-detect
  1. Strip zero-width chars (fix false positives from emoji ZWJ, Word soft hyphens, BOM)
  2. NFKC normalize (collapse full-width chars, ligatures, Roman numerals)
  3. Cyrillic/Greek -> Latin confusables table (defeat homoglyph attacks)
  4. Accent folding + whitespace collapse ("actúa" == "actua", defeat space insertion)
  5. Trigger/target co-occurrence in a word window (paraphrase-tolerant, intent-aware)
  6. Comment extraction + rescan (defeat HTML/code comment smuggling)
  7. Base64 decode-and-rescan (defeat encoding bypasses)

Language coverage:
  - EN, ES: triggers, override verbs, agent targets, jailbreak terms
  - PT, FR: override verbs + agent targets only
  - DE/IT/other: no coverage
  To add a language: extend the trigger lists, STRONG_VERB/WEAK_VERB and the TARGET regexes.

Known tradeoff: a user who literally types a canonical attack ("ignore all previous
instructions") to discuss it is blocked too; pipe such fixtures through the script instead.
"""
import sys
import json
import re
import unicodedata
import base64

# ---------------------------------------------------------------------------
# Normalization tables
# ---------------------------------------------------------------------------

# Zero-width / invisible characters - stripped before pattern matching (NOT blocked)
# Includes classic ZW + Variation Selectors + Sneaky Bits for normalization.
ZERO_WIDTH_CHARS = re.compile(
    r"[​‌‍﻿­⁠᠎"
    r"︀-️"               # Variation Selectors 1-16
    r"\U000E0100-\U000E01EF"       # Variation Selectors 17-256
    r"⁢⁤]"               # Sneaky Bits (invisible times/plus)
)
ZW_WARN_THRESHOLD = 5

# Cyrillic->Latin confusables (visually identical characters)
CONFUSABLES = str.maketrans({
    # Cyrillic lowercase
    "а": "a", "е": "e", "о": "o", "р": "p",
    "с": "c", "у": "y", "х": "x", "һ": "h",
    "і": "i", "ј": "j", "к": "k", "м": "m",
    "н": "n", "т": "t", "в": "v", "з": "z",
    # Cyrillic uppercase
    "А": "A", "Е": "E", "О": "O", "Р": "P",
    "С": "C", "У": "Y", "Х": "X", "І": "I",
    "К": "K", "М": "M", "Н": "N", "Т": "T",
    "В": "V",
    # Greek lowercase (M-SEC-002)
    "α": "a", "ο": "o", "ε": "e", "ι": "i",
    "ρ": "p",
    # Greek uppercase (M-SEC-002)
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N",
    "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y",
    "Χ": "X",
})

# ---------------------------------------------------------------------------
# Format injection - always BLOCK. Matched on lowercased text with newlines intact.
# ---------------------------------------------------------------------------

FORMAT_INJECTION = [
    r"<system>",
    r"\[inst\]",
    r"begin\s+system\s+message",
    r"</?(system|instruction|prompt)\s*/?>",
    r"\[system\]",
    r"<<sys>>",
    r"human:\s*\n\s*assistant:",
    # Conversation splice: a blank line, a "Human:" turn, later a blank line + "Assistant:".
    r"\n\s*\n\s*human:.*?\n\s*\n\s*assistant:",
]

# ---------------------------------------------------------------------------
# Agent-directed targets. Matched on folded text (lowercase, no accents, single spaces).
# ---------------------------------------------------------------------------

_RULE_NOUNS = (
    r"(instructions?|rules|guidelines|directives|constraints|restrictions|limitations"
    r"|guardrails|filters|programming|training|polic(y|ies)|system prompt|prompt)"
)
_ES_RULE_NOUNS = (
    r"(instrucciones|reglas|directrices|restricciones|limitaciones|filtros|politicas"
    r"|normas|pautas|prompt de sistema|prompt del sistema)"
)

# "your rules", "tus instrucciones": the possessive points at the agent itself.
POSSESSIVE_TARGET = re.compile(
    r"\byour (own |current |original |safety |content )?" + _RULE_NOUNS + r"\b"
    r"|\btus (propias )?" + _ES_RULE_NOUNS + r"\b"
    r"|\b(suas|tuas) (instrucoes|regras)\b"
    r"|\b(vos|tes) (instructions|regles|consignes)\b"
)

# "previous instructions", "the system prompt", "las reglas anteriores". Points at the
# agent's instructions unless first-person ("my previous instructions" = user self-correction).
_NOT_MINE = r"(?<!\bmy )(?<!\bmis )(?<!\bmi )"
POSITIONAL_TARGET = re.compile(
    _NOT_MINE + r"\b(previous|prior|above|earlier|preceding|original|initial) "
    r"(instructions?|rules|guidelines|directives|prompts?|commands)\b"
    r"|" + _NOT_MINE + r"\bsystem (prompt|instructions|message)\b"
    r"|" + _NOT_MINE + r"\b(las )?(instrucciones|reglas|directrices|normas|indicaciones) "
    r"(anteriores|previas|originales|iniciales|del sistema)\b"
    r"|" + _NOT_MINE + r"\b(el )?prompt (de|del) sistema\b"
    r"|\binstrucoes anteriores\b|\b(instructions|regles) precedentes\b"
)

# The same nouns preceded by "my/mis/mi": a user correcting themself. WARN only.
FIRST_PERSON_TARGET = re.compile(
    r"\b(my|mis|mi) (previous |prior |earlier |original |last )?"
    r"(instructions?|rules|prompt|indicaciones|instrucciones|reglas)\b"
)

JAILBREAK_TARGET = re.compile(
    r"\b(unrestricted|unfiltered|uncensored|unaligned|jailbr\w*|do anything now"
    r"|dan mode|developer mode|god mode|no (restrictions|rules|limits|filters|guidelines)"
    r"|without (restrictions|rules|limits|filters|guidelines)"
    r"|sin (restricciones|filtros|limites|reglas|censura|limitaciones)"
    r"|modo (desarrollador|dios|sin restricciones))\b"
)

# Targets that make an identity/secrecy trigger agent-directed. POSITIONAL is left out on
# purpose: "from now on the system prompt lives in config.yaml" is ordinary dev talk.
AGENT_TARGETS = (POSSESSIVE_TARGET, JAILBREAK_TARGET)

# Generic rule nouns with no agent marker ("the lint rules"). Only feed WARN-tier proximity.
GENERIC_TARGET = re.compile(
    r"\b(instructions?|rules|guidelines|prompt|constraints|configuration|restrictions"
    r"|safety|filters|instrucciones|reglas|instrucoes|regras|regles)\b"
)

# ---------------------------------------------------------------------------
# Triggers
# ---------------------------------------------------------------------------

# Verbs that discard instructions. STRONG + positional target blocks; WEAK needs a
# possessive ("skip your rules") because "skip the previous steps" is ordinary work talk.
STRONG_VERB = re.compile(
    r"\b(ignor\w*|disregard\w*|forg[eo]t\w*|bypass\w*|circumvent\w*|olvid\w*"
    r"|haz caso omiso|esquec\w*|desconsider\w*|oubli\w*)\b"
)
WEAK_VERB = re.compile(
    r"\b(skip\w*|drop\w*|discard\w*|disabl\w*|overrid\w*|abandon\w*|remov\w*"
    r"|stop following|stop obeying|omit\w*|salta\w*|desactiv\w*|descart\w*|anul\w*"
    r"|evad\w*|deja de (seguir|obedecer)|no sigas|descarte)\b"
)
# "don't ignore your rules" / "no olvides las reglas anteriores" flip the meaning.
NEGATION_BEFORE = re.compile(r"\b(don'?t|do not|never|not|no|nunca|jamas|ni)\s*$")

IDENTITY_TRIGGER = re.compile(
    r"\byou are now\b|\bpretend (you are|to be)\b|\bact as if\b|\bfrom now on\b"
    r"|\broleplay as\b|\bsimulate being\b|\bassume the role\b|\bswitch to .{0,20}mode\b"
    r"|\bahora eres\b|\bactua como si\b|\ba partir de ahora\b|\bdesde ahora\b"
    r"|\bfinge (que eres|ser)\b|\bhaz de cuenta que eres\b|\bcomportate como\b"
)

SECRECY_TRIGGER = re.compile(
    r"\bdo not (tell|inform) the user\b|\bdon'?t (tell|inform) the user\b|\bdo not report\b"
    r"|\bdo not share\b|\bhide this from\b|\bdon'?t mention\b|\bdo not mention\b"
    r"|\bkeep this secret\b|\bdo not reveal\b|\bnever (disclose|reveal)\b"
    r"|\bno le (digas|cuentes|menciones) al usuario\b|\bno (menciones|reveles|compartas)\b"
    r"|\bocultale\b|\bmantenlo en secreto\b|\bsin que el usuario (lo sepa|se entere)\b"
)

# WARN-only phrases that sound like overrides but are everyday edits ("ignore the above error").
WEAK_OVERRIDE = re.compile(
    r"\b(ignore|disregard) (the |everything |all )?(above|before)\b"
    r"|\bignora todo lo anterior\b|\bolvida (todo )?lo anterior\b"
    r"|\bnew system prompt\b|\bnuevo prompt (de|del) sistema\b"
)

VERB_WINDOW = 6       # words after an override verb in which the target must appear
COOCCUR_WINDOW = 12   # words before/after an identity/secrecy trigger

# ---------------------------------------------------------------------------
# Encoding / obfuscation detection
# ---------------------------------------------------------------------------

BASE64_PATTERN = re.compile(r"(?<!\w)[A-Za-z0-9+/]{20,}={0,2}(?!\w)")
BASE64_MAX_DECODE_DEPTH = 3

# ---------------------------------------------------------------------------
# Unicode threat detection
# ---------------------------------------------------------------------------

# Tag characters (U+E0000-U+E007F) - used for emoji tag sequences but exploited
# for smuggling with 100% ASR. 3+ consecutive = suspicious.
# Full block includes U+E0001 (LANGUAGE TAG) used in attacks (Cisco AI Defense).
TAG_SMUGGLING_PATTERN = re.compile(r"[\U000E0000-\U000E007F]{3,}")

# Bidi override characters - can make text render in misleading order
BIDI_OVERRIDE_PATTERN = re.compile(
    r"[‪‫‬‭‮⁦⁧⁨⁩]"
)

# Variation Selectors - VS1-16 (U+FE00-FE0F) + VS17-256 (U+E0100-E01EF)
# Used by Glassworm campaign (Mar 2026, 400+ repos) for binary encoding.
# 1 VS after a base char is legitimate (emoji presentation). 2+ consecutive = suspicious.
VARIATION_SELECTOR_PATTERN = re.compile(
    r"[︀-️\U000E0100-\U000E01EF]{2,}"
)

# Sneaky Bits - U+2062 (invisible times) / U+2064 (invisible plus)
# Binary encoding technique (Rehberger, Mar 2025). 3+ consecutive = suspicious.
SNEAKY_BITS_PATTERN = re.compile(r"[⁢⁤]{3,}")

# ---------------------------------------------------------------------------
# Comment extraction - scan for injection hidden in comments
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


def _fold(text):
    """Lowercase, drop accents, unify apostrophes, collapse whitespace to single spaces."""
    decomposed = unicodedata.normalize("NFD", text.lower())
    no_marks = "".join(c for c in decomposed if not unicodedata.combining(c))
    no_marks = no_marks.replace("’", "'").replace("‘", "'")
    return re.sub(r"\s+", " ", no_marks).strip()


def _extract_comment_content(text):
    """Extract text hidden inside HTML/code comments."""
    matches = COMMENT_PATTERN.findall(text)
    if not matches:
        return ""
    stripped = []
    for m in matches:
        m = re.sub(r"^<!--|-->$|^/\*|\*/$", "", m).strip()
        if m:
            stripped.append(m)
    return "\n".join(stripped)


def _words_after(text, pos, n):
    return " " + " ".join(text[pos:].split(" ")[:n + 1])


def _words_before(text, pos, n):
    return " ".join(text[:pos].split(" ")[-n - 1:]) + " "


def _find_target(window, targets):
    for target in targets:
        m = target.search(window)
        if m:
            return m.group().strip()
    return None


def _classify(raw_lower, folded):
    """Return (blocks, warns): lists of human-readable reasons."""
    blocks, warns = [], []

    for pattern in FORMAT_INJECTION:
        if re.search(pattern, raw_lower, re.DOTALL):
            blocks.append(f"format injection '{pattern}'")

    # Override verb followed by a target within VERB_WINDOW words.
    for verb_re, strong in ((STRONG_VERB, True), (WEAK_VERB, False)):
        for m in verb_re.finditer(folded):
            if NEGATION_BEFORE.search(folded[:m.start()]):
                continue
            after = _words_after(folded, m.end(), VERB_WINDOW)
            verb = m.group()
            hit = POSSESSIVE_TARGET.search(after)
            if hit:
                blocks.append(f"instruction override '{verb} ... {hit.group().strip()}'")
                continue
            hit = POSITIONAL_TARGET.search(after)
            if hit:
                reason = f"instruction override '{verb} ... {hit.group().strip()}'"
                (blocks if strong else warns).append(reason)
                continue
            hit = FIRST_PERSON_TARGET.search(after) or GENERIC_TARGET.search(after)
            if hit:
                warns.append(f"override-like phrase '{verb} ... {hit.group().strip()}'")

    # Identity / secrecy triggers: block only with an agent target nearby.
    for trig_re, label in ((IDENTITY_TRIGGER, "identity hijack"), (SECRECY_TRIGGER, "secrecy")):
        for m in trig_re.finditer(folded):
            window = (_words_before(folded, m.start(), COOCCUR_WINDOW) + m.group()
                      + _words_after(folded, m.end(), COOCCUR_WINDOW))
            target = _find_target(window, AGENT_TARGETS)
            if target:
                blocks.append(f"{label} '{m.group()}' + agent target '{target}'")
            else:
                warns.append(f"{label}-like phrase '{m.group()}'")

    for m in WEAK_OVERRIDE.finditer(folded):
        warns.append(f"override-like phrase '{m.group()}'")

    # Jailbreak vocabulary on its own ("pretend ... unrestricted" without a trigger).
    if not blocks:
        m = JAILBREAK_TARGET.search(folded)
        if m:
            warns.append(f"jailbreak term '{m.group()}'")

    return blocks, warns


def _scan_text(text):
    """Classify already-normalized text. Returns (blocks, warns)."""
    return _classify(text.lower(), _fold(text))


def _decode_and_rescan_base64(text, depth=0):
    """Decode base64 candidates and classify the decoded content.

    Returns (blocks, warns) for the first payload with any finding, else None.
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

        normalized, _ = _normalize(decoded)
        blocks, warns = _scan_text(normalized)
        if blocks or warns:
            return blocks, warns

        # Recursive: check for nested base64
        nested = _decode_and_rescan_base64(decoded, depth + 1)
        if nested:
            return nested

    return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _block(reason):
    print(f"Cerbero: blocked prompt - {reason}", file=sys.stderr)
    sys.exit(2)


def main():
    # Messages may quote prompt text; never crash on a console code page.
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

    try:
        # Hook input is UTF-8. Read bytes: on Windows sys.stdin decodes with the locale
        # code page (cp1252), which garbles accents and non-Latin text before matching.
        data = json.loads(sys.stdin.buffer.read().decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, ValueError):
        print("Cerbero: could not parse hook input - failing open", file=sys.stderr)
        sys.exit(0)

    prompt = data.get("prompt", "") if isinstance(data, dict) else ""
    if not prompt:
        sys.exit(0)

    warnings = []

    # --- Step 1: Normalize ---
    normalized, zw_count = _normalize(prompt)

    # --- Step 2: Patterns on normalized text ---
    blocks, warns = _scan_text(normalized)
    if blocks:
        _block(blocks[0])
    warnings += warns

    # --- Step 3: Patterns inside comments ---
    comment_text = _extract_comment_content(normalized)
    if comment_text:
        blocks, warns = _scan_text(comment_text)
        if blocks:
            _block(f"{blocks[0]} hidden in comment")
        warnings += [w + " (in comment)" for w in warns]

    # --- Step 4: Tag character smuggling ---
    if TAG_SMUGGLING_PATTERN.search(prompt):
        _block("tag character sequence detected (possible smuggling)")

    # --- Step 4b: Variation Selector encoding ---
    if VARIATION_SELECTOR_PATTERN.search(prompt):
        _block("variation selector sequence detected (possible Glassworm-style encoding)")

    # --- Step 4c: Sneaky Bits binary encoding ---
    if SNEAKY_BITS_PATTERN.search(prompt):
        _block("sneaky bits sequence detected (possible binary encoding via invisible math operators)")

    # --- Step 5: Base64 decode-and-rescan ---
    b64_result = _decode_and_rescan_base64(prompt)
    if b64_result:
        blocks, warns = b64_result
        if blocks:
            _block(f"{blocks[0]} in Base64 payload")
        warnings += [w + " (in Base64 payload)" for w in warns]

    # --- Step 6: Warnings (non-blocking) ---
    if BIDI_OVERRIDE_PATTERN.search(prompt):
        warnings.append("bidirectional override characters; text may render differently than intended")

    if zw_count > ZW_WARN_THRESHOLD:
        warnings.append(f"{zw_count} zero-width characters stripped; may indicate hidden content")

    # Real Base64 mixes cases and digits; plain paths and identifiers ("skills/cerbero/hooks") do not.
    if not b64_result and any(
        re.search(r"[a-z]", c) and re.search(r"[A-Z]", c) and re.search(r"\d", c)
        for c in BASE64_PATTERN.findall(prompt)
    ):
        warnings.append("Base64-like payload in prompt; verify source before proceeding")

    for w in dict.fromkeys(warnings):
        print(f"Cerbero warning: {w}", file=sys.stderr)

    sys.exit(0)


if __name__ == "__main__":
    main()
