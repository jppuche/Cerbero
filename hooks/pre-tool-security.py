"""Cerbero hook: PreToolUse - block dangerous shell commands.

Normalization: shlex.split() resolves quotes and backslash escapes before matching.
Multi-match: scans all patterns, returns highest severity (deny > warn).
Scope: catches accidental dangerous commands and basic static evasion. Dynamic
evasion (variable expansion, aliases, IFS tricks) is out of scope - use Claude
Code's sandbox mode for OS-level enforcement.

Fail-open: parse errors → allow (consistent with all Ignite hooks).
"""
import sys
import json
import re
import shlex

# Shell names are anchored (\b on both sides) so "| sha256sum", "| shasum" or "| shellcheck"
# do not read as "| sh". A shell after a pipe may sit behind sudo / env / an absolute path.
_PIPE_TO_SHELL = r"\|\s*(sudo\s+(-\S+\s+)*)?(env\s+)?(\S*/)?(ba|z|da|k|fi)?sh\b"
_PS_DOWNLOAD = r"\b(invoke-webrequest|iwr|invoke-restmethod|irm|curl|wget)\b"

DANGEROUS_PATTERNS = [
    # -r/-R anywhere in the flag cluster (-rf, -fr, -Rf) or --recursive. "git rm -r" only
    # untracks files git can restore, so it is left out.
    (r"(?<!\bgit\s)\brm\s+(-\S+\s+)*(-\w*[rR]\w*|--recursive)\b", "recursive delete"),
    (r"\bmkfs(\.\w+)?\s", "filesystem format"),
    (r"\bdd\s+(\S+\s+)*if=", "disk overwrite"),
    (r"\bchmod\s+(-\w+\s+)*0?777\b", "world-writable permissions"),
    (r":\(\)\s*\{.*:\|:&\s*\}\s*;:", "fork bomb"),
    (r"\bcurl\b.*" + _PIPE_TO_SHELL, "remote code execution via curl|sh"),
    (r"\bwget\b.*" + _PIPE_TO_SHELL, "remote code execution via wget|sh"),
    (r"\b(ba|z)?sh\s+<\(\s*(curl|wget)\b", "remote code execution via sh <(curl)"),
    (r"\bn(c|cat)\s+(\S+\s+)*-\w*e\b", "reverse shell via netcat"),
    (r"python.*-c.*import\s+os.*\b(system|exec|popen|spawn)\b", "Python OS command execution"),
    (_PS_DOWNLOAD + r".*\|\s*(iex|invoke-expression)\b", "PowerShell remote execution"),
    (r"\b(iex|invoke-expression)\s*[\(\$]", "PowerShell Invoke-Expression"),
    (r"\bstart-process\b.*-windowstyle\s+hidden\b", "hidden process execution"),
    # C-SEC-001: eval/base64/source bypass patterns
    (r"(?:^|[;&|]\s*)eval\s+\S", "eval command execution"),
    (r"\beval\$", "eval with subshell"),
    (r"\$\(.*base64\s+(-d|--decode)", "base64 decode in subshell"),
    (r"\bsource\s+/dev/stdin", "stdin source execution"),
    (r"`[^`]*base64\s+(-d|--decode)[^`]*`", "base64 decode in backtick subshell"),
    # M-3: cmd.exe dangerous commands (Windows)
    (r"\bdel\s+(/\w\s+)*/[sq]\b", "Windows recursive delete (del /s or /q)"),
    (r"\b(rd|rmdir)\s+(/\w\s+)*/s\b", "Windows recursive directory delete (rd /s)"),
    (r"\bformat(\.com)?\s+[A-Z]:(\s|$)", "Windows disk format"),
    (r"\bnet\s+user\s+\S", "Windows user account modification"),
    (r"\breg\s+delete\b", "Windows registry deletion"),
]

WARNING_PATTERNS = [
    (r"\bcurl\s+.*\s-o\s", "download to disk via curl -o"),
    (r"\bcurl\s+.*--output\s", "download to disk via curl --output"),
    (r"\bwget\s+.*\s-O\s", "download to disk via wget -O"),
    (r"\bwget\s+.*--output-document", "download to disk via wget --output-document"),
    (r"\b(invoke-webrequest|iwr)\b.*-OutFile", "download to disk via Invoke-WebRequest"),
]


def _normalize_command(cmd):
    """Best-effort shell normalization via shlex. Resolves quotes, backslashes.
    Falls back to raw lowercased command on parse failure (fail-open)."""
    try:
        return " ".join(shlex.split(cmd)).lower()
    except ValueError:
        return cmd.lower()


def main():
    try:
        # Hook input is UTF-8. Read bytes: on Windows sys.stdin decodes with the locale code page.
        data = json.loads(sys.stdin.buffer.read().decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)
    if not isinstance(data, dict):
        sys.exit(0)
    tool_input = data.get("tool_input") or {}
    command = tool_input.get("command", "") if isinstance(tool_input, dict) else ""

    if not command:
        sys.exit(0)

    normalized = _normalize_command(command)

    # M-4: Scan ALL patterns, collect matches, return highest severity
    blocks = []
    for pattern, desc in DANGEROUS_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE) or re.search(pattern, normalized, re.IGNORECASE):
            blocks.append(desc)

    warnings = []
    for pattern, desc in WARNING_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE) or re.search(pattern, normalized, re.IGNORECASE):
            warnings.append(desc)

    if blocks:
        reason = "Cerbero: blocked dangerous command"
        if len(blocks) == 1:
            reason += f" ({blocks[0]})"
        else:
            reason += f" ({', '.join(blocks)})"
        json.dump({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }, sys.stdout)
        sys.exit(0)

    if warnings:
        msg = "Cerbero WARNING: detected " + ", ".join(warnings) + ". Verify source and destination."
        json.dump({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "additionalContext": msg,
            }
        }, sys.stdout)
        sys.exit(0)

    sys.exit(0)


if __name__ == "__main__":
    main()
