"""Cerbero hook: PreToolUse — block dangerous shell commands.

Normalization: shlex.split() resolves quotes and backslash escapes before matching.
Multi-match: scans all patterns, returns highest severity (deny > warn).
Scope: catches accidental dangerous commands and basic static evasion. Dynamic
evasion (variable expansion, aliases, IFS tricks) is out of scope — use Claude
Code's sandbox mode for OS-level enforcement.

Fail-open: parse errors → allow (consistent with all Ignite hooks).
"""
import sys
import json
import re
import shlex

DANGEROUS_PATTERNS = [
    (r"rm\s+-rf?", "recursive delete"),
    (r"mkfs\.", "filesystem format"),
    (r"dd\s+if=", "disk overwrite"),
    (r"chmod\s+777", "world-writable permissions"),
    (r":\(\)\s*\{.*:\|:&\s*\}\s*;:", "fork bomb"),
    (r"curl.*\|.*sh", "remote code execution via curl|sh"),
    (r"wget.*\|.*sh", "remote code execution via wget|sh"),
    (r"nc\s+-e", "reverse shell via netcat"),
    (r"python.*-c.*import\s+os.*\b(system|exec|popen|spawn)\b", "Python OS command execution"),
    (r"Invoke-WebRequest.*\|.*iex", "PowerShell remote execution"),
    (r"iex\s*\(", "PowerShell Invoke-Expression"),
    (r"Start-Process.*-NoNewWindow", "hidden process execution"),
    # C-SEC-001: eval/base64/source bypass patterns
    (r"(?:^|[;&|]\s*)eval\s+\S", "eval command execution"),
    (r"\beval\$", "eval with subshell"),
    (r"\$\(.*base64\s+(-d|--decode)", "base64 decode in subshell"),
    (r"source\s+/dev/stdin", "stdin source execution"),
    (r"`[^`]*base64\s+(-d|--decode)[^`]*`", "base64 decode in backtick subshell"),
    # M-3: cmd.exe dangerous commands (Windows)
    (r"\bdel\s+/[sq]", "Windows recursive delete (del /s or /q)"),
    (r"\brd\s+/s", "Windows recursive directory delete (rd /s)"),
    (r"\bformat\s+[A-Z]:", "Windows disk format"),
    (r"\bnet\s+user\s+", "Windows user account modification"),
    (r"\breg\s+delete\b", "Windows registry deletion"),
]

WARNING_PATTERNS = [
    (r"curl\s+.*-o\s", "download to disk via curl -o"),
    (r"curl\s+.*--output\s", "download to disk via curl --output"),
    (r"wget\s+.*-O\s", "download to disk via wget -O"),
    (r"wget\s+.*--output-document", "download to disk via wget --output-document"),
    (r"Invoke-WebRequest.*-OutFile", "download to disk via Invoke-WebRequest"),
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
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
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
