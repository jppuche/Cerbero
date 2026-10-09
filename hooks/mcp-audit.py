"""Cerbero hook: PreToolUse - audit trail for MCP tool invocations.

Log directory: CERBERO_LOG_DIR if set (one shared log; each entry records its
project), else <project>/.claude/security/ with <project> from _project_root().

Known limitation (M-RES-001): No file locking on concurrent writes. The counter
read-increment-write has a theoretical TOCTOU race if CC fires parallel PreToolUse
hooks. Impact: counter off by +-1 (used only for reminder threshold). Log append via
open('a') is effectively atomic for entries < 4KB on POSIX/NTFS. Accepted risk.

Fail-open: any I/O error exits 0 without blocking the tool call.
"""
import sys
import json
import os
import tempfile
from datetime import datetime, timezone


def _project_root(input_cwd):
    """Project root for the audit log.

    The input's "cwd" follows Claude's `cd`, so it is only a last resort.
    Order: CLAUDE_PROJECT_DIR (also right for a global ~/.claude/hooks/
    install), then the parent of the .claude/ dir that holds this script
    (.claude/hooks/ or .claude/skills/cerbero/hooks/), then the input cwd.
    """
    env_dir = os.environ.get("CLAUDE_PROJECT_DIR")
    if env_dir and os.path.isdir(env_dir):
        return env_dir
    d = os.path.dirname(os.path.abspath(__file__))
    while os.path.normcase(os.path.basename(d)) != ".claude":
        parent = os.path.dirname(d)
        if parent == d:
            return input_cwd or os.getcwd()
        d = parent
    return os.path.dirname(d)


def main():
    try:
        # Hook input is UTF-8. Read bytes: on Windows sys.stdin decodes with the locale code page.
        data = json.loads(sys.stdin.buffer.read().decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)
    if not isinstance(data, dict):
        sys.exit(0)
    tool_name = data.get("tool_name", "unknown")
    tool_input = data.get("tool_input")

    project = _project_root(data.get("cwd"))
    override = os.environ.get("CERBERO_LOG_DIR")
    if override:
        log_dir = os.path.abspath(os.path.expanduser(override))
    else:
        log_dir = os.path.join(project, ".claude", "security")
    try:
        os.makedirs(log_dir, exist_ok=True)
    except OSError:
        sys.exit(0)
    log_path = os.path.join(log_dir, "mcp-audit.log")

    entry = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tool": tool_name,
        "input_keys": sorted(tool_input.keys()) if isinstance(tool_input, dict) else [],
        "session": data.get("session_id", "unknown"),
        "project": project,
    }

    # Log rotation: truncate to last 500 entries if over 1MB
    try:
        if os.path.exists(log_path) and os.path.getsize(log_path) > 1_000_000:
            with open(log_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            with open(log_path, "w", encoding="utf-8") as f:
                f.writelines(lines[-500:])
    except OSError:
        pass  # Fail open on rotation errors

    try:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        sys.exit(0)

    # M-5: Atomic counter update (tempfile + os.replace on same volume)
    counter_path = os.path.join(log_dir, "invocation-counter.txt")
    count = 0
    try:
        with open(counter_path, "r", encoding="utf-8") as cf:
            count = int(cf.read().strip())
    except (ValueError, OSError):
        count = 0
    count += 1
    try:
        fd, tmp_path = tempfile.mkstemp(dir=log_dir)
        with os.fdopen(fd, "w", encoding="utf-8") as cf:
            cf.write(str(count))
        os.replace(tmp_path, counter_path)
    except OSError:
        try:
            # Fallback: direct write (non-atomic but functional)
            with open(counter_path, "w", encoding="utf-8") as cf:
                cf.write(str(count))
        except OSError:
            pass
    if count % 50 == 0:
        print(f"Cerbero: {count} MCP invocations since last reset. Consider running /cerbero verify.", file=sys.stderr)

    sys.exit(0)


if __name__ == "__main__":
    main()
