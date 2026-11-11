"""Cerbero hook: PreToolUse - audit trail for MCP tool invocations.

Log directory: CERBERO_LOG_DIR if set (one shared log; each entry records its
project), else <project>/.claude/security/ with <project> from _project_root().

Known limitation (M-RES-001): No file locking on concurrent writes. The counter
read-increment-write has a theoretical TOCTOU race if CC fires parallel PreToolUse
hooks. Impact: counter off by +-1 (used only for reminder threshold). Log append via
open('a') is effectively atomic for entries < 4KB on POSIX/NTFS. Accepted risk.

Tripwire: when <project>/.claude/security/mcp-inventory.json is a
cerbero-mcp-snapshot/1 baseline (written by cerbero-mcp-snapshot.py), a call to
a tool that is not in the baseline of its server, or to a server the baseline
does not cover, produces a warning. It sees tool names only, at call time: it
catches a tool added after approval (also mid-session), not a changed
description. CERBERO_TRIPWIRE: unset or "warn" = warn only (default), "ask" =
also return permissionDecision "ask" for an unknown tool of a baselined server,
"off" = disabled.

Messages for the user go to stdout as one JSON object with "systemMessage":
Claude Code discards the stderr of a hook that exits 0.

Fail-open: any error exits 0 without blocking the tool call.
"""
import sys
import json
import os
import re
import tempfile
from datetime import datetime, timezone

SNAPSHOT_FORMAT = "cerbero-mcp-snapshot/1"
MAX_WARNED_SESSIONS = 20


def _norm(name):
    """Claude Code's tool-name form: anything outside A-Z a-z 0-9 _ - becomes _."""
    return re.sub(r"[^A-Za-z0-9_-]", "_", str(name))


def _load_index(baseline_path, cache_path):
    """({server: {"status", "reason", "tools": [...]}}, cache, fresh) from the baseline.
    Parsed once per baseline version: the cache is keyed by the baseline's
    path, modification time (ns) and size. A rewrite that keeps all three is
    not noticed until the next change."""
    st = os.stat(baseline_path)
    key = [os.path.normcase(os.path.abspath(baseline_path)), st.st_mtime_ns, st.st_size]
    cache = {}
    try:
        with open(cache_path, "r", encoding="utf-8") as f:
            cache = json.load(f)
    except (OSError, ValueError):
        cache = {}
    if not isinstance(cache, dict):
        cache = {}
    if cache.get("key") == key and isinstance(cache.get("servers"), dict):
        return cache["servers"], cache, False
    with open(baseline_path, "rb") as f:
        doc = json.loads(f.read().decode("utf-8-sig", errors="replace"))
    if not isinstance(doc, dict) or doc.get("format") != SNAPSHOT_FORMAT or not isinstance(doc.get("servers"), dict):
        return None, cache, False
    servers = {}
    for name, s in doc["servers"].items():
        if not isinstance(s, dict):
            continue
        tools = s.get("tools") if isinstance(s.get("tools"), dict) else {}
        servers[_norm(name)] = {"name": str(name), "status": s.get("status"), "reason": s.get("reason"),
                                "tools": sorted(_norm(t) for t in tools)}
    cache = {"key": key, "servers": servers, "warned": cache.get("warned") if isinstance(cache.get("warned"), dict) else {}}
    return servers, cache, True


def _split_tool(tool_name, data, servers):
    """(normalized server, normalized tool) of an mcp__<server>__<tool> name."""
    rest = tool_name[len("mcp__"):]
    info = data.get("mcp_server")
    candidates = []
    if isinstance(info, dict) and info.get("name"):
        candidates.append(_norm(info["name"]))          # Claude Code v2.1.274+
    candidates.extend(sorted(servers, key=len, reverse=True))
    for server in candidates:
        if rest.startswith(server + "__"):
            return server, rest[len(server) + 2:]
    server, _, tool = rest.partition("__")
    return server, tool


def _tripwire(data, tool_name, project):
    """(warning or None, ask). Any exception is the caller's to swallow.
    The cache sits next to the baseline, in the project, so projects that
    share one CERBERO_LOG_DIR never read each other's tool set."""
    mode = os.environ.get("CERBERO_TRIPWIRE", "warn").strip().lower()
    if mode == "off" or not tool_name.startswith("mcp__"):
        return None, False
    baseline_path = os.path.join(project, ".claude", "security", "mcp-inventory.json")
    if not os.path.isfile(baseline_path):
        return None, False
    state_dir = os.path.dirname(baseline_path)
    cache_path = os.path.join(state_dir, "mcp-tripwire-cache.json")
    servers, cache, dirty = _load_index(baseline_path, cache_path)
    if servers is None:
        return None, False
    server, tool = _split_tool(tool_name, data, servers)
    entry = servers.get(server)
    ask = False
    if entry is None:
        key, once = server, True
        msg = ("Cerbero tripwire: MCP server '%s' is not in the approved baseline "
               "(plugin, connector and unapproved servers are not covered). Tool: %s." % (server, tool_name))
    elif entry.get("status") != "ok":
        key, once = server, True
        msg = ("Cerbero tripwire: MCP server '%s' is in the baseline but its tools were not read (%s). "
               "Tool: %s." % (entry.get("name"), entry.get("reason"), tool_name))
    elif tool not in entry.get("tools", []):
        key, once = server + "__" + tool, mode != "ask"
        ask = mode == "ask"
        msg = ("Cerbero tripwire: tool '%s' was not offered by MCP server '%s' when it was approved. "
               "Run /cerbero verify before trusting it." % (tool, entry.get("name")))
    else:
        key, once, msg = None, True, None

    # One warning per session and server (or tool); "ask" repeats on every call.
    if msg and once:
        warned = cache.setdefault("warned", {})
        session = str(data.get("session_id", "unknown"))
        seen = warned.setdefault(session, [])
        if key in seen:
            msg = None
        else:
            seen.append(key)
            while len(warned) > MAX_WARNED_SESSIONS:
                warned.pop(next(iter(warned)))
            dirty = True
    if dirty:
        try:
            fd, tmp_path = tempfile.mkstemp(dir=state_dir)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(cache, f)
            os.replace(tmp_path, cache_path)
        except OSError:
            pass
    return msg, ask and msg is not None


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
    except (OSError, ValueError):
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
            with open(log_path, "rb") as f:        # bytes: a damaged line must not stop the rotation
                lines = f.readlines()
            with open(log_path, "wb") as f:
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
    messages = []
    ask = False
    try:
        warning, ask = _tripwire(data, str(tool_name), project)
        if warning:
            messages.append(warning)
    except Exception:
        ask = False  # Fail open: a broken baseline or cache never blocks a tool call
    if count % 50 == 0:
        messages.append(f"Cerbero: {count} MCP invocations since last reset. Consider running /cerbero verify.")

    if messages:
        out = {"systemMessage": " ".join(messages)}
        if ask:
            out["hookSpecificOutput"] = {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": messages[0],
            }
        try:
            sys.stdout.write(json.dumps(out) + "\n")  # ASCII-only: safe on any console code page
            sys.stdout.flush()   # here, inside the try: a closed pipe must not surface at interpreter exit
        except (OSError, ValueError):
            os._exit(0)          # nobody is reading: skip the exit-time flush that would fail again (exit 120)

    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        sys.exit(0)  # Fail open: no error of this hook may block or fail a tool call
