#!/usr/bin/env python3
"""Cerbero MCP snapshot: tool-definition baseline for approved MCP servers.

Standalone script, not a hook. Stdlib only, Python 3.8+, Windows and POSIX.
Design: docs/design/rug-pull-snapshot.md.

Subcommands:
  pins      static launcher / pin / registry-integrity report. Launches nothing.
  approve   write the approval record of one configured server to
            .claude/security/mcp-approved.json (the launch allowlist).
  snapshot  connect to each APPROVED server (stdio subprocess or HTTP POST),
            read server instructions and tools/list, write a normalized
            snapshot (format cerbero-mcp-snapshot/1).
  compare   diff a current snapshot against the baseline.
            Exit 0 unchanged, 1 changed, 2 error, 3 legacy baseline.
  accept    back up the old baseline to .claude/security/history/<ts>/ and
            write the new inventory, hash and date. Never deletes.

Safety rules:
  - Only servers with a record in mcp-approved.json are ever launched or
    contacted, and only while command, args, url and env still match it.
  - A record counts only if `approve` registered its hash under the user's
    home (~/.claude/security/cerbero-approvals.json): an approval file that
    came with a repository approves nothing.
  - A record that lacks what a gate needs is invalid, never a pass.
  - Servers from a project .mcp.json need a trusted workspace (the same
    hasTrustDialogAccepted flag Claude Code uses), or --trust-project, and
    are skipped when a disabledMcpjsonServers entry rejects them.
  - Only a pinned launcher runs: an exact registry version, an image digest
    or a local file whose hash still matches the record. Unpinned ones need
    --allow-unpinned; launchers this script cannot verify need the user's
    recorded decision (approve --allow-unverified).
  - Records with sandbox_required, or risk CRITICAL, are skipped without
    --inside-isolation.
  - A bare command is looked up in the absolute entries of PATH only, never
    in the current directory.
  - OAuth, headersHelper, SSE/WebSocket, plugin, connector and managed
    servers are not covered: reported as skipped, never as unchanged.
  - Environment and header values are never printed or stored (hashes only).
  - The client identifies itself as "cerbero-snapshot". A server that shows
    other tools to other clients is not detected (documented limitation).
"""
import argparse
import hashlib
import json
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

TOOL_VERSION = "1.3.0"
FORMAT = "cerbero-mcp-snapshot/1"
CLIENT_NAME = "cerbero-snapshot"
MODERN_VERSION = "2026-07-28"       # first revision with per-request metadata
LEGACY_VERSION = "2025-11-25"       # last revision with the initialize handshake
# JSON-RPC errors only a modern (2026-07-28+) server returns:
# HeaderMismatch, MissingRequiredClientCapability, UnsupportedProtocolVersion.
MODERN_ERROR_CODES = (-32020, -32021, -32022)
UNSUPPORTED_VERSION_CODE = -32022
RESPONSE_CAP = 5 * 1024 * 1024      # bytes read from one server, per run
MAX_PAGES = 200
MAX_CURSOR = 4096                   # characters of a nextCursor we are willing to send back
SAFE_BATCH_ARG = re.compile(r"^[A-Za-z0-9@/._:=+-]+$")
VAR_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")
DOCKER_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
INTERPRETERS = re.compile(r"^(python[0-9.]*|py|pythonw|node|nodejs|deno|bun|ruby|java|dotnet|bash|sh|pwsh|powershell)$")

EXIT_OK, EXIT_CHANGED, EXIT_ERROR, EXIT_LEGACY = 0, 1, 2, 3


class SnapError(Exception):
    """A server could not be snapshotted. reason is a stable keyword."""

    def __init__(self, reason, detail=None, status="error"):
        Exception.__init__(self, reason)
        self.reason = reason
        self.detail = detail
        self.status = status


# --------------------------------------------------------------------------
# Canonical form and hashes
# --------------------------------------------------------------------------

def canon(obj):
    """Canonical bytes. No Unicode normalization and no trimming: an added
    zero-width or tag character must change the hash."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8", errors="surrogatepass")


def sha(obj):
    return "sha256:" + hashlib.sha256(canon(obj)).hexdigest()


def sha_text(text):
    return "sha256:" + hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()


def sha_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# Files
# --------------------------------------------------------------------------

def read_json(path):
    with open(path, "rb") as f:
        return json.loads(f.read().decode("utf-8-sig", errors="replace"))


def write_text_atomic(path, text):
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".cerbero-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_json_atomic(path, obj):
    # ensure_ascii=True: invisible characters are stored as visible \uXXXX escapes.
    write_text_atomic(path, json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n")


def emit(obj):
    sys.stdout.write(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n")


# --------------------------------------------------------------------------
# Configuration (what Claude Code would load, from the files we can read)
# --------------------------------------------------------------------------

def _norm_path(p):
    p = str(p).replace("\\", "/").rstrip("/")
    return p.lower() if os.name == "nt" else p


def _project_entries(home_cfg, project):
    """Entries of ~/.claude.json "projects" for this project, exact key first.
    Keys use forward slashes on Windows, with either drive-letter case."""
    projects = home_cfg.get("projects") if isinstance(home_cfg, dict) else None
    if not isinstance(projects, dict):
        return []
    want = _norm_path(project)
    hits = [(k, v) for k, v in projects.items() if isinstance(v, dict) and _norm_path(k) == want]
    hits.sort(key=lambda kv: kv[0].replace("\\", "/").rstrip("/") != str(project).replace("\\", "/").rstrip("/"))
    return [v for _, v in hits]


def workspace_trusted(home_cfg, project):
    """True if the project folder or one of its parents passed Claude Code's
    workspace trust dialog (projects[...].hasTrustDialogAccepted)."""
    d = os.path.abspath(project)
    while True:
        for entry in _project_entries(home_cfg, d):
            if entry.get("hasTrustDialogAccepted") is True:
                return True
        parent = os.path.dirname(d)
        if parent == d:
            return False
        d = parent


def load_configs(project, home):
    """Return ({name: (scope, entry)}, home_cfg, problems).
    Precedence local > project > user; the whole entry wins, no field merge."""
    problems = []
    home_cfg = {}
    home_path = os.path.join(home, ".claude.json")
    if os.path.isfile(home_path):
        try:
            home_cfg = read_json(home_path)
        except (OSError, ValueError):
            problems.append("unreadable: ~/.claude.json")
            home_cfg = {}
    if not isinstance(home_cfg, dict):
        home_cfg = {}
    project_cfg = {}
    mcp_path = os.path.join(project, ".mcp.json")
    if os.path.isfile(mcp_path):
        try:
            project_cfg = read_json(mcp_path)
        except (OSError, ValueError):
            problems.append("unreadable: .mcp.json")
    if not isinstance(project_cfg, dict):
        project_cfg = {}

    servers = {}

    def take(block, scope):
        if isinstance(block, dict):
            for name, entry in block.items():
                if isinstance(entry, dict):
                    servers[str(name)] = (scope, entry)

    take(home_cfg.get("mcpServers"), "user")
    take(project_cfg.get("mcpServers"), "project")
    for entry in reversed(_project_entries(home_cfg, project)):
        take(entry.get("mcpServers"), "local")
    return servers, home_cfg, problems


def expand(value, env):
    """${VAR} and ${VAR:-default}. An unset variable without a default stays
    as written, as Claude Code does."""
    if not isinstance(value, str):
        return value

    def repl(m):
        if m.group(1) in env:
            return env[m.group(1)]
        if m.group(2) is not None:
            return m.group(2)
        return m.group(0)

    return VAR_REF.sub(repl, value)


def transport_of(entry):
    t = entry.get("type")
    if t in (None, "stdio"):
        return "stdio"
    if t in ("http", "streamable-http"):
        return "http"
    return str(t)


def config_fingerprint(entry):
    """Hash of the entry as written, with every env and header value replaced
    by its own hash: a rotated literal token changes the fingerprint, and no
    secret is stored."""
    e = json.loads(json.dumps(entry))
    for key in ("env", "headers"):
        if isinstance(e.get(key), dict):
            e[key] = {k: sha_text(str(v)) for k, v in e[key].items()}
    return sha(e)


def launch_fingerprint(entry, env=None):
    """Hash of what decides which code runs or which endpoint is contacted:
    command, args and url as written, the same three after ${VAR} expansion,
    and the entry's whole env block (names, and a hash of each value as
    written). Any variable can change what a launcher runs (PATH, PYTHONPATH,
    NODE_OPTIONS, LD_PRELOAD, a registry URL), so none is exempt. A secret
    referenced as ${TOKEN} inside env can rotate without a new approval; a
    literal one cannot. Only hashes are kept."""
    env = os.environ if env is None else env
    cfg_env = entry.get("env") if isinstance(entry.get("env"), dict) else {}
    args = entry.get("args") if isinstance(entry.get("args"), list) else []
    resolved = [expand(str(entry.get("command") or ""), env)] + [expand(str(a), env) for a in args]
    resolved.append(expand(str(entry.get("url") or ""), env))
    return sha({"v": 2,
                "type": entry.get("type"), "command": entry.get("command"), "args": entry.get("args"),
                "url": entry.get("url"),
                "env": {str(k): sha_text(str(v)) for k, v in cfg_env.items()},
                "resolved": sha(resolved)})


# --------------------------------------------------------------------------
# Launcher classification (layer C, static)
# --------------------------------------------------------------------------

NPM_NAME = re.compile(r"^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$", re.I)
NPM_EXACT = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")
PYPI_NAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?(\[[A-Za-z0-9,._ -]*\])?$")
PYPI_EXACT = re.compile(r"^\d+(\.\d+)*((a|b|rc)\d+)?(\.post\d+)?(\.dev\d+)?(\+[0-9A-Za-z.]+)?$")
SECRET_FLAG = re.compile(r"(?i)^(--?[a-z0-9_.-]*(token|key|secret|passw|auth|credential|bearer|cookie|session)[a-z0-9_.-]*)=.*$")
REGISTRY_FLAGS = ("--registry", "--index-url", "-i", "--index", "--default-index", "--extra-index-url",
                  "--find-links", "-f")
REGISTRY_ENV = ("NPM_CONFIG_REGISTRY", "NPM_CONFIG_USERCONFIG", "YARN_NPM_REGISTRY_SERVER", "COREPACK_NPM_REGISTRY",
                "UV_INDEX", "UV_INDEX_URL", "UV_DEFAULT_INDEX", "UV_EXTRA_INDEX_URL", "UV_FIND_LINKS",
                "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "PIP_CONFIG_FILE")
NPX_VALUE_FLAGS = ("-p", "--package", "-c", "--call", "--registry", "--cache", "--userconfig", "--prefix", "-w",
                   "--workspace")
UVX_VALUE_FLAGS = ("--from", "--with", "--with-requirements", "--with-editable", "--python", "-p", "--spec",
                   "--index-url", "-i", "--index", "--default-index", "--extra-index-url", "--find-links", "-f",
                   "--constraint", "-c", "--overrides", "--cache-dir", "--directory", "--project")
DOCKER_VALUE_FLAGS = ("-e", "--env", "-v", "--volume", "--name", "-p", "--publish", "--network", "--net",
                      "--mount", "-w", "--workdir", "-u", "--user", "--entrypoint", "--env-file", "-l",
                      "--label", "--platform", "-h", "--hostname", "--add-host", "--cap-add", "--cap-drop",
                      "--memory", "-m", "--cpus", "--pull", "--security-opt", "--tmpfs", "--device", "--gpus")


def _base(cmd):
    b = os.path.basename(str(cmd).replace("\\", "/")).lower()
    for ext in (".exe", ".cmd", ".bat", ".ps1"):
        if b.endswith(ext):
            return b[:-len(ext)]
    return b


def _first_positional(args, value_flags):
    """First argument that is not a flag or a flag's value."""
    skip = False
    for a in args:
        if skip:
            skip = False
            continue
        if a == "--":
            continue
        if a.startswith("-"):
            if "=" not in a and a in value_flags:
                skip = True
            continue
        return a
    return None


def _flag_values(args, names):
    out = []
    for i, a in enumerate(args):
        for n in names:
            if a == n and i + 1 < len(args):
                out.append(args[i + 1])
            elif a.startswith(n + "="):
                out.append(a[len(n) + 1:])
    return out


def _split_npm(spec):
    at = spec.rfind("@")
    if at > 0:
        return spec[:at], spec[at + 1:]
    return spec, None


def _split_pypi(spec):
    if "==" in spec:
        name, ver = spec.split("==", 1)
        return name, ver
    if "@" in spec[1:]:
        name, ver = spec.rsplit("@", 1)
        return name, ver
    return spec, None


def _origin(url):
    """scheme://host[:port] of a URL: no user, no path, no query."""
    try:
        p = urllib.parse.urlsplit(url)
        host = p.hostname or ""
        if p.port:
            host = "%s:%d" % (host, p.port)
        return urllib.parse.urlunsplit((p.scheme, host, "", "", ""))
    except ValueError:
        return ""


def redact(text):
    """A launcher string that is safe to store and print: anything URL-shaped
    is cut to its origin, and the value of a secret-looking flag is dropped."""
    t = str(text)
    if "://" in t:
        prefix, _, rest = t.partition("://")
        scheme = prefix.rsplit("+", 1)[-1]
        return (prefix[:len(prefix) - len(scheme)] + _origin(scheme + "://" + rest)) or "<redacted>"
    m = SECRET_FLAG.match(t)
    if m:
        return m.group(1) + "=***"
    return t


def _npm_pinned(spec):
    name, ver = _split_npm(spec)
    return bool(NPM_NAME.match(name) and ver and NPM_EXACT.match(ver))


def _pypi_pinned(spec):
    name, ver = _split_pypi(spec)
    return bool(PYPI_NAME.match(name) and ver and PYPI_EXACT.match(ver))


def _custom_registry(entry, args):
    """True if a flag or an env name points the launcher at another registry."""
    for a in args:
        if a in REGISTRY_FLAGS or a.split("=", 1)[0] in REGISTRY_FLAGS:
            return True
    env = entry.get("env") if isinstance(entry.get("env"), dict) else {}
    return any(str(k).upper() in REGISTRY_ENV for k in env)


def _package_launcher(kind, specs, pinned_fn, entry, args):
    """Result for an npm-style or PyPI-style launcher. Only a registry-style
    name with an exact version is pinned; anything else (a range, a tag, a
    URL, a git reference, a local path) is not, and is stored redacted."""
    specs = [s for s in specs if s]
    if not specs:
        return {"kind": kind, "spec": "", "pinned": False}
    pinned = all(pinned_fn(s) for s in specs)
    out = {"kind": kind, "spec": " ".join(redact(s) for s in specs), "pinned": pinned}
    if pinned and len(specs) == 1:
        splitter = _split_npm if kind == "npx" else _split_pypi
        out["version"] = splitter(specs[0])[1]
    if pinned and _custom_registry(entry, args):
        # The version is exact, but it is resolved somewhere this script cannot check.
        out["pinned"] = None
        out["note"] = "custom registry or index"
    return out


def classify_launcher(entry, project, env=None):
    """{"kind", "spec", "pinned", ["version"], ["integrity"], ["note"]}.

    pinned is True (an exact registry version, an image digest, or a local
    file whose hash is recorded), False (a package launcher that resolves
    something at start: no exact version, a range, a URL, extra unpinned
    packages) or None (not verifiable here: a remote URL, a custom registry,
    a launcher this script does not understand). Only True passes the gates
    on its own; None needs the user's recorded decision.
    spec never contains a URL path, URL credentials, a query string or an
    argument: see redact()."""
    env = os.environ if env is None else env
    if transport_of(entry) != "stdio":
        return {"kind": "url", "spec": _origin(str(entry.get("url") or "")), "pinned": None}

    command = str(entry.get("command") or "")
    args = [str(a) for a in (entry.get("args") or []) if isinstance(a, (str, int, float))]
    base = _base(command)
    if base == "cmd" and args and args[0].lower() == "/c" and len(args) > 1:
        base, args = _base(args[1]), args[2:]
    elif base in ("env", "winpty") and args:
        base, args = _base(args[0]), args[1:]
    if base in ("node", "nodejs") and args and _base(args[0]) in ("npx-cli.js", "npx-cli.cjs", "npx-cli.mjs", "npx"):
        base, args = "npx", args[1:]

    npm_sub = {"npm": ("exec", "x"), "pnpm": ("exec", "dlx"), "yarn": ("dlx",), "bun": ("x",)}
    if base in ("npx", "bunx", "pnpx") or (base in npm_sub and args[:1] and args[0] in npm_sub[base]):
        if base in npm_sub:
            args = args[1:]
        specs = _flag_values(args, ("-p", "--package")) or [_first_positional(args, NPX_VALUE_FLAGS)]
        return _package_launcher("npx", specs, _npm_pinned, entry, args)

    if base == "uv" and args[:1] == ["run"]:
        # `uv run` resolves an environment at start, whatever follows.
        return {"kind": "uvx", "spec": redact(_first_positional(args[1:], UVX_VALUE_FLAGS) or ""), "pinned": False}
    if base in ("uvx", "pipx") or (base == "uv" and args[:2] == ["tool", "run"]):
        if base == "uv":
            args = args[2:]
        if base == "pipx" and args[:1] == ["run"]:
            args = args[1:]
        main = (_flag_values(args, ("--from", "--spec")) or [_first_positional(args, UVX_VALUE_FLAGS)])[:1]
        extra = [s for v in _flag_values(args, ("--with",)) for s in v.split(",")]
        out = _package_launcher("uvx", main + extra, _pypi_pinned, entry, args)
        if out["pinned"] is not False and any(a.split("=", 1)[0] in ("--with-requirements", "--with-editable")
                                              for a in args):
            out["pinned"] = False
        return out

    if base == "deno" and args[:1] == ["run"]:
        target = _first_positional(args[1:], ()) or ""
        if "://" in target or target.split(":", 1)[0] in ("npm", "jsr"):
            return {"kind": "deno", "spec": redact(target), "pinned": False}

    if base in ("docker", "podman") and "run" in args:
        image = _first_positional(args[args.index("run") + 1:], DOCKER_VALUE_FLAGS) or ""
        return {"kind": "docker", "spec": redact(image), "pinned": bool(DOCKER_DIGEST.search(image))}

    # Local file: the command itself, or the script an interpreter runs.
    candidates = []
    if INTERPRETERS.match(base):
        if "-m" not in args and "-c" not in args and "-e" not in args:
            candidates = [a for a in args if not a.startswith("-") and a != "run"][:1]
    elif "/" in command or "\\" in command:
        candidates = [command]
    for cand in candidates:
        path = expand(cand, env)
        if not os.path.isabs(path):
            path = os.path.join(project, path)
        if os.path.isfile(path):
            try:
                return {"kind": "path", "spec": redact(cand), "pinned": True, "integrity": sha_file(path)}
            except OSError:
                break
    return {"kind": "other", "spec": redact(command), "pinned": None}


def _registry_json(url):
    req = urllib.request.Request(url, headers={"Accept": "application/json",
                                               "User-Agent": "cerbero-mcp-snapshot/" + TOOL_VERSION})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read(RESPONSE_CAP).decode("utf-8", errors="replace"))


def registry_integrity(launcher):
    """Integrity the public registry reports for a pinned npm or PyPI spec.
    Sends a registry-style package name and an exact version, nothing else:
    a spec that is a URL, a git reference or a path is never sent anywhere.
    Returns (value, error)."""
    kind, spec = launcher.get("kind"), launcher.get("spec") or ""
    if launcher.get("pinned") is not True:
        return None, None
    try:
        if kind == "npx" and _npm_pinned(spec):
            name, ver = _split_npm(spec)
            doc = _registry_json("https://registry.npmjs.org/%s/%s" % (
                urllib.parse.quote(name, safe="@"), urllib.parse.quote(ver, safe="")))
            return (doc.get("dist") or {}).get("integrity"), None
        if kind == "uvx" and _pypi_pinned(spec):
            name, ver = _split_pypi(spec)
            name = name.split("[", 1)[0]
            doc = _registry_json("https://pypi.org/pypi/%s/%s/json" % (
                urllib.parse.quote(name, safe=""), urllib.parse.quote(ver, safe="")))
            files = sorted([u.get("filename"), (u.get("digests") or {}).get("sha256")]
                           for u in doc.get("urls") or [])
            return ("pypi-files-" + sha(files)) if files else None, None
    except Exception as e:  # network, HTTP or parse error: report, never raise
        return None, type(e).__name__
    return None, None


# --------------------------------------------------------------------------
# Approval records
# --------------------------------------------------------------------------

RISKS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def build_record(entry, scope, launcher, risk, sandbox_required, version, integrity, unverified):
    risk = str(risk).upper()
    record = {
        "launcher_kind": launcher["kind"],
        "launcher_spec": launcher["spec"],
        "version": version or launcher.get("version"),
        "integrity": integrity or launcher.get("integrity"),
        "risk": risk,
        "sandbox_required": bool(sandbox_required or risk == "CRITICAL"),
        "approved_at": now_iso(),
        "scope": scope,
        "config_fingerprint": config_fingerprint(entry),
        "launch_fingerprint": launch_fingerprint(entry),
    }
    if unverified:
        record["unverified_launcher"] = True
    return record


def record_problem(rec):
    """Why a record cannot be used, or None. A record that lacks what a gate
    needs is invalid: a missing field never means "skip that gate"."""
    fp = rec.get("launch_fingerprint")
    if not (isinstance(fp, str) and re.match(r"^sha256:[0-9a-f]{64}$", fp)):
        return "no launch_fingerprint"
    if str(rec.get("risk")).upper() not in RISKS:
        return "no valid risk"
    return None


def needs_isolation(rec):
    return bool(rec.get("sandbox_required")) or str(rec.get("risk")).upper() == "CRITICAL"


def anchors_path(home):
    return os.path.join(home, ".claude", "security", "cerbero-approvals.json")


def _read_anchors(home):
    try:
        data = read_json(anchors_path(home))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def write_anchor(home, project, name, record):
    """Register the record's hash outside the project. mcp-approved.json sits
    in the project folder, where a cloned repository can put its own: a
    record counts only if its hash is also here, under the user's home."""
    data = _read_anchors(home)
    block = data.setdefault(_norm_path(os.path.abspath(project)), {})
    if not isinstance(block, dict):
        block = data[_norm_path(os.path.abspath(project))] = {}
    block[name] = sha(record)
    write_json_atomic(anchors_path(home), data)


def anchored(home, project, name, record):
    block = _read_anchors(home).get(_norm_path(os.path.abspath(project)))
    return isinstance(block, dict) and block.get(name) == sha(record)


def project_disabled(ctx, name):
    """True if a disabledMcpjsonServers entry rejects this .mcp.json server.
    Claude Code honours that list from any settings file."""
    lists = []
    for path in (os.path.join(ctx.home, ".claude", "settings.json"),
                 os.path.join(ctx.project, ".claude", "settings.json"),
                 os.path.join(ctx.project, ".claude", "settings.local.json")):
        try:
            doc = read_json(path)
        except (OSError, ValueError):
            continue
        if isinstance(doc, dict):
            lists.append(doc.get("disabledMcpjsonServers"))
    for entry in _project_entries(ctx.home_cfg, ctx.project):
        lists.append(entry.get("disabledMcpjsonServers"))
    return any(isinstance(lst, list) and name in lst for lst in lists)


# --------------------------------------------------------------------------
# Context shared by the subcommands
# --------------------------------------------------------------------------

class Context(object):
    def __init__(self, args):
        project = getattr(args, "project", None) or os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
        self.project = os.path.abspath(project)
        self.home = os.path.expanduser("~")
        self.security_dir = os.path.abspath(getattr(args, "security_dir", None)
                                            or os.path.join(self.project, ".claude", "security"))
        self.approved_path = os.path.join(self.security_dir, "mcp-approved.json")
        self.configs, self.home_cfg, self.problems = load_configs(self.project, self.home)
        self.approved = {}
        if os.path.isfile(self.approved_path):
            try:
                data = read_json(self.approved_path)
                if isinstance(data, dict):
                    self.approved = {k: v for k, v in data.items() if isinstance(v, dict)}
                else:
                    self.problems.append("mcp-approved.json is not an object")
            except (OSError, ValueError):
                self.problems.append("unreadable: mcp-approved.json")

    def names(self, selected):
        names = sorted(set(self.configs) | set(self.approved))
        if selected:
            names = [n for n in names if n in set(selected)]
        return names


# --------------------------------------------------------------------------
# pins / approve
# --------------------------------------------------------------------------

def _unverified(launcher):
    return launcher["pinned"] is None and launcher["kind"] != "url"


def cmd_pins(args):
    ctx = Context(args)
    report = {"generated_at": now_iso(), "offline": bool(args.offline), "servers": {}, "problems": ctx.problems}
    total = 0
    for name in ctx.names(args.server):
        rec = ctx.approved.get(name)
        if name not in ctx.configs:
            report["servers"][name] = {"approved": True, "findings": ["NOT_IN_CONFIG"],
                                       "note": "approved, but not in .mcp.json or ~/.claude.json "
                                               "(plugin, connector and managed servers are not covered)"}
            total += 1
            continue
        scope, entry = ctx.configs[name]
        launcher = classify_launcher(entry, ctx.project)
        findings = []
        row = {"scope": scope, "transport": transport_of(entry), "launcher": launcher,
               "approved": rec is not None, "findings": findings}
        if launcher["pinned"] is False:
            findings.append("UNPINNED")
        if rec is None:
            findings.append("NOT_APPROVED")
            if _unverified(launcher):
                findings.append("UNVERIFIED_LAUNCHER")
        else:
            if not anchored(ctx.home, ctx.project, name, rec):
                findings.append("APPROVAL_NOT_LOCAL")
            if record_problem(rec):
                findings.append("INVALID_RECORD")
                row["record_problem"] = record_problem(rec)
            elif rec.get("launch_fingerprint") != launch_fingerprint(entry):
                findings.append("LAUNCH_CHANGED")
            if _unverified(launcher) and not rec.get("unverified_launcher"):
                findings.append("UNVERIFIED_LAUNCHER")
            if rec.get("launcher_spec") not in (None, launcher["spec"]):
                findings.append("VERSION_DRIFT")
                row["approved_spec"] = redact(rec.get("launcher_spec"))
            if launcher.get("integrity") and rec.get("integrity") != launcher["integrity"]:
                findings.append("INTEGRITY_MISMATCH")
            if not args.offline and launcher["kind"] in ("npx", "uvx") and launcher["pinned"] is True:
                value, err = registry_integrity(launcher)
                row["registry"] = {"integrity": value, "error": err}
                if err or value is None:
                    row["registry"]["note"] = "registry integrity not checked"
                elif rec.get("integrity") and rec["integrity"] != value:
                    findings.append("INTEGRITY_MISMATCH")
        total += len(findings)
        report["servers"][name] = row
    report["findings_total"] = total
    emit(report)
    return EXIT_CHANGED if total else EXIT_OK


def cmd_approve(args):
    ctx = Context(args)
    if args.name not in ctx.configs:
        emit({"error": "not_in_config", "server": args.name,
              "detail": "no entry in .mcp.json or ~/.claude.json; plugin, connector and managed servers cannot be approved here"})
        return EXIT_ERROR
    scope, entry = ctx.configs[args.name]
    launcher = classify_launcher(entry, ctx.project)
    if launcher["pinned"] is False:
        emit({"error": "UNPINNED", "server": args.name, "launcher": launcher,
              "detail": "pin an exact version (npx pkg@1.2.3, uvx pkg==1.2.3, docker image@sha256:...) before approval. "
                        "Ranges, tags, URLs, git references and extra unpinned packages do not count"})
        return EXIT_CHANGED
    if _unverified(launcher) and not args.allow_unverified:
        emit({"error": "UNVERIFIED_LAUNCHER", "server": args.name, "launcher": launcher,
              "detail": "this script cannot tell what the launcher runs or whether it is pinned (%s). "
                        "If the user has checked it and accepts that, approve again with --allow-unverified"
                        % (launcher.get("note") or "unknown command")})
        return EXIT_CHANGED
    integrity = args.integrity or launcher.get("integrity")
    registry_note = None
    if not integrity and not args.offline and launcher["kind"] in ("npx", "uvx") and launcher["pinned"] is True:
        integrity, err = registry_integrity(launcher)
        if err:
            registry_note = "registry integrity not recorded (%s)" % err
    record = build_record(entry, scope, launcher, args.risk, args.sandbox_required, args.version, integrity,
                          _unverified(launcher))
    approved = dict(ctx.approved)
    replaced = args.name in approved
    approved[args.name] = record
    write_json_atomic(ctx.approved_path, approved)
    write_anchor(ctx.home, ctx.project, args.name, record)
    out = {"approved": args.name, "replaced": replaced, "record": record, "file": ctx.approved_path}
    if registry_note:
        out["note"] = registry_note
    emit(out)
    return EXIT_OK


# --------------------------------------------------------------------------
# MCP client: stdio
# --------------------------------------------------------------------------

def _kill_tree(proc):
    """Kill the server and every process it started."""
    if os.name == "nt":
        if proc.poll() is None:
            taskkill = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "taskkill.exe")
            try:
                subprocess.run([taskkill, "/T", "/F", "/PID", str(proc.pid)], stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
            except (OSError, subprocess.SubprocessError):
                pass
            if proc.poll() is None:
                try:
                    proc.kill()
                except OSError:
                    pass
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)  # start_new_session: pgid == pid
        except (ProcessLookupError, PermissionError, OSError):
            return
        deadline = time.time() + 1.0
        while time.time() < deadline:
            try:
                os.killpg(proc.pid, 0)
            except OSError:
                return
            proc.poll()
            time.sleep(0.05)


class StdioSession(object):
    def __init__(self, argv, env, cwd, deadline):
        self.deadline = deadline
        self.noise = 0
        self._next_id = 0
        self._stuck = False
        self._q = queue.Queue()
        kwargs = {"stdin": subprocess.PIPE, "stdout": subprocess.PIPE, "stderr": subprocess.DEVNULL,
                  "env": env, "cwd": cwd}
        if os.name == "nt":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        else:
            kwargs["start_new_session"] = True
        try:
            self.proc = subprocess.Popen(argv, **kwargs)
        except (OSError, ValueError) as e:
            raise SnapError("spawn_failed", type(e).__name__)
        t = threading.Thread(target=self._reader, daemon=True)
        t.start()

    def _reader(self):
        buf, total = b"", 0
        out = self.proc.stdout
        try:
            while True:
                chunk = out.read1(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > RESPONSE_CAP:
                    self._q.put(("too_large", None))
                    return
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    self._q.put(("line", line))
        except (OSError, ValueError):
            pass
        self._q.put(("eof", None))

    def _write(self, obj):
        data = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
        remaining = self.deadline - time.time()
        if remaining <= 0 or self._stuck:
            raise SnapError("timeout")
        failed = []

        def work():
            try:
                self.proc.stdin.write(data)
                self.proc.stdin.flush()
            except Exception as e:
                failed.append(e)

        # A server that never reads its input would block this write for ever
        # once the pipe is full, so the write runs under the same deadline.
        t = threading.Thread(target=work, daemon=True)
        t.start()
        t.join(remaining)
        if t.is_alive():
            self._stuck = True
            raise SnapError("timeout", "the server does not read its input")
        if failed:
            raise SnapError("protocol_error", "server closed its input")

    def send(self, method, params):
        self._next_id += 1
        self._write({"jsonrpc": "2.0", "id": self._next_id, "method": method, "params": params})
        return self._next_id

    def notify(self, method):
        self._write({"jsonrpc": "2.0", "method": method})

    def wait(self, ids, timeout=None):
        """Next response whose id is in ids, or None when timeout passes.
        Raises SnapError("timeout") when the server's whole budget is spent."""
        limit = self.deadline if timeout is None else min(self.deadline, time.time() + timeout)
        while True:
            remaining = limit - time.time()
            if remaining <= 0:
                if limit >= self.deadline:
                    raise SnapError("timeout")
                return None
            try:
                kind, line = self._q.get(timeout=remaining)
            except queue.Empty:
                continue
            if kind == "too_large":
                raise SnapError("too_large", "more than %d bytes" % RESPONSE_CAP)
            if kind == "eof":
                raise SnapError("protocol_error", "server closed its output")
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line.decode("utf-8", errors="replace"))
            except ValueError:
                msg = None
            if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
                self.noise += 1      # stdout line that is not JSON-RPC: ignored, counted
                continue
            if "method" in msg:
                if "id" in msg:      # legacy server-to-client request
                    if msg["method"] == "ping":
                        self._write({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
                    else:
                        self._write({"jsonrpc": "2.0", "id": msg["id"],
                                     "error": {"code": -32601, "message": "Method not found"}})
                continue             # notification (list_changed, progress, log): ignored
            if msg.get("id") in ids and ("result" in msg or "error" in msg):
                return msg

    def close(self):
        if not self._stuck:          # a blocked writer holds the pipe's lock: closing would block too
            try:
                self.proc.stdin.close()
            except (OSError, ValueError):
                pass
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        _kill_tree(self.proc)
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        try:
            self.proc.stdout.close()
        except (OSError, ValueError):
            pass


def modern_meta(version):
    return {"io.modelcontextprotocol/protocolVersion": version,
            "io.modelcontextprotocol/clientInfo": {"name": CLIENT_NAME, "version": TOOL_VERSION},
            "io.modelcontextprotocol/clientCapabilities": {}}


def _legacy_init_params():
    return {"protocolVersion": LEGACY_VERSION, "capabilities": {},
            "clientInfo": {"name": CLIENT_NAME, "version": TOOL_VERSION}}


def _is_discover_result(msg):
    r = msg.get("result") if isinstance(msg, dict) else None
    return isinstance(r, dict) and isinstance(r.get("supportedVersions"), list)


def _error_code(msg):
    e = msg.get("error") if isinstance(msg, dict) else None
    return e.get("code") if isinstance(e, dict) else None


def _pick_modern(versions):
    """A modern version from a server's list, or None if it only lists legacy ones."""
    versions = [v for v in versions or [] if isinstance(v, str)]
    if MODERN_VERSION in versions:
        return MODERN_VERSION
    modern = sorted(v for v in versions if v >= MODERN_VERSION)
    return modern[-1] if modern else None


def _server_info(obj):
    if not isinstance(obj, dict):
        return None
    return {"name": obj.get("name"), "version": obj.get("version")}


def _result_of(msg, what):
    if "error" in msg:
        raise SnapError("protocol_error", "%s returned error %s" % (what, _error_code(msg)))
    if not isinstance(msg.get("result"), dict):
        raise SnapError("protocol_error", "%s returned no result object" % what)
    return msg["result"]


def list_tools(call):
    """All pages of tools/list. call(params) returns the result object."""
    tools, cursor, seen = [], None, set()
    for _ in range(MAX_PAGES):
        res = call({"cursor": cursor} if cursor is not None else {})
        if res.get("resultType") not in (None, "complete") or not isinstance(res.get("tools"), list):
            raise SnapError("protocol_error", "tools/list result has no tool list")
        tools.extend(res["tools"])
        cursor = res.get("nextCursor")
        if cursor is None or cursor == "":
            return tools
        if not isinstance(cursor, str) or cursor in seen:
            raise SnapError("protocol_error", "tools/list pagination loop")
        if len(cursor) > MAX_CURSOR:
            raise SnapError("protocol_error", "tools/list cursor longer than %d characters" % MAX_CURSOR)
        seen.add(cursor)
    raise SnapError("protocol_error", "tools/list exceeds %d pages" % MAX_PAGES)


def normalize_tools(tools):
    """{name: {"hash", "def"}}. The definition is kept whole, unknown keys
    included: a field this script does not know still changes the hash."""
    out = {}
    for t in tools:
        if not isinstance(t, dict) or not isinstance(t.get("name"), str):
            raise SnapError("protocol_error", "tool without a string name")
        if t["name"] in out:
            raise SnapError("protocol_error", "duplicate tool name")
        out[t["name"]] = {"hash": sha(t), "def": t}
    return out


def _twice(call):
    first = normalize_tools(list_tools(call))
    second = normalize_tools(list_tools(call))
    stable = {k: v["hash"] for k, v in first.items()} == {k: v["hash"] for k, v in second.items()}
    return first, stable


def fetch_stdio(argv, env, cwd, timeout, probe_timeout):
    sess = StdioSession(argv, env, cwd, time.time() + timeout)
    try:
        probe = sess.send("server/discover", {"_meta": modern_meta(MODERN_VERSION)})
        msg = sess.wait([probe], probe_timeout)
        era, version, info, instructions, caps = None, None, None, None, {}

        def adopt_modern(m):
            r = m["result"]
            v = _pick_modern(r.get("supportedVersions"))
            if v is None:
                return None
            return ("modern", v, _server_info((r.get("_meta") or {}).get("io.modelcontextprotocol/serverInfo")),
                    r.get("instructions"), r.get("capabilities") or {})

        if msg is not None and _error_code(msg) == UNSUPPORTED_VERSION_CODE:
            data = msg["error"].get("data") if isinstance(msg["error"].get("data"), dict) else {}
            v = _pick_modern(data.get("supported"))
            if v is not None:
                rid = sess.send("server/discover", {"_meta": modern_meta(v)})
                msg = sess.wait([rid])
                if not _is_discover_result(msg):
                    raise SnapError("protocol_error", "server/discover failed after version retry")
            else:
                msg = None  # the server lists legacy versions only
        elif msg is not None and _error_code(msg) in MODERN_ERROR_CODES:
            raise SnapError("protocol_error", "modern server rejected server/discover (%s)" % _error_code(msg))

        got = adopt_modern(msg) if _is_discover_result(msg) else None
        if got is None:
            # Legacy: any other error, or silence. A slow modern server may
            # still answer the probe while we wait for initialize.
            init = sess.send("initialize", _legacy_init_params())
            while True:
                m = sess.wait([init, probe])
                if m.get("id") == probe:
                    late = adopt_modern(m) if _is_discover_result(m) else None
                    if late is not None:
                        got = late
                        break
                    continue
                r = _result_of(m, "initialize")
                got = ("legacy", r.get("protocolVersion"), _server_info(r.get("serverInfo")),
                       r.get("instructions"), r.get("capabilities") or {})
                sess.notify("notifications/initialized")
                break
        era, version, info, instructions, caps = got

        def call(params):
            if era == "modern":
                params = dict(params, _meta=modern_meta(version))
            return _result_of(sess.wait([sess.send("tools/list", params)]), "tools/list")

        if isinstance(caps, dict) and "tools" not in caps:
            tools, stable = {}, True
        else:
            tools, stable = _twice(call)
        return {"era": era, "version": version, "server_info": info, "instructions": instructions,
                "tools": tools, "stable": stable, "noise": sess.noise}
    finally:
        sess.close()


# --------------------------------------------------------------------------
# MCP client: Streamable HTTP
# --------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Configured headers may carry credentials: never follow a redirect."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HttpSession(object):
    def __init__(self, url, headers, deadline):
        self.url = url
        self.headers = dict(headers)
        self.deadline = deadline
        self.session_id = None
        self._next_id = 0
        self._read = 0
        self._resp = None
        self._opener = urllib.request.build_opener(_NoRedirect)

    def _limited(self, n):
        self._read += n
        if self._read > RESPONSE_CAP:
            raise SnapError("too_large", "more than %d bytes" % RESPONSE_CAP)
        if time.time() > self.deadline:
            raise SnapError("timeout")

    def abort(self):
        """Called from the watchdog when the budget is spent: unblock a read."""
        try:
            self._resp.fp.raw._sock.shutdown(2)
        except Exception:
            pass
        try:
            self._resp.close()
        except Exception:
            pass

    def _parse(self, resp, want_id):
        self._resp = resp
        ctype = (resp.headers.get("Content-Type") or "").lower()
        if ctype.startswith("text/event-stream"):
            data = []
            while True:
                raw = resp.readline(RESPONSE_CAP + 1)
                self._limited(len(raw))
                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                if raw and line.startswith("data:"):
                    data.append(line[5:].lstrip(" "))
                    continue
                if raw and line:
                    continue                      # event:, id:, retry:, comment
                if data:
                    try:
                        msg = json.loads("\n".join(data))
                    except ValueError:
                        msg = None
                    data = []
                    if isinstance(msg, dict) and msg.get("id") == want_id and ("result" in msg or "error" in msg):
                        return msg
                if not raw:
                    return None
        body = b""
        while True:                               # in pieces, so the deadline is checked between reads
            chunk = resp.read1(65536) if hasattr(resp, "read1") else resp.read(65536)
            if not chunk:
                break
            self._limited(len(chunk))
            body += chunk
        try:
            msg = json.loads(body.decode("utf-8", errors="replace"))
        except ValueError:
            return None
        return msg if isinstance(msg, dict) else None

    def post(self, body, extra):
        """(status, message or None, response headers)."""
        remaining = self.deadline - time.time()
        if remaining <= 0:
            raise SnapError("timeout")
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        headers.update(self.headers)
        headers.update(extra)
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        req = urllib.request.Request(self.url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
        try:
            with self._opener.open(req, timeout=max(1.0, min(remaining, 10.0))) as resp:
                return resp.status, self._parse(resp, body.get("id")), resp.headers
        except urllib.error.HTTPError as e:
            try:
                msg = self._parse(e, body.get("id"))
            except SnapError:
                raise
            except Exception:
                msg = None
            return e.code, msg, e.headers
        except SnapError:
            raise
        except Exception as e:  # URLError, socket timeout, TLS, reset
            if "timed out" in str(e).lower():
                raise SnapError("timeout")
            raise SnapError("unreachable", type(e).__name__)

    def request(self, method, params, extra):
        self._next_id += 1
        return self.post({"jsonrpc": "2.0", "id": self._next_id, "method": method, "params": params}, extra)


def fetch_http(url, headers, timeout):
    """_fetch_http under one overall deadline. A socket timeout only bounds a
    single read: a server that sends one byte, or one SSE ping, at a time
    would otherwise keep a request open until the size cap."""
    sess = HttpSession(url, headers, time.time() + timeout)
    box = {}

    def work():
        try:
            box["ok"] = _fetch_http(sess, headers)
        except SnapError as e:
            box["error"] = e
        except Exception as e:
            box["error"] = SnapError("protocol_error", type(e).__name__)

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(timeout + 1.0)
    if t.is_alive():
        sess.abort()
        raise SnapError("timeout")
    if "error" in box:
        raise box["error"]
    return box["ok"]


def _fetch_http(sess, headers):
    has_auth = any(k.lower() == "authorization" for k in headers)

    def auth_check(status):
        if status == 401 and not has_auth:
            raise SnapError("oauth", "HTTP 401: the server needs an interactive sign-in", status="skipped")
        if status in (401, 403):
            raise SnapError("auth_failed", "HTTP %d with the configured headers" % status)

    def modern_headers(version, method):
        return {"MCP-Protocol-Version": version, "Mcp-Method": method}

    def discover(version):
        status, msg, _ = sess.request("server/discover", {"_meta": modern_meta(version)},
                                      modern_headers(version, "server/discover"))
        auth_check(status)
        return status, msg

    status, msg = discover(MODERN_VERSION)
    got = None
    if _error_code(msg) == UNSUPPORTED_VERSION_CODE:
        data = msg["error"].get("data") if isinstance(msg["error"].get("data"), dict) else {}
        v = _pick_modern(data.get("supported"))
        if v is not None:
            status, msg = discover(v)
            if not _is_discover_result(msg):
                raise SnapError("protocol_error", "server/discover failed after version retry")
        else:
            msg = None
    elif _error_code(msg) in MODERN_ERROR_CODES:
        raise SnapError("protocol_error", "modern server rejected server/discover (%s)" % _error_code(msg))
    elif status >= 500:
        raise SnapError("protocol_error", "HTTP %d" % status)

    if _is_discover_result(msg):
        r = msg["result"]
        v = _pick_modern(r.get("supportedVersions"))
        if v is not None:
            got = ("modern", v, _server_info((r.get("_meta") or {}).get("io.modelcontextprotocol/serverInfo")),
                   r.get("instructions"), r.get("capabilities") or {})
    if got is None:
        # Legacy: a 4xx (or an error) that is not a recognized modern error.
        status, m, rh = sess.request("initialize", _legacy_init_params(), {})
        auth_check(status)
        if m is None:
            raise SnapError("protocol_error", "initialize: HTTP %d without a JSON-RPC response" % status)
        r = _result_of(m, "initialize")
        sess.session_id = rh.get("Mcp-Session-Id") if rh is not None else None
        got = ("legacy", r.get("protocolVersion"), _server_info(r.get("serverInfo")),
               r.get("instructions"), r.get("capabilities") or {})
        sess.post({"jsonrpc": "2.0", "method": "notifications/initialized"},
                  {"MCP-Protocol-Version": str(got[1] or LEGACY_VERSION)})
    era, version, info, instructions, caps = got

    def call(params):
        if era == "modern":
            status, m, _ = sess.request("tools/list", dict(params, _meta=modern_meta(version)),
                                        modern_headers(version, "tools/list"))
        else:
            status, m, _ = sess.request("tools/list", params,
                                        {"MCP-Protocol-Version": str(version or LEGACY_VERSION)})
        auth_check(status)
        if m is None:
            raise SnapError("protocol_error", "tools/list: HTTP %d without a JSON-RPC response" % status)
        return _result_of(m, "tools/list")

    if isinstance(caps, dict) and "tools" not in caps:
        tools, stable = {}, True
    else:
        tools, stable = _twice(call)
    return {"era": era, "version": version, "server_info": info, "instructions": instructions,
            "tools": tools, "stable": stable, "noise": 0}


# --------------------------------------------------------------------------
# snapshot
# --------------------------------------------------------------------------

def resolve_command(command, env):
    """Absolute path of a bare command, searched in the absolute entries of
    PATH only. The current directory is never searched (Windows and
    shutil.which do search it first), and neither are empty or relative PATH
    entries: the check runs from the project folder, and a file there named
    like the launcher must not be what runs. A command written with a path is
    returned as written."""
    if "/" in command or "\\" in command:
        return command
    exts = [""]
    if os.name == "nt":
        pathext = [e for e in env.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(os.pathsep) if e]
        if not any(command.lower().endswith(e.lower()) for e in pathext):
            exts = pathext
    for folder in env.get("PATH", "").split(os.pathsep):
        folder = folder.strip('"')
        if not folder or not os.path.isabs(folder):
            continue
        for ext in exts:
            cand = os.path.join(folder, command + ext)
            if os.path.isfile(cand) and (os.name == "nt" or os.access(cand, os.X_OK)):
                return cand
    return None


def _stdio_argv(entry, env):
    """argv for the server. ${VAR} comes from the environment of this run, as
    in Claude Code, never from the entry's own env block; the command is
    resolved with the PATH the server itself will get."""
    command = expand(str(entry.get("command") or ""), os.environ)
    args = [expand(str(a), os.environ) for a in (entry.get("args") or [])]
    resolved = resolve_command(command, env)
    if not resolved:
        raise SnapError("spawn_failed", "command not found in the absolute entries of PATH")
    if os.name != "nt":
        return [resolved] + args
    batch = resolved.lower().endswith((".cmd", ".bat")) or _base(resolved) == "cmd"
    if batch and not all(SAFE_BATCH_ARG.match(a) for a in args):
        # cmd.exe re-parses the arguments of a batch file: characters outside
        # this set could run other commands.
        raise SnapError("unsafe_args", "batch launcher with arguments outside [A-Za-z0-9@/._:=+-]", status="skipped")
    return [resolved] + args


def server_hash(s):
    return sha({"tools": {n: t["hash"] for n, t in s["tools"].items()},
                "instructions_hash": s["instructions_hash"],
                "server_info": s["server_info"],
                "config_fingerprint": s["config_fingerprint"],
                "launcher": s["launcher"]})


def inventory_hash(servers):
    return sha({n: s["server_hash"] for n, s in servers.items() if s.get("status") == "ok"})


def snapshot_server(ctx, name, args):
    rec = ctx.approved.get(name)
    if name not in ctx.configs:
        return {"status": "skipped", "reason": "not_covered_source",
                "detail": "approved, but not in .mcp.json or ~/.claude.json (plugin, connector and managed servers are not covered)"}
    scope, entry = ctx.configs[name]
    transport = transport_of(entry)
    launcher = classify_launcher(entry, ctx.project)
    s = {"scope": scope, "transport": transport, "launcher": launcher,
         "config_fingerprint": config_fingerprint(entry)}

    def skip(reason, detail=None, status="skipped"):
        s.update({"status": status, "reason": reason})
        if detail:
            s["detail"] = detail
        return s

    # Gates. Nothing is launched or contacted before all of them pass, and a
    # gate that cannot be evaluated fails closed.
    if rec is None:
        return skip("not_approved", "no record in mcp-approved.json")
    if not anchored(ctx.home, ctx.project, name, rec):
        return skip("approval_not_local", "the record was not written by `approve` on this machine, or was edited since: "
                                          "an approval file that came with the project approves nothing. Evaluate, then approve")
    problem = record_problem(rec)
    if problem:
        return skip("invalid_record", "approval record has %s: approve again" % problem)
    if rec["launch_fingerprint"] != launch_fingerprint(entry):
        return skip("launch_changed", "command, args, url or env differ from the approval record: re-evaluate, then approve again")
    if scope == "project":
        if project_disabled(ctx, name):
            return skip("disabled", "rejected by a disabledMcpjsonServers entry")
        if not args.trust_project and not workspace_trusted(ctx.home_cfg, ctx.project):
            return skip("untrusted_workspace", "the .mcp.json folder has not passed Claude Code's trust dialog")
    if needs_isolation(rec) and not args.inside_isolation:
        return skip("isolation", "the approval record requires isolation: run inside it with --inside-isolation")
    if launcher["pinned"] is False and not args.allow_unpinned:
        return skip("unpinned", "the launcher has no exact version: snapshotting would run whatever is newest")
    if _unverified(launcher) and not rec.get("unverified_launcher") and not args.allow_unpinned:
        return skip("unpinned", "this script cannot verify what the launcher runs (%s) and the record does not "
                                "accept that: approve with --allow-unverified" % (launcher.get("note") or "unknown command"))
    if launcher.get("integrity") and rec.get("integrity") != launcher["integrity"]:
        return skip("integrity_mismatch", "the local file changed since approval: it was not run. Re-evaluate, then approve again")
    if transport not in ("stdio", "http"):
        return skip("unsupported_transport", "transport %r is not covered" % transport)
    if transport == "http" and entry.get("headersHelper"):
        return skip("headers_helper", "headersHelper runs a command: not executed")

    env = dict(os.environ)
    try:
        if transport == "stdio":
            for k, v in (entry.get("env") or {}).items():
                env[str(k)] = expand(str(v), os.environ)
            env["CLAUDE_PROJECT_DIR"] = ctx.project
            argv = _stdio_argv(entry, env)
            got = fetch_stdio(argv, env, ctx.project, args.timeout, min(args.probe_timeout, args.timeout / 2.0))
        else:
            url = expand(str(entry.get("url") or ""), env)
            if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
                raise SnapError("protocol_error", "url is not http(s)")
            headers = {str(k): expand(str(v), env) for k, v in (entry.get("headers") or {}).items()}
            got = fetch_http(url, headers, args.timeout)
    except SnapError as e:
        return skip(e.reason, e.detail, status=e.status)

    s.update({
        "status": "ok", "reason": None,
        "protocol": {"era": got["era"], "version": got["version"]},
        "server_info": got["server_info"],
        "instructions": got["instructions"],
        "instructions_hash": sha(got["instructions"]),
        "tools": got["tools"],
        "stable": got["stable"],
        "stdout_noise_lines": got["noise"],
    })
    s["server_hash"] = server_hash(s)
    return s


def cmd_snapshot(args):
    ctx = Context(args)
    servers = {}
    for name in ctx.names(args.server):
        servers[name] = snapshot_server(ctx, name, args)
    for name in args.server or []:
        if name not in servers:
            servers[name] = {"status": "skipped", "reason": "not_approved", "detail": "unknown server name"}
    doc = {"format": FORMAT, "generated_at": now_iso(), "tool_version": TOOL_VERSION,
           "partial": bool(args.server), "servers": servers}
    doc["inventory_hash"] = inventory_hash(servers)
    write_json_atomic(args.out, doc)
    emit(_coverage(doc, {"out": os.path.abspath(args.out), "problems": ctx.problems}))
    return EXIT_OK


def _coverage(doc, extra=None):
    servers = doc.get("servers") or {}
    ok = sorted(n for n, s in servers.items() if s.get("status") == "ok")
    out = {
        "inventory_hash": doc.get("inventory_hash"),
        "checked": ok,
        "not_checked": {n: s.get("reason") for n, s in sorted(servers.items()) if s.get("status") != "ok"},
        "unstable": sorted(n for n in ok if servers[n].get("stable") is False),
        "unpinned": sorted(n for n, s in servers.items() if (s.get("launcher") or {}).get("pinned") is False),
        "limitation": "point-in-time check; does not see mid-session changes or client-specific tool lists",
    }
    out.update(extra or {})
    return out


# --------------------------------------------------------------------------
# compare
# --------------------------------------------------------------------------

def load_snapshot(path):
    """(doc, None) for a cerbero-mcp-snapshot/1 file, else (None, why)."""
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        return None, "missing"
    try:
        doc = json.loads(raw.decode("utf-8-sig", errors="replace"))
    except ValueError:
        return None, "legacy"
    if not isinstance(doc, dict) or doc.get("format") != FORMAT or not isinstance(doc.get("servers"), dict):
        return None, "legacy"
    return doc, None


def _leaf_diff(a, b, path=""):
    """Paths whose values differ. Lists are compared whole."""
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for k in sorted(set(a) | set(b)):
            p = "%s.%s" % (path, k) if path else str(k)
            if k not in a or k not in b:
                out.append(p)
            else:
                out.extend(_leaf_diff(a[k], b[k], p))
        return out
    return [] if canon(a) == canon(b) and type(a) is type(b) else [path]


def diff_server(old, new):
    """Changes of one server between two snapshots; {} when there are none."""
    d = {}
    o_ok, n_ok = old.get("status") == "ok", new.get("status") == "ok"
    if o_ok and not n_ok:
        d["newly_skipped"] = {"status": new.get("status"), "reason": new.get("reason")}
    if not o_ok and n_ok:
        d["newly_covered"] = True
    if n_ok and new.get("stable") is False:
        d["unstable"] = True
    if old.get("config_fingerprint") != new.get("config_fingerprint"):
        d["config_changed"] = True
    if old.get("launcher") != new.get("launcher"):
        d["launcher_changed"] = {"before": old.get("launcher"), "after": new.get("launcher")}
    if o_ok and n_ok:
        ot, nt = old.get("tools") or {}, new.get("tools") or {}
        added = sorted(set(nt) - set(ot))
        removed = sorted(set(ot) - set(nt))
        changed = []
        for name in sorted(set(ot) & set(nt)):
            if ot[name].get("hash") != nt[name].get("hash"):
                changed.append({"tool": name,
                                "fields_changed": _leaf_diff(ot[name].get("def"), nt[name].get("def")),
                                "before": ot[name].get("def"), "after": nt[name].get("def")})
        if added:
            d["added_tools"] = added
        if removed:
            d["removed_tools"] = removed
        if changed:
            d["changed_tools"] = changed
        if old.get("instructions_hash") != new.get("instructions_hash"):
            d["instructions_changed"] = {"before": old.get("instructions"), "after": new.get("instructions")}
        if (old.get("server_info") or {}).get("version") != (new.get("server_info") or {}).get("version"):
            d["server_version_changed"] = {"before": (old.get("server_info") or {}).get("version"),
                                           "after": (new.get("server_info") or {}).get("version")}
    return d


def _flags(d, new):
    flags = []
    if d.get("unstable"):
        flags.append("UNSTABLE")
    if (new.get("launcher") or {}).get("pinned") is False:
        flags.append("UNPINNED")
    if d.get("launcher_changed"):
        flags.append("LAUNCHER_CHANGED")
    paths = [p for c in d.get("changed_tools", []) for p in c["fields_changed"]]
    if any(p == "annotations" or p.startswith("annotations.") or p.startswith("_meta") for p in paths):
        flags.append("META_OR_ANNOTATIONS_CHANGED")
    if d.get("config_changed") and not d.get("launcher_changed") and len(d) == 1:
        flags.append("CONFIG_ONLY")
    return flags


def _scan(payload):
    """Run cerbero-scanner.py (same folder) on the new text, before anyone reads it."""
    scanner = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cerbero-scanner.py")
    if not os.path.isfile(scanner):
        return {"status": "NOT RUN (scanner not found next to this script)"}
    try:
        p = subprocess.run([sys.executable, scanner, "--stdin"],
                           input=json.dumps(payload, ensure_ascii=False).encode("utf-8", errors="replace"),
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60)
        rep = json.loads(p.stdout.decode("utf-8", errors="replace"))
        return {"status": "RUN", "verdict": rep["summary"]["verdict"],
                "total_findings": rep["summary"]["total_findings"],
                "finding_types": sorted(set(str(f.get("type") or f.get("category") or f.get("check") or "finding")
                                            for f in rep.get("findings") or [] if isinstance(f, dict)))}
    except Exception as e:
        return {"status": "NOT RUN (%s)" % type(e).__name__}


def cmd_compare(args):
    base, why = load_snapshot(args.baseline)
    if why == "missing":
        emit({"status": "ERROR", "error": "baseline_missing",
              "detail": "no baseline file: create one (setup-guide.md A.6)"})
        return EXIT_ERROR
    if why == "legacy":
        emit({"status": "BASELINE MIGRATION REQUIRED",
              "detail": "the baseline is not a cerbero-mcp-snapshot/1 file. Older baselines hold no tool "
                        "definitions and cannot be migrated. Review the current snapshot, then run accept: "
                        "it moves the old files to history/ and starts a new baseline (a new trust-on-first-use point)."})
        return EXIT_LEGACY
    cur, why = load_snapshot(args.current)
    if cur is None:
        emit({"status": "ERROR", "error": "current_snapshot_invalid"})
        return EXIT_ERROR

    bs, cs = base["servers"], cur["servers"]
    partial = bool(cur.get("partial"))
    full = {"added_servers": sorted(set(cs) - set(bs)),
            "removed_servers": [] if partial else sorted(set(bs) - set(cs)),
            "servers": {}}
    summary_servers = {}
    for name in sorted(set(bs) & set(cs)):
        d = diff_server(bs[name], cs[name])
        if not d:
            continue
        flags = _flags(d, cs[name])
        entry = dict(d, flags=flags)
        summ = {"flags": flags}
        for key in ("added_tools", "removed_tools", "newly_skipped", "newly_covered", "unstable", "config_changed"):
            if key in d:
                summ[key] = d[key]
        if "changed_tools" in d:
            summ["changed_tools"] = [{"tool": c["tool"], "fields_changed": c["fields_changed"]}
                                     for c in d["changed_tools"]]
        if "instructions_changed" in d:
            summ["instructions_changed"] = True
        if "server_version_changed" in d:
            summ["server_version_changed"] = True
        if "launcher_changed" in d:
            summ["launcher_changed"] = d["launcher_changed"]
        new_text = {}
        if "instructions_changed" in d:
            new_text["instructions"] = d["instructions_changed"]["after"]
        if d.get("added_tools"):
            new_text["added"] = {t: cs[name]["tools"][t]["def"] for t in d["added_tools"]}
        if d.get("changed_tools"):
            new_text["changed"] = {c["tool"]: c["after"] for c in d["changed_tools"]}
        if d.get("newly_covered"):
            # Nothing of this server was in the baseline: all of it is new text.
            new_text = {"instructions": cs[name].get("instructions"),
                        "added": {t: v["def"] for t, v in (cs[name].get("tools") or {}).items()}}
        if new_text and not args.no_scan:
            entry["scan"] = summ["scan"] = _scan(new_text)
        full["servers"][name] = entry
        summary_servers[name] = summ
    for name in full["added_servers"]:
        s = cs[name]
        summ = {"status": s.get("status"), "reason": s.get("reason"),
                "tools": sorted((s.get("tools") or {}).keys())}
        if s.get("status") == "ok" and not args.no_scan:
            summ["scan"] = _scan({"instructions": s.get("instructions"),
                                  "added": {t: v["def"] for t, v in s["tools"].items()}})
        summary_servers[name] = dict(summ, added_server=True)
        full["servers"][name] = dict(summ, added_server=True)

    changed = bool(full["servers"] or full["removed_servers"])
    summary = _coverage(cur, {
        "status": "CHANGED" if changed else "UNCHANGED",
        "baseline_generated_at": base.get("generated_at"),
        "current_generated_at": cur.get("generated_at"),
        "added_servers": full["added_servers"],
        "removed_servers": full["removed_servers"],
        "servers": summary_servers,
    })
    if args.out:
        full.update({"status": summary["status"], "baseline_generated_at": base.get("generated_at"),
                     "current_generated_at": cur.get("generated_at")})
        write_json_atomic(args.out, full)
        summary["full_diff"] = os.path.abspath(args.out)
    emit(summary)
    return EXIT_CHANGED if changed else EXIT_OK


# --------------------------------------------------------------------------
# accept
# --------------------------------------------------------------------------

BASELINE_FILES = ("mcp-inventory.json", "mcp-baseline.sha256", "baseline-date.txt")


def cmd_accept(args):
    cur, why = load_snapshot(args.current)
    if cur is None:
        emit({"status": "ERROR", "error": "current_snapshot_invalid"})
        return EXIT_ERROR
    ctx_dir = os.path.abspath(args.security_dir or os.path.join(
        os.path.abspath(args.project or os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()), ".claude", "security"))
    inv_path = os.path.join(ctx_dir, "mcp-inventory.json")
    old, old_why = load_snapshot(inv_path)
    previous_date = None
    try:
        with open(os.path.join(ctx_dir, "baseline-date.txt"), encoding="utf-8-sig", errors="replace") as f:
            previous_date = f.read().strip() or None
    except OSError:
        pass

    new = cur
    merged = False
    if cur.get("partial"):
        if old_why == "legacy":
            emit({"status": "ERROR", "error": "partial_snapshot_on_legacy_baseline",
                  "detail": "take a full snapshot (no --server) to replace a legacy baseline"})
            return EXIT_ERROR
        servers = dict(old["servers"]) if old else {}
        servers.update(cur["servers"])
        new = dict(old or cur, servers=servers, generated_at=cur["generated_at"], tool_version=TOOL_VERSION)
        merged = old is not None
    new = dict(new, partial=False)
    new["inventory_hash"] = inventory_hash(new["servers"])

    # Text that is new to the baseline goes through the Tier 0 scanner first.
    scans = {}
    old_servers = old["servers"] if old else {}
    for name, s in sorted(cur["servers"].items()):
        if s.get("status") != "ok":
            continue
        before = old_servers.get(name) or {}
        if before.get("status") == "ok" and before.get("server_hash") == s.get("server_hash"):
            continue
        scans[name] = _scan({"instructions": s.get("instructions"),
                             "tools": {t: v["def"] for t, v in (s.get("tools") or {}).items()}})
    rejected = sorted(n for n, r in scans.items() if r.get("verdict") == "REJECT")
    if rejected and not args.accept_rejected:
        emit({"status": "REFUSED", "rejected_by_scanner": rejected, "scan": scans,
              "detail": "the scanner rejects text these servers serve. Nothing was written. Review the findings; "
                        "--accept-rejected overrides, and is the user's decision"})
        return EXIT_CHANGED

    # Back up first. Old files are moved, never deleted.
    backup = None
    existing = [f for f in BASELINE_FILES if os.path.exists(os.path.join(ctx_dir, f))]
    if existing:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ("-legacy" if old_why == "legacy" else "")
        backup = os.path.join(ctx_dir, "history", stamp)
        n = 1
        while os.path.exists(backup):
            n += 1
            backup = os.path.join(ctx_dir, "history", "%s-%d" % (stamp, n))
        os.makedirs(backup)
        for f in existing:
            shutil.move(os.path.join(ctx_dir, f), os.path.join(backup, f))

    date = now_iso()
    write_json_atomic(inv_path, new)
    write_text_atomic(os.path.join(ctx_dir, "mcp-baseline.sha256"), new["inventory_hash"].split(":", 1)[1] + "\n")
    write_text_atomic(os.path.join(ctx_dir, "baseline-date.txt"), date + "\n")
    emit(_coverage(new, {"status": "BASELINE UPDATED", "previous_date": previous_date, "new_date": date,
                         "merged_partial_snapshot": merged, "replaced_legacy_baseline": old_why == "legacy",
                         "backup": backup, "servers_in_snapshot": sorted(cur["servers"].keys()),
                         "scan": scans}))
    return EXIT_OK


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(prog="cerbero-mcp-snapshot.py",
                                description="Tool-definition baseline for approved MCP servers.")
    sub = p.add_subparsers(dest="cmd")

    def common(sp):
        sp.add_argument("--project", help="project root (default: CLAUDE_PROJECT_DIR, else the current directory)")
        sp.add_argument("--security-dir", help="default: <project>/.claude/security")

    sp = sub.add_parser("pins", help="static launcher, pin and integrity report (launches nothing)")
    common(sp)
    sp.add_argument("--offline", action="store_true", help="no registry lookups")
    sp.add_argument("--server", action="append", metavar="NAME")
    sp.set_defaults(func=cmd_pins)

    sp = sub.add_parser("approve", help="record one configured server in mcp-approved.json")
    common(sp)
    sp.add_argument("name")
    sp.add_argument("--risk", required=True, choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], type=str.upper)
    sp.add_argument("--sandbox-required", action="store_true", help="implied by --risk CRITICAL")
    sp.add_argument("--version")
    sp.add_argument("--integrity", help="integrity recorded at evaluation (for example the npm dist.integrity)")
    sp.add_argument("--offline", action="store_true", help="no registry lookup")
    sp.add_argument("--allow-unverified", action="store_true",
                    help="approve a launcher this script cannot verify (unknown command, custom registry): "
                         "the user's decision, recorded in the approval")
    sp.set_defaults(func=cmd_approve)

    sp = sub.add_parser("snapshot", help="read tool definitions from approved servers")
    common(sp)
    sp.add_argument("--out", required=True, metavar="FILE")
    sp.add_argument("--server", action="append", metavar="NAME")
    sp.add_argument("--timeout", type=float, default=20.0, help="seconds per server (default 20)")
    sp.add_argument("--probe-timeout", type=float, default=5.0,
                    help="seconds to wait for server/discover before trying initialize (default 5)")
    sp.add_argument("--allow-unpinned", action="store_true",
                    help="also run launchers that are unpinned or that this script cannot verify")
    sp.add_argument("--inside-isolation", action="store_true",
                    help="this run is already inside the isolation that sandbox_required records demand")
    sp.add_argument("--trust-project", action="store_true",
                    help="snapshot .mcp.json servers although the workspace trust flag was not found")
    sp.set_defaults(func=cmd_snapshot)

    sp = sub.add_parser("compare", help="diff a snapshot against the baseline")
    sp.add_argument("--baseline", required=True, metavar="FILE")
    sp.add_argument("--current", required=True, metavar="FILE")
    sp.add_argument("--out", metavar="FILE", help="write the full diff, with before/after text, to FILE")
    sp.add_argument("--no-scan", action="store_true", help="do not run cerbero-scanner.py on the new text")
    sp.set_defaults(func=cmd_compare)

    sp = sub.add_parser("accept", help="make a snapshot the new baseline (old files move to history/)")
    common(sp)
    sp.add_argument("--current", required=True, metavar="FILE")
    sp.add_argument("--accept-rejected", action="store_true",
                    help="write the baseline although the scanner rejects text in it")
    sp.set_defaults(func=cmd_accept)
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return EXIT_ERROR
    try:
        return args.func(args)
    except Exception as e:  # never a traceback that could echo configuration
        emit({"status": "ERROR", "error": type(e).__name__})
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
