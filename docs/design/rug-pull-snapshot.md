# Rug pull detection redesign (implemented on branch `feature/rug-pull-snapshot`)

- Date: 2026-10-30
- Scope: verify flow (`.claude/skills/cerbero/op-verify-existing.md`), baseline creation (`op-evaluate-mcp.md` Step 8, `setup-guide.md` A.6), public claims (`README.md`, `SKILL.md`), hooks.
- Status: **implemented** on branch `feature/rug-pull-snapshot` (2026-11-10), not yet released. Approved by the maintainer on 2026-11-10 (section 7). Section 8 lists what the implementation re-verified and where it deviates from sections 3 to 5.
- Paths: this document was written in a private development repository with a `Cerbero/` path prefix and at version 1.2.0. Paths below are mapped to this repository's root (`hooks/`, `tests/`, `.claude/skills/cerbero/`); the release that carries this change is the next minor after 1.3.0.
- Method: docs fetched as raw markdown with `curl -sL` on 2026-10-30 and read directly. Fetched content was treated as data; no embedded instructions found. No `claude mcp list` was run and no MCP server was started.

Starting assumptions (verify before implementing):

1. A1: Claude Code docs at `code.claude.com/docs/en/*.md` reflect the installed CLI. Version gates quoted below (v2.1.x) were not checked against the local `claude --version`.
2. A2: Most servers Cerbero users approve are stdio servers launched via `npx`/`uvx`/`docker`, plus a minority of remote HTTP servers. Not measured.
3. A3: "Zero external dependencies, stdlib only, Python 3.8+" stays a hard rule (`CONTRIBUTING.md`).

---

## 1. Verified facts

Legend: **[V]** verified in the cited doc on 2026-10-30. **[I]** inferred from the doc, not stated outright. **[U]** unverified.

Sources (all fetched 2026-10-30):
`mcp.md` = https://code.claude.com/docs/en/mcp.md, `cli` = https://code.claude.com/docs/en/cli-reference.md, `hooks` = https://code.claude.com/docs/en/hooks.md, `sdk-ts` = https://code.claude.com/docs/en/agent-sdk/typescript.md, `sdk-py` = https://code.claude.com/docs/en/agent-sdk/python.md, `sdk-mcp` = https://code.claude.com/docs/en/agent-sdk/mcp.md, `env` = https://code.claude.com/docs/en/env-vars.md, `headless` = https://code.claude.com/docs/en/headless.md, `cmds` = https://code.claude.com/docs/en/commands.md, `spec26` = https://modelcontextprotocol.io/specification/2026-07-28/ (changelog, server/tools, basic/versioning, basic/transports/stdio, basic/transports/streamable-http), `spec25` = https://modelcontextprotocol.io/specification/2025-11-25/ (server/tools, basic/lifecycle).

### 1.1 CLI

| # | Fact | Tag | Source |
|---|------|-----|--------|
| F1 | `claude mcp` subcommands documented: `add`, `add-json`, `list`, `get`, `remove`, `login`, `logout`, `reset-project-choices`. None documents `--json`. (`--json` exists only on `claude agents` and `claude ultrareview`.) | V | `cli` lines 28-50, `mcp.md` "Managing your servers" |
| F2 | `claude mcp list` prints each server with a health status (`✔ Connected`, `! Needs authentication`, `✘ Failed to connect` + failure detail, warnings for whitespace/duplicate scopes/missing env vars). No tool names or descriptions are documented in its output. | V | `mcp.md` "Server status", "Connection failures" |
| F3 | Only the config-decision statuses (Pending approval, Rejected, Disabled, Blocked) are printed "without connecting to the server". So the other statuses come from a real connection attempt, i.e. `claude mcp list` already launches stdio servers. | I | `mcp.md` "Server status" |
| F4 | `/mcp [reconnect|enable|disable]` manages connections; in `-p` mode with no argument it prints a text summary of server status. No documented tool-definition dump. | V | `cmds` line 111 |
| F5 | `claude -p --output-format stream-json` emits a `system/init` message with `tools: string[]` (names only) and `mcp_servers: {name,status,source}[]`. No descriptions or schemas. | V | `sdk-ts` SDKSystemMessage; `headless` line 286 |

**Conclusion:** the current procedure is broken by design. Even if `--json` existed, the output would be server health, which changes with network state, and would never contain tool definitions. Worse (F3), it already spawns every stdio server, so the "no code execution" property it seemed to have was never real.

### 1.2 Hooks

| # | Fact | Tag | Source |
|---|------|-----|--------|
| F6 | No hook event receives a server's tool list or tool definitions. MCP tools appear in tool events (`PreToolUse`, `PostToolUse`, `PostToolUseFailure`, `PermissionRequest`, `PermissionDenied`) with `tool_name`, `tool_input`, `tool_use_id`. | V | `hooks` "Match MCP tools", "PreToolUse input" |
| F7 | MCP tool events carry `mcp_server: {name, source}` (source = `plugin`, `sdk`, `user`, `project`, ...). Requires Claude Code v2.1.274+. | V | `hooks` "PreToolUse input" |
| F8 | `SessionStart` input has no MCP data and fires before MCP servers are available. | V | `hooks` "SessionStart input", "Events that fire before MCP servers are available" |
| F9 | "Claude never sees stderr from a hook that exits 0." Stdout of PreToolUse is only written to the debug log. User-visible warning channel: JSON `systemMessage`. | V | `hooks` "Exit code 0", "JSON output" |

**Side finding (bug):** `hooks/mcp-audit.py` prints its "Consider running /cerbero verify" reminder to stderr and exits 0. Per F9 nobody sees it outside debug logs. Fix it in the same change (emit `{"systemMessage": ...}` on stdout).

### 1.3 Agent SDK

| # | Fact | Tag | Source |
|---|------|-----|--------|
| F10 | TS `query.mcpServerStatus()` / Python `ClaudeSDKClient.get_mcp_status()` return `McpServerStatus` with `serverInfo {name, version}`, `config`, `scope`, `source`, and `tools[]` of `{name, description, annotations{readOnly,destructive,openWorld}, _meta}`. **No `inputSchema`.** `_meta` is filtered to UI keys only. | V | `sdk-ts` "McpServerStatus"; `sdk-py` "McpServerStatus" |
| F11 | The SDK drives the CLI over a control protocol; docs acknowledge "a client that drives the CLI's control protocol directly" but do not document the request subtype behind `mcpServerStatus()`. | V (existence) / U (wire format) | `sdk-ts` line ~909 |
| F12 | The SDK is a pip/npm package (not stdlib). | V | `sdk-py`, `sdk-ts` |

### 1.4 Runtime behaviour that bounds any snapshot design

| # | Fact | Tag | Source |
|---|------|-----|--------|
| F13 | After connecting, Claude Code sends `tools/list`, `prompts/list`, `resources/list`. | V | `mcp.md` "Failed discovery requests" |
| F14 | On a `list_changed` notification, Claude Code silently refetches the tool list mid-session (interactive, `-p`, and SDK). | V | `mcp.md` "Dynamic tool updates" |
| F15 | Optional discovery cache for remote HTTP/SSE servers: tool list reused from a previous session for up to 4 h (cap 7 days); on-disk location not documented. | V / U (location) | `mcp.md` "Server status detail"; `env` `MCP_DISCOVERY_CACHE*` |
| F16 | Server `instructions` and tool names load into context at session start; descriptions are cut at 4,096 chars (upfront) or 16,384 (tool search) by default. | V | `mcp.md` "Tool search" section |
| F17 | Claude Code reads `_meta["anthropic/maxResultSizeChars"]`, `_meta["anthropic/requiresUserInteraction"]`, an upfront-load `_meta` flag, and tool `annotations` from `tools/list` entries. These change Claude Code behaviour, so they are security-relevant. | V | `mcp.md` lines ~1520-1750 |
| F18 | Config locations: local scope = `~/.claude.json` `projects["<path>"].mcpServers`; user scope = `~/.claude.json` top-level `mcpServers`; project = `.mcp.json`. Precedence: local > project > user > plugin > claude.ai connectors; `managedMcpServers` above all. Whole entry wins, no field merge. `${VAR}` and `${VAR:-default}` expansion in `command`, `args`, `env`, `url`, `headers`. | V | `mcp.md` "Scope hierarchy", "Environment variable expansion" |
| F19 | On this Windows machine, `~/.claude.json` project keys use forward slashes (`C:/...`). | V (local observation, key shape only) / U (documented contract) | local check 2026-10-30 |
| F20 | A cloned repo cannot approve its own `.mcp.json` servers; approvals come from non-committed settings after workspace trust. | V | `mcp.md` "Project server approvals and workspace trust" |

### 1.5 MCP protocol

| # | Fact | Tag | Source |
|---|------|-----|--------|
| F21 | Two eras now coexist. Legacy (<= `2025-11-25`): `initialize` + `notifications/initialized`, then `tools/list`. Modern (`2026-07-28`): no handshake; every request carries `_meta` `io.modelcontextprotocol/protocolVersion` and client capabilities; servers MUST implement `server/discover`. | V | `spec26` changelog items 2-3; `spec25` lifecycle |
| F22 | Dual-era client on stdio: probe `server/discover`; `DiscoverResult` or a recognized modern error means modern; any other error or timeout means legacy, fall back to `initialize`. Fallback MUST NOT key on one error code. On HTTP: try modern, inspect `400` body. | V | `spec26` stdio + streamable-http "Backward Compatibility" |
| F23 | `tools/list` is paginated (`cursor`/`nextCursor`). Modern results add required `ttlMs`, `cacheScope`, `resultType` (volatile, must not be hashed). Servers SHOULD return tools in deterministic order (not MUST). | V | `spec26` server/tools, changelog minor 3 and 5 |
| F24 | Modern spec: list endpoints "no longer vary per-connection". Legacy servers had no such rule. A malicious server ignores both. | V / I | `spec26` changelog major 1 |
| F25 | Tool fields: `name`, `title`, `description`, `icons`, `inputSchema`, `outputSchema`, `annotations`, `execution` (legacy 2025-11-25), `_meta`. Server-level `instructions` come from the `initialize` result (legacy) or the `server/discover` result (modern). | V | `spec25` lifecycle; `spec26` server/tools, server/discover |
| F26 | Modern Streamable HTTP POSTs must carry `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name` headers; SSE resumability removed. HTTP+SSE (old) transport is Deprecated. | V | `spec26` changelog, streamable-http |

---

## 2. Candidate approaches

### A. Stdlib MCP client: `tools/list` per server, out-of-band

How: new standalone script reads server configs (F18), launches each approved stdio server with `subprocess` (or POSTs to an HTTP endpoint with `urllib`), negotiates era (F22), pages through `tools/list`, captures `instructions` and `serverInfo`, normalizes, hashes, closes stdin, kills the process tree.

- Gets: full definitions, including `inputSchema` and `_meta` (the parts F10 misses). This is where most tool-poisoning payloads live (parameter descriptions, defaults, enums).
- Security cost: runs the server's code outside Claude Code. Not a new risk class versus today (F3), but new failure modes: (1) **workspace-trust bypass** if the script launches a `.mcp.json` server from a cloned, untrusted repo (F20). Must only launch servers already approved by Cerbero. (2) env handling differs from Claude Code (no `CLAUDE_PROJECT_DIR`, no `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB`), so the server may see more or fewer env vars than in a session. (3) `npx -y pkg` without a version fetches and runs the newest package at snapshot time, i.e. the snapshot itself can be the first execution of a rug-pulled version. Pin check (C) should run first and block snapshotting unpinned servers by default.
- Remote HTTP: works for no-auth and static-header servers (`${VAR}` from env). OAuth servers: tokens live in Claude Code's keychain/credentials store; reading them is out of scope (credential handling). Report `SKIPPED (oauth)`. `headersHelper` executes a configured command: skip by default. Legacy HTTP+SSE: skip in v1 (Deprecated, F26).
- Windows: `npx`/`uvx` resolve to `.cmd` shims; `subprocess` with `shell=False` cannot run them without resolving via `shutil.which`, and passing args through `cmd.exe` exposes the batch-file argument-injection class (BatBadBut, 2024; Python documents this as a caller responsibility, **[U] re-check current Python docs**). Mitigation: resolve with `shutil.which`; for `.cmd`/`.bat` targets only allow args matching `^[A-Za-z0-9@/._:=+-]+$`, else skip with reason. Process tree: `npx` spawns `node`; kill with `taskkill /T /F /PID` (or a Job Object via `ctypes`, stdlib). Python 3.8 compatible.
- Stdlib feasibility: yes (`subprocess`, `json`, `threading` for timeouts, `urllib.request`, `hashlib`). Estimated 400-550 lines. HTTP SSE response parsing (Streamable HTTP may answer with `text/event-stream`) needs a small line parser.
- Detects: added/removed tools, changed description/params/schemas/annotations/_meta, changed instructions, `serverInfo.version` drift, between two points in time.
- Cannot detect: (1) client-differential cloaking (server inspects `clientInfo` or env and shows benign tools to Cerbero); (2) per-session randomization (snapshot vs session differ; partially caught by taking N=2 snapshots and flagging instability); (3) mid-session `list_changed` swaps (F14); (4) behaviour changes behind identical definitions (tool output injection is `validate-tool-output.py`'s job); (5) plugin servers, claude.ai connectors, managed servers (configs not in the files we read, F18); (6) OAuth remote servers.

### B. Leverage Claude Code natively

- B1 `claude mcp list` / `get`: no tool data (F2). **Dead.**
- B2 Hooks: no tool lists (F6). Useful only as a runtime tripwire: `PreToolUse` on `mcp__.*` checks `tool_name` against the baseline's tool set for that server and warns via `systemMessage` (F9) or returns `permissionDecision: "ask"` for a tool never seen at approval. Stdlib, no spawn, fail-open, cheap. Detects new tools at first call, including mid-session additions (F14) that A misses. Does not detect description changes.
- B3 `claude -p --output-format stream-json` init: tool names only (F5). Needs a prompt and probably an API call **[U]**: no documented way to stop after `init` without a model turn. Weak; skip.
- B4 Agent SDK `mcpServerStatus()`: same server resolution, env, OAuth, plugins, connectors as a real session (big plus, closes gaps 5 and 6 of A, and kills cloaking-by-client). But no `inputSchema` (F10), `_meta` filtered, not stdlib (F12). Could be an **optional** extended mode if the maintainer relaxes A3 for opt-in tooling. Whether descriptions there are pre- or post-truncation (F16) is **[U]**.
- B5 Drive the CLI control protocol directly from stdlib Python (F11): would give B4's data without the SDK package, but the wire format for MCP status is undocumented **[U]**. Do not build on it until documented.
- B6 Ask Claude in-session to list the tool definitions it sees: model-mediated, truncated (F16), deferred by tool search, not reproducible. Rejected for hashing.

### C. Pin and integrity check (static, no spawn)

How: parse each approved server's `command`/`args` and classify the launcher: `npx`/`npm exec` (`pkg@version`), `uvx`/`pipx run` (`pkg==version`), `docker run` (`image@sha256:`), local path (hash the file or dir manifest), remote URL (nothing to pin). Compare with the approved record from `op-evaluate-mcp` Step 8.2 and optionally fetch registry integrity via `urllib` (`registry.npmjs.org/<pkg>/<ver>` `dist.integrity`, `pypi.org/pypi/<pkg>/<ver>/json` digests).

- Security cost: none for code execution. Network only to package registries; `--offline` skips registry lookups.
- Windows: trivial. Stdlib: yes.
- Detects: unpinned launchers (the most common real rug-pull path for stdio servers: a malicious new release picked up by `npx -y pkg`), version drift vs approval, registry integrity mismatch for the approved version (republish or registry tampering).
- Cannot detect: changes inside a pinned version that fetches descriptions remotely at runtime; remote servers; npx cache poisoning **[U]** (cache layout not examined).

### D. Reduce the claim

If A is rejected: drop "Detects rug pulls" and say "Detects unpinned or drifted MCP server versions (supply-chain rug pulls) and warns on never-approved MCP tools at call time" (C + B2). Honest and still useful, but loses description-level detection, which is the headline threat in the README.

### Comparison

| | Tool defs incl. schemas | Code execution | OAuth/plugins/connectors | Mid-session changes | Stdlib | Windows |
|---|---|---|---|---|---|---|
| A stdlib client | Yes | Yes (approved servers only) | No | No | Yes | Yes, with `.cmd` care |
| B2 hook tripwire | Names only, at call | No | Yes (sees all calls) | New tools only | Yes | Yes |
| B4 Agent SDK | No schemas | Yes (via CC) | Yes | No | No | Yes |
| C pin check | No | No | N/A | N/A | Yes | Yes |
| D reduce claim | - | - | - | - | - | - |

---

## 3. Recommendation

Ship **A + C + B2** as three layers, and narrow the public claim to what they actually cover.

1. **C first, always** (`pins`): static, cheap. Unpinned launcher = finding `UNPINNED` (SUSPICIOUS) and blocks A for that server unless `--allow-unpinned`.
2. **A for approved servers** (`snapshot` + `compare`): the actual tool-definition baseline. Two consecutive `tools/list` calls per server (same connection for legacy, two requests for modern); differing results = `UNSTABLE` finding.
3. **B2 runtime tripwire** in `mcp-audit.py`: unknown tool for a baselined server, or unknown server, gives a `systemMessage` warning. No blocking by default (fail-open stays).
4. B4 documented as an optional future extension, not built now.

Rejected: B1, B3, B5 (undocumented), B6.

### Canonical snapshot format (`format: "cerbero-mcp-snapshot/1"`)

```json
{
  "format": "cerbero-mcp-snapshot/1",
  "generated_at": "2026-10-30T18:00:00Z",
  "tool_version": "1.3.0",
  "inventory_hash": "sha256:<hex>",
  "servers": {
    "<server-name>": {
      "status": "ok | skipped | error",
      "reason": "oauth | headers_helper | unpinned | not_approved | not_covered_source | timeout | spawn_failed | protocol_error | null",
      "scope": "local | project | user",
      "transport": "stdio | http",
      "protocol": {"era": "modern | legacy", "version": "2026-07-28"},
      "config_fingerprint": "sha256:<hex>",
      "launcher": {"kind": "npx | uvx | docker | path | url | other", "spec": "@scope/pkg@1.2.3", "pinned": true},
      "server_info": {"name": "...", "version": "..."},
      "instructions": "<full text>",
      "instructions_hash": "sha256:<hex>",
      "tools": {
        "<tool-name>": {"hash": "sha256:<hex>", "def": { "name": "...", "description": "...", "inputSchema": {}, "...": "..." }}
      },
      "stable": true,
      "server_hash": "sha256:<hex>"
    }
  }
}
```

Canonicalization `C(x)`: `json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`. No Unicode normalization, no whitespace trimming: zero-width, tag and homoglyph changes must change the hash. Lists keep server order except the tool list, which becomes a dict keyed by `name` (duplicate names = `PROTOCOL_ERROR` finding). Not full RFC 8785 JCS (float formatting differs), acceptable because both sides are produced by the same Python code from the same parse.

- **Tool hash** = `sha256(C(def))` where `def` keeps exactly: `name`, `title`, `description`, `inputSchema`, `outputSchema`, `annotations`, `execution`, `icons`, `_meta`. Unknown future keys are kept too (fail-closed: new field = visible diff). `_meta` is kept whole because Claude Code acts on some keys (F17).
- **Excluded** (volatile or transport-level): list `nextCursor`, `ttlMs`, `cacheScope`, `resultType`, result-level `_meta`, `generated_at`, `tool_version`, `status`/`reason` text, `protocol.version`.
- **Server hash** = `sha256(C({"tools": {name: tool_hash}, "instructions_hash": ..., "server_info": ..., "config_fingerprint": ..., "launcher": ...}))`.
- **config_fingerprint** = `sha256(C(entry))` of the resolved config entry with every `env` and `headers` value replaced by `sha256(value)` (secrets never stored in plaintext; a changed token changes the fingerprint, reported as BENIGN-by-default `config` change).
- **inventory_hash** = `sha256(C({name: server_hash}))` over `ok` servers; skipped servers listed but not hashed (reported every run as coverage gaps).
- `mcp-baseline.sha256` stores `inventory_hash` (hex only) for a quick equality check; `compare` always does the per-server and per-tool diff, so the sha file is a convenience, not the source of truth.

Diff report (JSON, consumed by the skill for Step 3 classification): per server `added_tools`, `removed_tools`, `changed_tools[{tool, fields_changed[], before, after}]`, `instructions_changed`, `server_version_changed`, `config_changed`, `newly_skipped`, `unstable`. Changed text is piped to `cerbero-scanner.py --stdin` so Tier 1 patterns run deterministically before Claude reads the new text.

---

## 4. Change list

Version: the next minor release (new script, changed artifact format). Bump the version markers that `tests/test_versions.py` checks.

### New: `hooks/cerbero-mcp-snapshot.py` (standalone, not a hook)

Separate from `cerbero-scanner.py` to keep the Tier 0 scanner small and free of process spawning. Subcommands:

```
pins     [--offline] [--server NAME]...                     static launcher/pin/integrity report (C)
snapshot --out FILE [--server NAME]... [--timeout 20] [--allow-unpinned]
compare  --baseline FILE --current FILE                     exit 0 unchanged, 1 changed, 2 error, 3 legacy baseline
accept   --current FILE                                     backs up old baseline to .claude/security/history/<ts>/, then writes inventory, sha256, date
```

Rules: stdlib only, Python 3.8+; only servers present in `.claude/security/mcp-approved.json` (see below) are launched, everything else is `skipped/not_approved`; plugin, connector and managed sources are `skipped/not_covered_source`; never print or store env/header values; per-server timeout and 5 MB response cap; stdout lines that are not JSON-RPC are ignored and counted; stdin closed then tree-kill on exit; `-I` friendly (no imports from cwd).

### New runtime artifact: `.claude/security/mcp-approved.json`

`{name: {launcher_spec, version, integrity, risk, sandbox_required, approved_at, config_fingerprint}}`. Written by `op-evaluate-mcp` Step 8.2 (today "record approved version" has no defined location). This is the launch allowlist for `snapshot` and the reference for `pins`.

### `op-verify-existing.md`

- Step 1: replace the `claude mcp list --json` block with `pins` then `snapshot --out "$env:TEMP/mcp-current-inventory.json"`. Report skipped servers as coverage gaps.
- Step 2: replace Get-FileHash comparison with `compare`; branch on exit code (3 = legacy baseline, see compat).
- Step 3: consume the diff JSON instead of a free-form file diff; pipe changed text to `cerbero-scanner.py --stdin`. Add classification rows: `UNPINNED` and `UNSTABLE` = SUSPICIOUS; removed `requiresUserInteraction` or changed `annotations.destructive`/`readOnly` = SUSPICIOUS; `config` fingerprint-only change = BENIGN unless command/args changed.
- Step 5: report adds `Coverage: <n> servers checked, <m> skipped (<reasons>)` and a fixed limitation line ("point-in-time check; does not see mid-session changes or client-specific tool lists").
- Step 6: use `accept`; keep the "ALWAYS notify" rule.

### `op-evaluate-mcp.md` Step 8

- 8.1: require a pinned version in the install command (no bare `npx -y pkg`).
- 8.2: write the entry to `mcp-approved.json` (with integrity) **before** 8.4.
- 8.4: replace the `claude mcp list --json` block with `snapshot --server <name>` merged into the baseline via `accept`. Keep the notify line.
- Step 4b: note that `<tool-definitions.json>` for post-install re-evaluation can come from `snapshot` output (pre-install stays static source review; do not launch unevaluated servers).

### `op-full-audit.md`

Step 2 unchanged (delegates to verify). Report section 2 adds `Coverage` and `Pins` lines. Step 4 adds: every `enabledMcpjsonServers` entry has an `mcp-approved.json` record.

### `SKILL.md`

- Runtime artifacts block (~line 39-45): `mcp-inventory.json` = "baseline: normalized tool definitions per approved server (cerbero-mcp-snapshot/1)"; add `mcp-approved.json`; add `history/`.
- Hook scripts block: add `cerbero-mcp-snapshot.py <-- MCP tool-definition snapshot (not a hook)`.
- Detection tiers: "Hash comparison against baseline" stays Tier 1 (compare is fast) but add a line that taking the snapshot launches approved servers and is not < 100 ms.

### `setup-guide.md`

- A.4b: deploy the new script.
- A.6: replace with `pins`, `snapshot`, `accept`, plus a one-time step to create `mcp-approved.json` for already-installed servers (human confirms each one; this is the TOFU moment).
- A.8 checklist: add pinned launchers and `mcp-approved.json`.

### `hooks/mcp-audit.py`

- Fix F9 bug: reminder via `{"systemMessage": ...}` on stdout, not stderr.
- Tripwire (B2): if `.claude/security/mcp-inventory.json` is format `/1`, warn via `systemMessage` when `tool_name` is not in the baseline for its server (use `mcp_server.name` when present, F7, else parse `mcp__<server>__`). Cache the parsed tool set by baseline mtime to stay cheap. Fail-open on any error. No blocking by default; `permissionDecision: "ask"` behind an opt-in env var is an open question.

### `README.md` claims

| Line | Today | Proposed |
|---|---|---|
| 5 | "...supply chain attacks, rug pulls, and known CVEs." | Keep "rug pulls" only if A ships; otherwise "unpinned/drifted MCP versions". |
| 87 | "SHA-256 baseline comparison catches silent updates to MCP server tool descriptions." | "Snapshots each approved MCP server's tool definitions (`tools/list`: descriptions, parameter schemas, annotations) and reports per-tool drift since approval. Also flags unpinned or drifted package versions. Point-in-time: it cannot see changes a server makes mid-session or serves only to other clients, and skips OAuth, plugin and claude.ai connector servers." |
| 161 | "to detect changes to tool descriptions" | "to detect changes to tool definitions" |
| 233 | keep | keep |
| 303 | "...and provides rug pull detection." | "...and provides point-in-time rug pull detection for stdio and static-auth HTTP servers." Also "5 automation hooks plus a standalone pre-context scanner" becomes "plus two standalone scripts". |

Also: `CHANGELOG.md` entry for the next minor (Fixed: broken `claude mcp list --json` baseline; invisible mcp-audit reminder. Added: snapshot script, pin check, tripwire). The private repository's `CLAUDE.md` items (smoke commands, architecture note) have no counterpart here: this repository has no `CLAUDE.md`.

### Backward compatibility

- Existing `mcp-inventory.json` was produced by an undocumented flag: it is plain text, an error message, or JSON of health status. It contains no tool definitions, so it **cannot be migrated** and must not be silently trusted.
- `compare` detects it (missing or different `format` field) and exits 3. The skill reports `STATUS: BASELINE MIGRATION REQUIRED` (not UNCHANGED, not CHANGED), explains why, and on human confirmation runs `accept`, which first moves `mcp-inventory.json`, `mcp-baseline.sha256`, `baseline-date.txt` to `.claude/security/history/<ts>-legacy/` (backup, never delete).
- File names stay the same, so external references (user CLAUDE.md files, Ignite) keep working; the content of `mcp-baseline.sha256` changes meaning (inventory hash, not file hash), documented in CHANGELOG.
- The first `/1` baseline is a new TOFU point: if a server was already rug-pulled before migration, the baseline captures the bad state. The migration report must say so and recommend re-running `op-evaluate-mcp` for HIGH/CRITICAL servers.

---

## 5. Test plan (no third-party servers)

Location: `tests/` (stdlib `unittest`, run with `python -m unittest discover -s tests`). Shipped in this repository (decision 8).

Fixtures:

- `fixtures/fake_mcp_server.py`: stdlib stdio server. Flags: `--era legacy|modern|dual`, `--tools FILE` (definitions JSON), `--instructions TEXT`, `--paginate N`, `--shuffle` (random tool and key order), `--random-per-session`, `--sniff-client` (benign tools unless `clientInfo.name` contains "claude"), `--emit-list-changed`, `--stdout-noise`, `--hang` (never replies), `--ignore-eof` (does not exit on stdin close, spawns a child to test tree-kill), `--huge` (exceeds size cap), `--sentinel PATH` (touches a file when launched, to prove a server was or was not executed), `--ttl-vary` (different `ttlMs`/`cacheScope` each call).
- `fixtures/fake_mcp_http.py`: `http.server` Streamable HTTP endpoint on `127.0.0.1:0`; JSON and `text/event-stream` response variants; `--require-auth` returns 401 with OAuth metadata; modern `400` with `UnsupportedProtocolVersionError` body.
- `fixtures/tools/*.json`: base set, plus mutations: description typo, new imperative sentence, parameter description injection, new enum value, default change, tool added, tool removed, `_meta.anthropic/requiresUserInteraction` removed, zero-width char added, tag-char smuggling.
- Fake config roots: temp dir with `.mcp.json`, fake home with `.claude.json` (forward-slash and backslash project keys), `HOME`/`USERPROFILE` overridden.

Cases:

1. Canonicalization: `--shuffle` and `--ttl-vary` give identical `inventory_hash` across runs.
2. Each mutation changes exactly the expected tool hash and `fields_changed`; zero-width/tag cases also produce `cerbero-scanner.py` findings.
3. Era handling: legacy, modern, dual all yield the same tool hashes; legacy server answering `server/discover` with `-32601`, `-32602`, or silence all fall back.
4. Pagination: 3 pages merged; cursor loop guard (server returns same cursor) ends with `protocol_error`.
5. Safety gates: server absent from `mcp-approved.json` is not launched (sentinel absent); unpinned `npx` spec skipped without `--allow-unpinned`; `.cmd` target with metacharacter args skipped (Windows only, `skipUnless`).
6. Robustness: `--hang` hits timeout, `--ignore-eof` child is killed (no leftover PID), `--huge` capped, `--stdout-noise` tolerated.
7. Known-limitation tests (assert the documented blind spot, so the README stays honest): `--sniff-client` is NOT detected; `--random-per-session` IS flagged `UNSTABLE`.
8. HTTP: no-auth OK; 401 gives `skipped/oauth`; SSE response parsed; header values never appear in output files.
9. Compat: legacy baseline (plain text, health JSON, empty) gives exit 3; `accept` moves old files to `history/` and never deletes.
10. `pins`: `pkg`, `pkg@latest`, `pkg@1.2.3`, `uvx pkg==1.0`, `docker image:tag`, `image@sha256:` classified correctly; `--offline` makes no network calls (patch `urllib.request.urlopen` to raise).
11. `mcp-audit.py` tripwire: known tool silent, unknown tool emits valid single-object JSON with `systemMessage`; corrupt baseline exits 0 with no output.
12. Static: grep that new files import only stdlib (extend the existing coupling grep); run all under Python 3.8 (`py -3.8` if available) and current Python; Windows and one POSIX run.

Manual (maintainer, optional, after code review): one real pinned server from a trusted publisher in a throwaway project, compared against what `/mcp` shows.

---

## 6. Open questions for the maintainer

1. Accept that `snapshot` executes approved server code outside Claude Code, given `claude mcp list` already does (F3)? Or require it to run inside the same isolation as Claude Code for HIGH/CRITICAL servers (`sandbox_required`)?
2. Is an optional, non-stdlib extended mode via Agent SDK `mcpServerStatus()` (B4) acceptable, to cover OAuth, plugin and connector servers? It would be the only way to see what Claude Code itself sees, but lacks schemas.
3. Should the tripwire be allowed to return `permissionDecision: "ask"` (opt-in) or stay warn-only?
4. Unpinned launchers: SUSPICIOUS finding only, or block approval in `op-evaluate-mcp` outright?
5. Cloaking by `clientInfo`: send a neutral `clientInfo` (`cerbero-snapshot`) and document the gap, or mimic Claude Code's identity (exact value **[U]**, and arguably deceptive)?
6. Do `mcp-approved.json` records already exist somewhere in Ignite or user projects, or is 8.2 "record approved version" currently unrecorded in practice?
7. Run `snapshot` automatically (e.g. async `SessionStart` hook), or keep it manual via `/cerbero verify`? Automatic doubles server launches per session.
8. Ship `tests/` in the public product, or keep them in the dev repo only?
9. Should the docs-version assumptions (v2.1.274+ for `mcp_server`) become a minimum Claude Code version in `setup-guide.md`?
10. Modern servers return `instructions` from `server/discover` (F25). Should `snapshot` always call `server/discover` on modern servers even when not needed for era detection (HTTP path), so `instructions` are hashed for both transports? Recommended: yes.

---

## 7. Maintainer decisions (2026-11-10)

The maintainer answered the ten questions of section 6. The design is approved for implementation with these answers; the status in the title changes only when the code ships.

1. **Running approved servers outside Claude Code**: accepted, for approved servers only. A server whose approval record carries `sandbox_required` is skipped (`skipped/isolation`) unless `snapshot` runs inside that isolation; the operator states it with an explicit flag.
2. **Agent SDK extended mode (B4)**: not built. Stdlib-only stays a hard rule; B4 remains documented as a future option.
3. **Tripwire**: warn-only by default. `permissionDecision: "ask"` is opt-in through an environment variable.
4. **Unpinned launchers**: `UNPINNED` is a SUSPICIOUS finding, `snapshot` skips the server without `--allow-unpinned`, and `op-evaluate-mcp` does not approve a server until its version is pinned.
5. **`clientInfo`**: neutral (`cerbero-snapshot`). The cloaking gap is documented as a known limitation; Cerbero does not imitate Claude Code's identity.
6. **Existing `mcp-approved.json` records**: none found on the maintainer's machine on 2026-11-10 (project and user `.claude/security/` folders). It is a new artifact, created in a one-time step the user confirms.
7. **When `snapshot` runs**: manually, through `/cerbero verify`. No automatic `SessionStart` snapshot.
8. **Tests**: shipped in the public repository, next to the existing `tests/`.
9. **Minimum Claude Code version**: stated in `setup-guide.md` (v2.1.274 for `mcp_server`), after re-checking assumption A1 against the installed CLI.
10. **`server/discover`**: always called on modern servers, so `instructions` are hashed on both transports.

Before implementing, re-verify section 1 against the current vendor pages and the installed CLI: the facts there are dated 2026-10-30.

---

## 8. Implementation notes (2026-11-10)

### 8.1 Re-verification of section 1

Done on 2026-11-10 against the installed CLI (Claude Code 2.1.321, the build bundled with the desktop app; `claude` is not on PATH on the maintainer's machine) and the same vendor pages, fetched again as raw markdown. No `claude mcp list` was run and no MCP server was started for the verification.

| Fact | Result |
|------|--------|
| F1 | Holds. `claude mcp list --help` on 2.1.321 shows one option, `-h`. `cli-reference.md` documents `--json` only for `claude agents` and `claude ultrareview`. |
| F2, F3 | Hold, and F3 is now stated by the CLI itself: the `list` and `get` help texts say approved servers "are health-checked" and unapproved `.mcp.json` servers are "not connected to". |
| F4, F5 | Hold (`commands.md` `/mcp` row; `headless.md` `mcp_servers` with `name` and `status`). |
| F6 to F9 | Hold. `mcp_server` still requires v2.1.274; "Claude never sees stderr from a hook that exits 0" is unchanged, and the hooks page now recommends `systemMessage` on stdout for a `PreToolUse` warning. |
| F10 to F12 | Not re-read in full; `mcpServerStatus()` and `McpServerStatus` are still documented. Nothing here depends on them (B4 was not built). |
| F13 to F18, F20 | Hold. New detail used by the implementation: `projects["<path>"].hasTrustDialogAccepted` in `~/.claude.json` is the documented workspace-trust flag. |
| F19 | Holds on the maintainer's machine, with one addition: the same project can appear under both `C:/...` and `c:/...` keys, so keys are matched case-insensitively on Windows. |
| F21 to F26 | Hold. Details used by the implementation: the modern error codes are `-32020` (HeaderMismatch), `-32021` (MissingRequiredClientCapability) and `-32022` (UnsupportedProtocolVersion); a modern HTTP server answers an unknown method with `404` and `-32601`; `serverInfo` of a modern server is in `_meta["io.modelcontextprotocol/serverInfo"]` of the `server/discover` result. |

Assumption A1 (docs reflect the installed CLI) holds for 2.1.321. A2 was not measured.

### 8.2 Deviations from sections 3 to 5

| # | Deviation | Why |
|---|-----------|-----|
| D1 | A fifth subcommand, `approve`, writes the `mcp-approved.json` record. | The record needs two SHA-256 fingerprints of the configuration entry. An agent or a person cannot compute those by hand; without a command, Step 8.2 would have no reliable way to write the allowlist. `approve` also enforces decision 4 (it refuses an unpinned launcher). |
| D2 | The record carries two more fields, `launch_fingerprint` and `scope`, and `snapshot` skips a server whose command, args, URL or `env` block differ from the record (`skipped/launch_changed`). See 8.4 item 1 for what the fingerprint covers. | The allowlist is keyed by server name. Without this, editing the command of an approved name would make the snapshot run different code than the one approved. `config_fingerprint` alone cannot gate this: it also changes when a header token rotates. |
| D3 | Servers from a project `.mcp.json` are skipped unless the folder passed Claude Code's trust dialog (`hasTrustDialogAccepted`), with `--trust-project` as the override (`skipped/untrusted_workspace`). | Narrows the workspace-trust bypass named in section 2A. It does not close it by itself: the trust flag is not an approval of a server. 8.4 item 3 closes it. |
| D4 | More skip and error reasons than the format lists: `isolation` (decision 1), `launch_changed`, `untrusted_workspace`, `unsupported_transport` (SSE, WebSocket), `unsafe_args` (Windows batch launcher), `too_large` (5 MB cap), `unreachable`, `auth_failed`, and after the review `approval_not_local`, `invalid_record`, `integrity_mismatch`, `disabled`. | Each is a distinct cause the report has to name. `oauth` is used for a `401` without a configured `Authorization` header; a `401`/`403` with one is `auth_failed`, as Claude Code treats it. |
| D5 | `config_fingerprint` hashes the entry as written, before `${VAR}` expansion. | A rotated secret referenced as `${TOKEN}` should not change the fingerprint; a literal one does, as designed. Expanding first would also make the fingerprint depend on the shell the check runs in. |
| D6 | `launcher` has an `integrity` field for local-file launchers (SHA-256 of the script), and it is part of the server hash. | Section 2C asks to hash local paths; putting it in `launcher` makes a changed local server show up in `compare` as well as in `pins`. |
| D7 | `compare` prints a summary without definition text and writes the full before/after diff to `--out`; it runs `cerbero-scanner.py` itself. Paths in `fields_changed` go down to the leaf (`inputSchema.properties.query.description`). | The design wants the scanner to run before Claude reads new text. A summary that carries no server-controlled prose, plus a scan verdict, lets the skill decide whether to open the full diff at all. |
| D8 | Snapshots carry `partial` (true when `--server` was used); `accept` merges a partial snapshot into the baseline and `compare` does not report the other servers as removed. | Needed by `op-evaluate-mcp` Step 8.4 ("merged into the baseline via accept"). |
| D9 | `--random-per-session` in the fixture varies the listing on every call, and a second flag, `--random-per-process`, varies it per launch. Per-launch variation is reported as CHANGED on every check, not as `UNSTABLE`. | The two listings are taken on one connection (section 3). A server that is stable within a process cannot be told apart from a changed one by two calls; the test asserts what is actually detected. |
| D10 | The tripwire warns once per session for each server or tool, and `ask` mode asks only for an unknown tool of a baselined server (every call); an unknown or unread server only warns. `CERBERO_TRIPWIRE=off` disables it. | Plugin and connector servers are never in the baseline: a warning or a prompt on every one of their calls would train the user to ignore it. |
| D11 | Mutation fixtures are built at test time from `tests/fixtures/tools/base.json`; no mutation file is committed. | Repository convention (see `tests/test_cli.py`): text a detector should flag, and invisible characters, are assembled at runtime so the repository does not carry them. |
| D12 | The HTTP fixture runs in a thread of the test process (a module with `start()`), not as a separate script with flags. | Simpler, and it lets tests read the requests the server received. |
| D13 | No Job Object on Windows: the process tree is killed with `taskkill /T /F` while the server is alive. | A server that exits on end-of-input and leaves a detached child behind is not cleaned up on Windows. Known limitation, stated in the README. |
| D14 | CHANGELOG entry is headed `[Unreleased]`; the version markers stay at 1.3.0, and `TOOL_VERSION` of the new script joins the markers `tests/test_versions.py` checks. | The release, version bump and tag are the maintainer's. |

### 8.3 Not tested

- A real MCP server of any kind: tests start only the fixtures in `tests/fixtures/`. The optional manual check at the end of section 5 is still open.
- A real remote HTTP server: TLS, proxies, redirects (refused by design), and an OAuth-protected server beyond the fixture's `401`.
- A real `npx`, `uvx` or `docker` launch, and `--allow-unpinned`. The registry lookups of `pins` and `approve` were tested with a patched `urlopen` only, never against npm or PyPI.
- Python 3.8 to 3.11, and macOS: the suite ran on Windows 11 (Python 3.14 and 3.13) and on Ubuntu under WSL (Python 3.12). Python 3.8 compatibility is checked statically only (`ast.parse(..., feature_version=(3, 8))`). CI runs Ubuntu with 3.10 to 3.12 on push.
- The legacy HTTP+SSE transport and WebSocket: skipped by design.
- The tripwire inside a live Claude Code session (that `systemMessage` and `permissionDecision: "ask"` render as documented) and the skill documents driven by a live `/cerbero verify`.

### 8.4 Review fixes (2026-11-11)

An independent review of the first implementation found defects in the launch gates. Each was reproduced with a failing test in `tests/test_mcp_gates.py` before the fix. Where a fix changes sections 3 to 5 or the notes above, this section is the current behaviour.

| # | Defect | Outcome |
|---|--------|---------|
| 1 | `env` was outside `launch_fingerprint`: an env-only edit after approval (`PATH`, `PYTHONPATH`, `NODE_OPTIONS`, `LD_PRELOAD`, or a variable used in `command`/`args`) changed what ran, passed the gate and was reported `CONFIG_ONLY`. | **Fixed.** The fingerprint covers `command`, `args`, `url` as written, the same after `${VAR}` expansion, and the whole `env` block (names and a hash of each value as written). No variable name is exempt: a list of dangerous names would always be incomplete. `${VAR}` in `command`/`args` now expands from the environment of the run only, as in Claude Code, not from the entry's own `env`. Cost: editing a literal `env` value needs a new approval; a secret referenced as `${TOKEN}` inside `env` rotates freely. `CONFIG_ONLY` now means a header change, or an env change the user has approved again. |
| 2 | A credential in a launcher spec leaked: `uvx --from git+https://TOKEN@host/...@1.0.0` counted as pinned, was sent to pypi.org, and was written to the approval record, snapshots and stdout. Same for URL paths and for `args[0]` of unknown launchers. | **Fixed.** Pinned requires a registry-style package name. `registry_integrity` re-checks that itself and sends nothing else. Every stored spec goes through `redact()`: a URL is cut to `scheme://host[:port]`, an unknown launcher is stored as its command only, a secret-looking `--flag=value` loses its value. The `url` launcher spec is the origin; a changed path is still caught by `launch_fingerprint`. |
| 3 | The workspace trust flag was treated as approval of project servers, and `enabledMcpjsonServers` / `disabledMcpjsonServers` were never read. A cloned repository could ship `.mcp.json` plus a matching `mcp-approved.json`. | **Fixed, by a different route than the enabled list.** Vendor docs (`mcp.md`, "Project server approvals and workspace trust", re-read 2026-11-11): approvals live in settings files, and Claude Code trusts an in-repository one only after a git "is it tracked" check. Decision: an approval file inside the project cannot be trusted at all. `approve` also writes the record's hash to `~/.claude/security/cerbero-approvals.json`, keyed by project path, and `snapshot` skips any record without that entry (`approval_not_local`), whatever the scope and whatever `--trust-project` says. A hand-edited record fails the same check. `disabledMcpjsonServers` from any settings file is honoured (`disabled`). `enabledMcpjsonServers` is deliberately **not** required: `op-evaluate-mcp` takes the first snapshot (Step 8.4) before the server is enabled (Step 8.5), and the local anchor is already a per-server decision by the user. |
| 4 | On Windows `shutil.which` searches the current directory before `PATH`, so a repository with `npx.cmd` at its root hijacked a user-scope server. | **Fixed.** `resolve_command` searches the absolute entries of `PATH` only, on every OS; empty and relative entries and the current directory are skipped. |
| 5 | Pin check holes: `npx pkg@1.2` passed; launchers classified `pinned: None` passed approve and snapshot; `--with other` and `--registry=` were ignored. | **Fixed.** npm needs `x.y.z`. `uv run`, `yarn dlx`, `bun x`, `deno run npm:/jsr:/URL`, `node .../npx-cli.js` are classified; `--with` packages must be pinned too; `--with-requirements` and `--with-editable` are unpinned. A custom registry or index (flag or env name) and any unknown command are `pinned: None`, and `None` no longer passes: `approve` refuses with `UNVERIFIED_LAUNCHER` unless the user passes `--allow-unverified`, which is recorded, and `snapshot` skips it otherwise. Git references pinned to a commit are treated as unpinned (not implemented). |
| 6 | Approval records failed open: no `launch_fingerprint` meant "launch", and `risk: CRITICAL` without `sandbox_required` ran outside isolation. | **Fixed.** `invalid_record` for a record without a well-formed `launch_fingerprint` or a valid `risk`; CRITICAL always needs `--inside-isolation`. |
| 7 | `snapshot` did not compare the recorded integrity before launching, so a modified approved local script ran first and was reported afterwards. | **Fixed** for local files (`integrity_mismatch`, not launched). **By design** for npm and PyPI packages: the registry comparison stays in `pins`, which runs first in every operation, because `snapshot` makes no registry request. |
| 8 | Hangs: a stdio write could block for ever on a server that floods output and never reads; HTTP had only a per-read timeout. | **Fixed.** Writes run under the per-server deadline; a `nextCursor` over 4,096 characters is a protocol error; the whole HTTP exchange runs under one deadline with a watchdog, and the deadline is checked between reads. |
| 9a | Windows tree kill misses orphaned grandchildren. | **Limitation** (D13, README). A Job Object would fix it; not built. |
| 9b | A newly covered server was not scanned before `accept`. | **Fixed.** `compare` scans it, and `accept` scans every server new to the baseline and refuses a `REJECT` verdict without `--accept-rejected`. |
| 9c | Env and header value hashes are unsalted. | **Limitation** (README). A salt stored next to the files would not protect a file that leaks with its folder. |
| 9d | `mcp-audit.py` could still raise (`UnicodeDecodeError` in log rotation, `OSError` on stdin). | **Fixed.** Rotation works on bytes, and `main()` is wrapped: any exception exits 0. |
| 9e | The tripwire cache was keyed by mtime and size and shared across projects under one `CERBERO_LOG_DIR`. | **Fixed** for sharing (the cache sits next to the baseline) and narrowed for the key (path, `mtime_ns`, size). A rewrite that keeps all three is still not noticed: limitation. |
| 10 | The no-shell test was a substring grep. | **Fixed.** Structural (`ast`): `shell=` must be the literal `False`, no `os.system`/`os.popen`/`os.spawn*`/`os.exec*`, no unknown `**` mapping on a `subprocess` call. |

Still open after the review, by decision: files a launcher reads from the project folder (`.npmrc`, `uv.toml`), the imports of an approved local script, and the user's own environment for `${VAR}` inside `env` are not covered (README, *Rug pull detection limits*).
