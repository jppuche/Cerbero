# Changelog

## [Unreleased] - planned as 1.4.0

Rug pull detection redesign (design: `docs/design/rug-pull-snapshot.md`). The four version markers stay at 1.3.0 until release.

### Fixed
- **The rug pull baseline never held tool definitions.** `/cerbero verify`, `op-evaluate-mcp` Step 8 and `setup-guide.md` A.6 built it with `claude mcp list --json`. That flag does not exist, and the command's output is server health, which changes with the network and contains no tool description. Every call to it is removed
- **`mcp-audit.py` reminder was invisible.** The "consider running /cerbero verify" reminder went to stderr with exit 0, which Claude Code discards. It is now a `systemMessage` in one JSON object on stdout

### Added
- **`hooks/cerbero-mcp-snapshot.py`** (a script, not a hook; stdlib only). `pins`: static launcher check (`UNPINNED`, `VERSION_DRIFT`, `LAUNCH_CHANGED`, `INTEGRITY_MISMATCH`), with an optional npm/PyPI integrity lookup (`--offline` disables it). `approve`: writes a server's approval record and refuses an unpinned launcher. `snapshot`: connects to each approved server (stdio, or Streamable HTTP with static headers; `initialize` and 2026-07-28 protocol eras), reads its instructions and every page of `tools/list` twice, and writes a normalized `cerbero-mcp-snapshot/1` file. `compare`: per-server, per-tool, per-field diff with the Tier 0 scanner run on the new text (exit 0 unchanged, 1 changed, 2 error, 3 legacy baseline). `accept`: moves the old baseline to `.claude/security/history/<timestamp>/` and writes the new one; a single-server snapshot is merged
- **`.claude/security/mcp-approved.json`**: the approval record per server (launcher, version, integrity, risk, `sandbox_required`, date, configuration fingerprints). It is the launch allowlist, and every gate fails closed. `snapshot` never starts a server without a record; with a record that `approve` did not write on this machine (its hash is anchored in `~/.claude/security/cerbero-approvals.json`, so an approval file shipped with a repository approves nothing) or that lacks a field; with a changed command, argument, URL or `env` block; whose local file changed; from an untrusted workspace or rejected by `disabledMcpjsonServers`; unpinned or unverifiable (without `--allow-unpinned`, or the user's recorded `approve --allow-unverified`); or marked `sandbox_required` or CRITICAL (without `--inside-isolation`)
- **Pinned means exact**: a registry-style name with a full version (`pkg@1.2.3`, `pkg==1.0`) or an image digest. Ranges (`pkg@1.2`), tags, URLs, git references, `uv run`, `yarn dlx`/`deno run npm:` without a version and `--with` an unpinned package are `UNPINNED`; a custom registry or index and unknown commands are `UNVERIFIED_LAUNCHER`. Launcher specs are stored redacted (no URL path, credentials, query or arguments), and only registry-style names are ever sent to a registry
- `accept` runs the scanner on every server that is new to the baseline and refuses (`REFUSED`) on a `REJECT` verdict unless `--accept-rejected` is given; `compare` scans a server that is covered for the first time. Each server has one deadline that also bounds writes to a server that does not read and HTTP responses that arrive a byte at a time. A bare command is resolved in the absolute entries of `PATH` only, never in the current directory
- **Runtime tripwire in `mcp-audit.py`**: warns, once per session, on a call to a tool name that is not in the baseline of its server, or to a server the baseline does not cover. Warning only by default; `CERBERO_TRIPWIRE=ask` returns a permission prompt for an unknown tool of a baselined server, `off` disables it. Fail-open: the hook now exits 0 on every error (log rotation over an undecodable line and a failed stdin read used to raise). Its cache sits next to the baseline, per project
- Tests: `test_mcp_snapshot.py`, `test_mcp_gates.py` (one class per launch-gate defect found in review) and `test_mcp_tripwire.py`, with local fixture servers only (`tests/fixtures/fake_mcp_server.py`, `fake_mcp_http.py`). They also assert the documented blind spots (client cloaking is not detected)
- `docs/design/rug-pull-snapshot.md`: the design, its verified facts and the maintainer's decisions

### Changed
- `op-verify-existing.md` rewritten around `pins`, `snapshot`, `compare`, `accept`; the report carries `Coverage`, `Pins` and a fixed limitation line. `op-evaluate-mcp.md`: APPROVED requires a pinned version, Step 8 records the approval and adds the server to the baseline. `op-full-audit.md`: every enabled server needs an approval record. `setup-guide.md` A.6: pin, approve (one time, by the user), snapshot, accept; minimum Claude Code v2.1.274 for the `mcp_server` hook field
- **`mcp-baseline.sha256` changes meaning**: it now holds the inventory hash of the snapshot, not the hash of a file. `compare` always does the per-tool diff; the hash file is a convenience
- README: the rug pull claim describes what the snapshot covers, with a *Rug pull detection limits* section (client cloaking, mid-session changes, OAuth/plugin/connector servers); "does not phone home" now names the two commands that use the network

### Upgrading
- A baseline from 1.3.0 or earlier cannot be migrated: it holds no tool definitions. `/cerbero verify` reports `BASELINE MIGRATION REQUIRED`; on your confirmation `accept` moves the old files to `history/<timestamp>-legacy/` (nothing is deleted) and writes a new baseline. That baseline is a new trust-on-first-use point: re-evaluate HIGH and CRITICAL servers first
- Copy `hooks/cerbero-mcp-snapshot.py` next to the other scripts, pin each server to an exact version, and create the approval records once (`setup-guide.md` A.6)

## [1.3.0] - 2026-11-10

### Security
- **`pre-tool-security.py` no longer auto-approves on a warning.** A download warning returned `permissionDecision: "allow"`, which skips Claude Code's permission prompt, so the warning removed a safeguard. It now returns `additionalContext` only and the normal permission flow applies
- **PowerShell tool coverage.** The hook reads `tool_input.command`, which the PowerShell tool also uses. Wire it with the matcher `Bash|PowerShell` (example settings and setup guide updated). New deny patterns: recursive `Remove-Item` (any `-Recurse` prefix, aliases `ri`/`rm`/`rmdir`/`rd`/`del`/`erase`), `Format-Volume`, `Clear-Disk`, `Set-ExecutionPolicy Bypass|Unrestricted`. **Upgrading**: change the matcher in your settings
- **Scanner, JSON input.** `\uXXXX` escapes are judged by what they decode to: a red flag only for format/control characters, variation selectors, line separators and lone surrogates. Every detector also runs on the decoded strings, so an escaped tag character, bidi override, zero-width character or injection phrase is caught; 1.2.2 missed all four. Ordinary accented text written by `json.dumps` no longer trips `encoding_red_flag` (with an imperative word it produced REJECT). Non-JSON input is scanned as before

### Changed
- **`validate-prompt.py` two-tier redesign.** Blocks (exit 2) only text aimed at the agent's own instructions, format-injection tags and invisible-Unicode smuggling, also inside comments or Base64. A trigger on its own ("a partir de ahora", "don't mention it", "skip the lint rules") warns on stderr and passes. Reads stdin as UTF-8 bytes; non-object input fails open
- Skill documents corrected: whole-process isolation (container, VM or `@anthropic-ai/sandbox-runtime`) replaces the nonexistent `claude --sandbox` flag; HIGH risk requires human review; verdict summaries match the operation tables; mcp-scan step removed; messages delivered in the user's language (rule 10); the rug-pull check states its coverage and reports `NOT RUN`, never `UNCHANGED`, when it cannot run; Skill folders with non-Markdown files require human review; user-level install documented
- One *Scanner path* definition in SKILL.md (project install, then `~/.claude/hooks/cerbero/`); operations write `<scanner>`
- `sandbox_required` is recorded in the MCP evaluation report and the `[security]` log entry, where the full audit reads it
- `examples/settings.local.json`: no matcher on `UserPromptSubmit`; external-content hooks use `^(WebFetch|WebSearch|mcp__.*)$` (`mcp__*` was a regex, and WebSearch output was not scanned)
- README: rug-pull claim narrowed to what the baseline covers; isolation guidance corrected; the install claim matches the skill (it installs on its own only on APPROVED); Quick Start creates the folders it copies into; an FAQ entry on scanning Cerbero's own files

### Added
- Tests: `test_docs.py` (stale strings, required rules, links and anchors, scanner path, isolation record), `test_examples.py` (hook wiring), `test_scanner_json.py`, `test_validate_prompt.py`, `test_versions.py`, PowerShell cases in `test_hooks_io.py`

## [1.2.2] - 2026-10-09

### Security
- **UTF-8 hook stdin.** `cerbero-scanner.py --stdin`, `validate-tool-output.py`, `pre-tool-security.py`, `mcp-audit.py` and `untrusted-source-reminder.py` now read stdin as UTF-8 bytes. Through `sys.stdin` they decoded with the locale code page (cp1252 on most Windows setups), so tag characters and Cyrillic homoglyphs reached the detectors mangled: the scanner returned **CLEAN** on them via `--stdin`, the path `op-evaluate-mcp` uses for MCP tool definitions, and `validate-tool-output.py` missed them in tool output. Input containing a byte cp1252 leaves undefined (`Á` is `C3 81`) made the reminder hook print nothing and `mcp-audit.py` drop the audit entry, both silently with exit 0. **MCP evaluations run on Windows with an earlier version should be re-run.** `validate-prompt.py` is unchanged in this release
- `cerbero-scanner.py --strip-only` writes its output as UTF-8

### Changed
- `pre-tool-security.py`: shell names are anchored, so `curl ... | sha256sum`, `| shasum` and `| shellcheck` no longer read as `| sh`, and `git rm -r` is allowed. It now also catches `sudo bash` / `/bin/sh` after a pipe, `bash <(curl ...)`, `rm -fr` / `rm -f -r`, `chmod -R 0777`, `irm | iex`, `Invoke-Expression`, `rmdir /s` and `del /f /s`. "Hidden process" now means `-WindowStyle Hidden` (`-NoNewWindow` hides nothing). Non-object input fails open
- `validate-tool-output.py` scans every string value in the tool response at any depth, within limits on depth, item count and total characters. It used to stop at the first known key, which missed WebSearch result lists and MCP responses of other shapes. WebSearch is listed in the docstring
- `mcp-audit.py`: `CERBERO_LOG_DIR` sends the log to one directory, for example to collect it across projects. Each entry carries a `project` field. I/O errors and non-object input fail open
- Hook commands in `examples/settings.local.json` and `setup-guide.md` use `"${CLAUDE_PROJECT_DIR}/.claude/hooks/..."`. Claude Code runs hooks from its current directory, so the relative `.claude/hooks/...` path broke once Claude ran `cd` into a subfolder. **Upgrading**: update the hook commands in your settings too

### Added
- `tests/test_hooks_io.py`: UTF-8 stdin cases for the scanner, `validate-tool-output.py` and the reminder hook, run with `PYTHONIOENCODING=cp1252` so they reproduce the Windows failure on any OS, plus `pre-tool-security.py` allow / warn / deny cases. `tests/test_mcp_audit.py` adds the `CERBERO_LOG_DIR` and fail-open cases. 60 tests total

## [1.2.1] - 2026-10-09

### Fixed
- `hooks/mcp-audit.py` wrote `.claude/security/mcp-audit.log` and `invocation-counter.txt` under the hook input's `cwd`, which follows Claude's `cd`. A session started in a subfolder, or one that changed directory, left orphan `.claude/security/` folders there and split the audit trail. The log directory is now anchored to the project root via `_project_root()`: `CLAUDE_PROJECT_DIR` first (also correct for a global `~/.claude/hooks/` install), then the parent of the `.claude/` directory that holds the script (`.claude/hooks/` or `.claude/skills/cerbero/hooks/`), then the input `cwd` as before (for example when run straight from a checkout of this repo)

### Added
- `tests/test_mcp_audit.py`: runs the hook as a subprocess from fake project, skill and global deployments with `cwd` in a subfolder, plus the no-`.claude` fallback. 49 tests total

## [1.2.0] - 2026-09-21

### Fixed
- **Behavior change**: `main()` in `hooks/cerbero-scanner.py` now exits with a code that reflects the computed verdict (it previously always exited `0`). New mapping (`verdict_exit_code()`): `2` on `REJECT`, `1` on `REQUIRES_HUMAN_REVIEW` (not currently produced by `compute_verdict()` - mapped defensively for the skill-level verdict documented in README's "Multi-scanner logic"; see README "Exit codes" for the full table), `0` otherwise (`CLEAN`, `SUSPICIOUS`). Previously a REJECT verdict was only visible in the JSON `summary.verdict` field, not in the process exit code - a caller gating on exit code alone would have let a REJECTed target through undetected
- `run_scan()` now forwards `target_name` into `scan_css_hiding(text, file_path)`, so the stylesheet-skip mitigation is reachable through the real pipeline and CLI (`--file`), not just when `scan_css_hiding()` is called directly. A genuine `.css`/`.html`/`.htm`/`.scss`/`.sass`/`.less`/`.svelte`/`.vue` file scanned via `--file` is no longer flagged for its own expected hide-via-CSS rules (zero-size, none-display, hidden-visibility). `--stdin` mode (`target_name="stdin"`, no extension) is unaffected

### Added
- Unit test suite (`tests/`): one positive + one negative case for each of the 13 `scan_*` detectors in `hooks/cerbero-scanner.py`, plus CLI entry point tests (`--file`, `--stdin`, `--strip-only`, missing-file, no-args, exit codes), plus `tests/fixtures/stylesheet_sample.css` exercising the CSS-path fix end-to-end. Stdlib `unittest` only, 45 tests total
- `.github/workflows/tests.yml`: runs the suite on `ubuntu-latest` against Python 3.10, 3.11 and 3.12
- README "Testing" and "Exit codes" sections

## [1.1.0] - 2026-03-31

### Security
- **Invisible Unicode remediation** (14 invisible-Unicode findings):
  - validate-prompt.py: Variation Selector + Sneaky Bits detection and stripping
  - validate-tool-output.py: full normalize-then-detect pipeline (ZW, NFKC, confusables, tag chars, bidi, VS, sneaky bits), _extract_text() expanded to 10 keys
  - cerbero-scanner.py: 4 new scans (tag chars, bidi, VS + Glassworm decoder, sneaky bits), confusables normalization before injection scan
- Procedural: invisible Unicode checks added to op-evaluate-skill (Step 3b) and op-evaluate-mcp (Step 1.7)
- SKILL.md invisible characters reference expanded (7 codepoints → 6 categories)

## [1.0.0] - 2026-03-30

### Added
- Security screening skill for Claude Code (`/cerbero`)
- 4-tier detection system (Tier 0-3): pre-context scanner, instant checks, local analysis, semantic analysis
- 4 operations: evaluate-mcp, evaluate-skill, verify-existing, full-audit
- 6 automation hooks: prompt injection defense, dangerous command blocking, MCP audit trail, untrusted source reminder, indirect injection scanner, pre-context scanner
- Normalize-then-detect pipeline: NFKC + homoglyph + proximity + base64 recursive decode + zero-width stripping
- Rug pull detection via SHA-256 baseline comparison
- Risk classification matrix (MEDIUM/HIGH/CRITICAL)
- Web research protocol for community intelligence
- Source credibility tiers (HIGH/MEDIUM/LOW)
- OWASP MCP Top 10 coverage mapping
- Trusted publishers allowlist with strict inclusion criteria
- Setup guide with verification checklist

### Origin
Extracted from [Ignite](https://github.com/jppuche/Ignite) v2.3.1 security framework. All hooks are pure Python stdlib - zero external dependencies.
