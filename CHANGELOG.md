# Changelog

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
- **Behavior change**: `main()` in `hooks/cerbero-scanner.py` now exits with a code that reflects the computed verdict (it previously always exited `0`). New mapping (`verdict_exit_code()`): `2` on `REJECT`, `1` on `REQUIRES_HUMAN_REVIEW` (not currently produced by `compute_verdict()` — mapped defensively for the skill-level verdict documented in README's "Multi-scanner logic"; see README "Exit codes" for the full table), `0` otherwise (`CLEAN`, `SUSPICIOUS`). Previously a REJECT verdict was only visible in the JSON `summary.verdict` field, not in the process exit code — a caller gating on exit code alone would have let a REJECTed target through undetected
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
Extracted from [Ignite](https://github.com/jppuche/Ignite) v2.3.1 security framework. All hooks are pure Python stdlib — zero external dependencies.
