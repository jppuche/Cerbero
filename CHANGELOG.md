# Changelog

## [1.2.0] - 2026-09-21

### Fixed
- **Behavior change**: `main()` in `hooks/cerbero-scanner.py` now exits with a code that reflects the computed verdict, unconditionally exiting `0` no longer being the case. New mapping (`verdict_exit_code()`): `2` on `REJECT`, `1` on `REQUIRES_HUMAN_REVIEW` (not currently produced by `compute_verdict()` — mapped defensively for the skill-level verdict documented in README's "Multi-scanner logic"; see README "Exit codes" for the full table), `0` otherwise (`CLEAN`, `SUSPICIOUS`). Previously a REJECT verdict was only visible in the JSON `summary.verdict` field, not in the process exit code — a caller gating on exit code alone would have let a REJECTed target through undetected
- `run_scan()` now forwards `target_name` into `scan_css_hiding(text, file_path)`, so the M-1 stylesheet-skip mitigation is reachable through the real pipeline and CLI (`--file`), not just when `scan_css_hiding()` is called directly. A genuine `.css`/`.html`/`.htm`/`.scss`/`.sass`/`.less`/`.svelte`/`.vue` file scanned via `--file` is no longer flagged for its own expected hide-via-CSS rules (zero-size, none-display, hidden-visibility). `--stdin` mode (`target_name="stdin"`, no extension) is unaffected

### Added
- Unit test suite (`tests/`): one positive + one negative case for each of the 13 `scan_*` detectors in `hooks/cerbero-scanner.py`, plus CLI entry point tests (`--file`, `--stdin`, `--strip-only`, missing-file, no-args, exit codes), plus `tests/fixtures/stylesheet_sample.css` exercising the CSS-path fix end-to-end. Stdlib `unittest` only, 45 tests total
- `.github/workflows/tests.yml`: runs the suite on `ubuntu-latest` against Python 3.11 and 3.12
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
