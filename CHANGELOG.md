# Changelog

## [Unreleased]

### Added
- Unit test suite (`tests/`): one positive + one negative case for each of the 13 `scan_*` detectors in `hooks/cerbero-scanner.py`, plus CLI entry point tests (`--file`, `--stdin`, `--strip-only`, missing-file, no-args). Stdlib `unittest` only, 37 tests total
- Two tests document (not fix) current scanner behavior found while writing the suite: `run_scan()` does not forward `file_path` into `scan_css_hiding()`, so its stylesheet-skip mitigation is unreachable from the real pipeline/CLI; and `main()` exits 0 unconditionally regardless of verdict, so a REJECT is only visible in the JSON body, not via exit code
- `.github/workflows/tests.yml`: runs the suite on `ubuntu-latest` against Python 3.11 and 3.12
- README "Testing" section

## [1.1.0] - 2026-03-31

### Security
- **Invisible Unicode remediation** (14 Sentinel findings):
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
