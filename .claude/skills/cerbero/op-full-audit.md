# Operation: Full Security Audit

Trigger: Monthly, or on user request.
Input: None.
Execution agent: Claude (active instance)

---

## Step 1 — Claude Code Version Check

```powershell
claude --version
```

Flag CRITICAL if not on latest stable. Known MCP ecosystem CVEs:
- CVE-2025-49596 — MCP Inspector RCE (CVSS 9.4, fixed in Inspector v0.14.1)
- CVE-2025-6514 — mcp-remote OS command injection (CVSS 9.6, fixed in v0.1.16)
- CVE-2025-68143/44/45 — Anthropic Git MCP Server path bypass + unsanitized args (patched Dec 2025)

## Step 2 — Rug Pull Detection

Execute [op-verify-existing.md](op-verify-existing.md) in full. Include its report as a section in the audit report.

## Step 3 — Re-scan All Components (recommended)

### 3a. Check external scanner availability

```powershell
mcp-scanner --version 2>&1
```

**If cisco-ai-mcp-scanner is NOT installed:**
- Record: `external-scanner: SKIPPED (not available)`
- Continue to Step 4.

**If cisco-ai-mcp-scanner IS available:**
- Execute in YARA-only mode (100% offline):
  ```powershell
  mcp-scanner --scan-yara
  ```
- Do NOT use API mode or LLM mode.

Record all findings.

> **Note:** mcp-scan (Snyk) is deprecated as of 2026-03. See op-evaluate-mcp.md Step 4 for details.

## Step 4 — Configuration Integrity

Read `.claude/settings.local.json` and verify:

1. `enabledMcpjsonServers` contains ONLY servers with a completed evaluation report.
2. `permissions.deny` contains the mandatory entries:
   - `Bash(curl:*)`, `Bash(wget:*)`, `Bash(rm -rf:*)`
   - `Read(./.env)`, `Read(./secrets/**)`, `Read(~/.ssh/**)`
   - `WebFetch`
3. `hooks` section has all three types: UserPromptSubmit, PreToolUse, PostToolUse.
4. No entries were added to `permissions.allow` that match dangerous shell patterns from SKILL.md.
5. Count HIGH+ risk servers enabled simultaneously. If 3+: flag compound risk as CRITICAL.
6. **Sandbox compliance:** For each CRITICAL-risk server, verify `"sandbox_required": true` annotation. Missing annotation on CRITICAL server: flag as CRITICAL finding.

## Step 5 — Hook Functionality

Verify each hook script exists:

```powershell
if (Test-Path .claude/hooks/validate-prompt.py) {"PASS"} else {"MISSING"}
if (Test-Path .claude/hooks/pre-tool-security.py) {"PASS"} else {"MISSING"}
if (Test-Path .claude/hooks/mcp-audit.py) {"PASS"} else {"MISSING"}
if (Test-Path .claude/hooks/cerbero-scanner.py) {"PASS: cerbero-scanner.py"} else {"MISSING: external scanner not deployed"}
if (Test-Path .claude/hooks/validate-tool-output.py) {"PASS: PostToolUse scanner"} else {"SKIPPED: PostToolUse scanner not installed (optional)"}
if (Test-Path .claude/hooks/untrusted-source-reminder.py) {"PASS: Untrusted source reminder"} else {"SKIPPED: Untrusted source reminder not installed (optional)"}
```

## Step 5b — Telemetry Check

Verify MCP audit log exists and is being written:

```powershell
if (Test-Path .claude/security/mcp-audit.log) {
    $lines = (Get-Content .claude/security/mcp-audit.log | Measure-Object -Line).Lines
    "PASS: $lines entries logged"
} else {"MISSING: mcp-audit.log not found — mcp-audit.py hook may not be active"}
```

## Step 6 — Web Research on Installed Components

For each enabled MCP server, run one query:

```
"<package-name>" vulnerability OR "CVE" OR "security" 2025 OR 2026
```

Add findings to report. Any CONFIRMED VULNERABILITY on a currently installed component: flag as CRITICAL.

Cap: 1 query per server. For projects with more than 5 MCP servers, prioritize HIGH-risk servers.

## Step 7 — Audit Report

**MANDATORY PRE-REPORT CHECK (I-1):** Before producing the report, list ALL steps (1-6) with status (COMPLETED/SKIPPED). For each SKIPPED step, state the reason. Do not produce a report if any step was skipped without documented justification.

```
CERBERO — SECURITY AUDIT REPORT
==================================
Date: <ISO 8601>

1. VERSION
   Claude Code: <version>
   Status: CURRENT / OUTDATED / CRITICAL

2. RUG PULL CHECK
   Status: UNCHANGED / CHANGED
   [Include op-verify-existing report if CHANGED]

3. COMPONENT SCAN
   external-scanner (cisco-ai-mcp-scanner): PASS / <n> findings / SKIPPED
   Skills scan: PASS / <n> findings / SKIPPED
   Details: <findings if any>

4. CONFIGURATION
   Enabled servers match evaluations: YES / NO (<mismatches>)
   Mandatory deny rules present: YES / NO (<missing>)
   Hooks configured: YES / NO (<missing types>)
   Suspicious allow entries: <list or NONE>
   Compound risk (3+ HIGH servers): YES / NO
   Sandbox compliance (CRITICAL servers): YES / NO (<missing>)

5. HOOKS
   validate-prompt.py: OK / MISSING
   pre-tool-security.py: OK / MISSING
   mcp-audit.py: OK / MISSING
   cerbero-scanner.py: OK / MISSING
   validate-tool-output.py: OK / MISSING (optional)
   untrusted-source-reminder.py: OK / MISSING (optional)

5b. TELEMETRY
    mcp-audit.log: OK (<n> entries) / MISSING

6. COMMUNITY INTELLIGENCE
   [Per-server findings from Step 6]

OVERALL: HEALTHY / NEEDS ATTENTION / CRITICAL
ACTIONS REQUIRED: <numbered list or NONE>
```
