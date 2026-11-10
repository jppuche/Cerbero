# Operation: Full Security Audit

Trigger: Monthly, or on user request.
Input: None.
Execution agent: Claude (active instance)

---

## Step 1 - Claude Code Version Check

```powershell
claude --version
```

Where only the desktop app is installed there is no `claude` command: record `Claude Code: version not read (no CLI)` and ask the user for the version the app shows. That is a gap to report, not a CRITICAL finding.

Compare the version with the latest release (one web lookup of the Claude Code release notes). Flag OUTDATED when behind; flag CRITICAL only when a security fix the release notes name is missing. If the lookup fails, say the comparison was not made.

Examples of past MCP ecosystem CVEs, as of 2025-12. This list is frozen and is not a current inventory - Step 6 is the current check:
- CVE-2025-49596 - MCP Inspector RCE (CVSS 9.4, fixed in Inspector v0.14.1)
- CVE-2025-6514 - mcp-remote OS command injection (CVSS 9.6, fixed in v0.1.16)
- CVE-2025-68143/44/45 - Anthropic Git MCP Server path bypass + unsanitized args (patched Dec 2025)

## Step 2 - Rug Pull Detection

Execute [op-verify-existing.md](op-verify-existing.md) in full. Include its report as a section in the audit report.

## Step 3 - Re-scan All Components (recommended)

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

## Step 4 - Configuration Integrity

Read `.claude/settings.local.json` and verify:

1. `enabledMcpjsonServers` contains ONLY servers with a completed evaluation report.
2. `permissions.deny` contains the mandatory entries:
   - `Bash(curl:*)`, `Bash(wget:*)`, `Bash(rm -rf:*)`
   - `Read(./.env)`, `Read(./secrets/**)`, `Read(~/.ssh/**)`
   - `WebFetch`, unless the project does web research. Then `WebFetch` may be allowed, on two conditions: the PostToolUse scanner (`validate-tool-output.py`) is wired for `WebFetch|WebSearch`, and the fetching is done by an agent with no file tools. Report which case applies; a project that allows `WebFetch` without the scanner wired is a finding.
3. `hooks` section has all three types: UserPromptSubmit, PreToolUse, PostToolUse. Also read `~/.claude/settings.json`: hooks installed at user level count, and are listed with their scope.
4. No entries were added to `permissions.allow` that match dangerous shell patterns from SKILL.md.
5. Count HIGH+ risk servers enabled simultaneously. If 3+: flag compound risk as CRITICAL.
6. **Isolation compliance:** For each CRITICAL-risk server, verify `"sandbox_required": true` annotation (whole-process isolation: container, VM or sandbox-runtime; the built-in `/sandbox` does not count). Missing annotation on CRITICAL server: flag as CRITICAL finding.

## Step 5 - Hook Functionality

Hooks can be installed at project level (`.claude/hooks/`, wired in `.claude/settings*.json`) or user level (`~/.claude/hooks/cerbero/`, wired in `~/.claude/settings.json`). Check both and report where each script was found. A script that exists but is not referenced by any settings file is not active: say so.

```powershell
$hookDirs = @(".claude/hooks", (Join-Path $HOME ".claude/hooks/cerbero"))
$scripts = [ordered]@{
    "validate-prompt.py"           = "required"
    "pre-tool-security.py"         = "required"
    "mcp-audit.py"                 = "required"
    "cerbero-scanner.py"           = "required (external scanner)"
    "validate-tool-output.py"      = "optional (PostToolUse scanner)"
    "untrusted-source-reminder.py" = "optional (untrusted source reminder)"
}
foreach ($name in $scripts.Keys) {
    $found = $hookDirs | Where-Object { Test-Path (Join-Path $_ $name) }
    if ($found) { "PASS: $name in $($found -join ', ')" } else { "MISSING: $name - $($scripts[$name])" }
}
# Which scripts are actually wired:
$settings = @(".claude/settings.json", ".claude/settings.local.json", (Join-Path $HOME ".claude/settings.json")) | Where-Object { Test-Path $_ }
Select-String -Path $settings -Pattern "validate-prompt|pre-tool-security|mcp-audit|cerbero-scanner|validate-tool-output|untrusted-source-reminder" | ForEach-Object { "WIRED: $($_.Path): $($_.Line.Trim())" }
```

A user-level install may be a deliberate subset (for example only the PostToolUse scanner and the reminder). Report missing scripts as MISSING, but do not flag a documented subset as CRITICAL.

## Step 5b - Telemetry Check

Verify the MCP audit log exists and is being written. `mcp-audit.py` writes to `$env:CERBERO_LOG_DIR` if set, else `<project>/.claude/security/` (also for a user-level install since Cerbero 1.2.1; `~/.claude/security/` may still hold entries from older versions):

```powershell
$logs = @($env:CERBERO_LOG_DIR, ".claude/security", (Join-Path $HOME ".claude/security")) |
    Where-Object { $_ } | ForEach-Object { Join-Path $_ "mcp-audit.log" } | Where-Object { Test-Path $_ }
if ($logs) {
    foreach ($log in $logs) { "PASS: $log - $((Get-Content $log | Measure-Object -Line).Lines) entries" }
} else {"MISSING: mcp-audit.log not found - mcp-audit.py hook may not be active"}
```

## Step 6 - Web Research on Installed Components

For each enabled MCP server, run one query:

```
"<package-name>" vulnerability OR "CVE" OR "security" <previous year> OR <current year>
```

Fill the two years from today's date.

Add findings to report. Any CONFIRMED VULNERABILITY on a currently installed component: flag as CRITICAL.

Cap: 1 query per server. For projects with more than 5 MCP servers, prioritize HIGH-risk servers.

## Step 7 - Audit Report

**Pre-report check:** before the report, list steps 1-6 with their status (COMPLETED or SKIPPED) and the reason for each SKIPPED one. A step skipped with no reason blocks the report: a HEALTHY that rests on a step nobody ran is worse than no audit.

```
CERBERO - SECURITY AUDIT REPORT
==================================
Date: <ISO 8601>

1. VERSION
   Claude Code: <version>
   Status: CURRENT / OUTDATED / CRITICAL

2. RUG PULL CHECK
   Status: UNCHANGED / CHANGED / NOT RUN (<reason>)
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
   Isolation compliance (CRITICAL servers): YES / NO (<missing>)

5. HOOKS (scope: project / user / both)
   validate-prompt.py: OK / MISSING
   pre-tool-security.py: OK / MISSING
   mcp-audit.py: OK / MISSING
   cerbero-scanner.py: OK / MISSING
   validate-tool-output.py: OK / MISSING (optional)
   untrusted-source-reminder.py: OK / MISSING (optional)

5b. TELEMETRY
    mcp-audit.log: OK (<path>, <n> entries) / MISSING

6. COMMUNITY INTELLIGENCE
   [Per-server findings from Step 6]

OVERALL: HEALTHY / NEEDS ATTENTION / CRITICAL
ACTIONS REQUIRED: <numbered list or NONE>
```
