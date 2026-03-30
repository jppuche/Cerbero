# Cerbero — Setup Guide (Human Only)

This document is for human configuration. Do not load in agent context.

## Prerequisites

- Node.js 18+
- Python 3.10+
- uv: https://docs.astral.sh/uv/ (for uvx commands)
- Claude Code updated to latest stable (`/status` to check)

## A.1 — Install External Scanner (recommended for 5+ MCPs)

### Cisco MCP Scanner (YARA-only mode)

Malware signature detection via 35+ curated YARA rules. 100% offline in YARA-only mode — zero network calls, zero data transmission. Complements Cerbero's regex-based detection with known-bad binary/behavioral signatures.

```powershell
# Install via uv (requires Python 3.11-3.13, NOT 3.14)
uv tool install --python 3.13 cisco-ai-mcp-scanner
# Verify
mcp-scanner --version
```

> **IMPORTANT:** Use YARA-only mode (`--scan-yara`). Do NOT use API mode or LLM mode — these require a Cisco AI Defense account and transmit data to Cisco's cloud.
>
> **When to install:** Recommended if you evaluate 5+ MCP servers or install from untrusted/emerging publishers. For 1-3 MCPs from known publishers, Cerbero's local tiers (T0-T3) provide sufficient coverage.

### Deprecated: mcp-scan (Snyk)

mcp-scan (Invariant Labs) was acquired by Snyk in June 2025. v0.3.0 is unmaintained (9+ months, no security patches). v0.4+ requires Snyk account + mandatory cloud data transmission. **Do not use.** Replaced by cisco-ai-mcp-scanner.

## A.1b — Other Complementary Tools

| Tool | Author | Strength | Status |
|------|--------|----------|--------|
| **Trail of Bits mcp-context-protector** | Trail of Bits | Runtime TOFU pinning + ANSI exploit protection | No stable release yet. Monitor for v1.0. |
| **Anthropic Sandbox** | Anthropic | OS-level filesystem/network enforcement | `claude --sandbox` (beta) |

> **Note:** For most users, Cerbero local tiers + cisco-ai-mcp-scanner (if needed) provide comprehensive coverage. Additional tools add defense-in-depth for high-security environments.

## A.2 — Install Cerbero

Clone the Cerbero repository:

```bash
git clone https://github.com/jppuche/Cerbero.git
cd Cerbero
```

### Option 1: Per-project installation

Copy the skill and hooks to your project:

```powershell
# Skill
Copy-Item -Recurse .claude/skills/cerbero/ <your-project>/.claude/skills/cerbero/

# Hooks
New-Item -ItemType Directory -Force <your-project>/.claude/hooks
Copy-Item hooks/*.py <your-project>/.claude/hooks/

# Security directory + trusted publishers
New-Item -ItemType Directory -Force <your-project>/.claude/security
Copy-Item security/trusted-publishers.txt <your-project>/.claude/security/
```

### Option 2: Global installation (all projects)

```powershell
# Skill (global)
Copy-Item -Recurse .claude/skills/cerbero/ ~/.claude/skills/cerbero/

# Hooks (global — configure in ~/.claude/settings.json)
New-Item -ItemType Directory -Force ~/.claude/hooks
Copy-Item hooks/*.py ~/.claude/hooks/
```

For per-project security artifacts, still create in each project:
```powershell
New-Item -ItemType Directory -Force .claude/security
Copy-Item security/trusted-publishers.txt .claude/security/
```

## A.3 — Define Permission Policy

File: `.claude/settings.local.json` (per-project) or `~/.claude/settings.json` (global)

```jsonc
{
  "enabledMcpjsonServers": [],
  "disabledMcpjsonServers": ["filesystem"],

  "permissions": {
    "allow": [
      "Bash(pwd)",
      "Bash(echo:*)",
      "Bash(cat:*)",
      "Bash(ls:*)"
    ],
    "ask": [
      "Bash(git push:*)",
      "Bash(npm run:*)",
      "Bash(docker run:*)"
    ],
    "deny": [
      "Bash(curl:*)",
      "Bash(wget:*)",
      "Bash(rm -rf:*)",
      "Read(./.env)",
      "Read(./secrets/**)",
      "Read(~/.ssh/**)",
      "WebFetch"
    ]
  }
}
```

Add each MCP server to `enabledMcpjsonServers` only after it passes Cerbero evaluation.

## A.4 — Configure Security Hooks

Add to your settings file (see `examples/settings.local.json` for a complete example):

```jsonc
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "python .claude/hooks/validate-prompt.py"
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python .claude/hooks/pre-tool-security.py"
          }
        ]
      },
      {
        "matcher": "^mcp__",
        "hooks": [
          {
            "type": "command",
            "command": "python .claude/hooks/mcp-audit.py"
          }
        ]
      },
      {
        "matcher": "WebFetch|^mcp__",
        "hooks": [
          {
            "type": "command",
            "command": "python .claude/hooks/untrusted-source-reminder.py"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "WebFetch",
        "hooks": [{ "type": "command", "command": "python .claude/hooks/validate-tool-output.py" }]
      },
      {
        "matcher": "mcp__*",
        "hooks": [{ "type": "command", "command": "python .claude/hooks/validate-tool-output.py" }]
      }
    ]
  }
}
```

> **NOTE:** For global installation, replace `.claude/hooks/` with `~/.claude/hooks/` in all command paths.

> **NOTE:** The PostToolUse hook scans external tool outputs for format injection tags and base64-obfuscated payloads. It warns via additionalContext — never blocks.

## A.5 — Trusted Publishers List

### Default list

The default `security/trusted-publishers.txt` contains:

```
anthropic
trailofbits
```

### Inclusion criteria

The trusted publishers list is intentionally minimal. A publisher on this list allows Cerbero to auto-approve their MCP servers/skills when all other checks pass. Every other publisher requires human review regardless of scan results.

**Requirements for inclusion (all three must be met):**

1. **Direct relevance to Claude Code security or runtime** — The publisher creates Claude Code itself or provides security tooling that Cerbero depends on.
2. **Established security track record** — Public security audits, responsible disclosure history, recognized by OWASP/CVE/industry bodies.
3. **No commercial conflict of interest** — Being a large or popular company is not sufficient. Trust is not reputation.

**Current entries and rationale:**

| Publisher | Rationale |
|-----------|-----------|
| `anthropic` | Creator of Claude and Claude Code. Runtime platform provider. |
| `trailofbits` | Security audit firm. Recognized by industry (DARPA, Ethereum Foundation, major tech companies). Authors of security research directly relevant to LLM tooling. |

### Adding a new publisher

1. Evaluate the MCP server/skill with Cerbero first (`/cerbero evaluate-mcp <pkg>`).
2. If APPROVED after full evaluation, verify the publisher meets **all three** criteria above.
3. Add to `.claude/security/trusted-publishers.txt` (one name per line).

All other publishers (including vercel, microsoft, supabase, etc.) are evaluated case-by-case with Cerbero. Being a well-known company does not exempt from evaluation.

## A.6 — Generate Initial Baseline

```powershell
claude mcp list --json | Out-File -Encoding utf8 .claude/security/mcp-inventory.json
(Get-FileHash .claude/security/mcp-inventory.json -Algorithm SHA256).Hash | Out-File .claude/security/mcp-baseline.sha256
(Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") | Out-File .claude/security/baseline-date.txt
```

## A.7 — Add Cerbero Reference to CLAUDE.md

Add to your project's `CLAUDE.md`:

```markdown
## Security

Before installing any MCP server or Skill, execute Cerbero evaluation.

## Skills

- Cerbero -- Before installing any MCP server or Skill. Security audits.
```

## A.8 — Verification Checklist

- [ ] `uv` installed (for tool management)
- [ ] (Recommended for 5+ MCPs) `cisco-ai-mcp-scanner` installed via `uv tool install --python 3.13 cisco-ai-mcp-scanner`
- [ ] Cerbero skill installed (`~/.claude/skills/cerbero/` or `.claude/skills/cerbero/`)
- [ ] Cerbero hook scripts installed in `.claude/hooks/` (or `~/.claude/hooks/`)
- [ ] `.claude/security/` directory created
- [ ] `.claude/security/trusted-publishers.txt` exists
- [ ] Baseline files generated (if MCPs already installed)
- [ ] Settings file has permissions and hooks configured
- [ ] `CLAUDE.md` references Cerbero
- [ ] Claude Code is latest stable version
- [ ] (Optional) Additional external scanners or sandbox-runtime for defense-in-depth
