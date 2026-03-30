# Contributing to Cerbero

Thanks for your interest in contributing to Cerbero.

## Reporting Bugs

Open an issue with:
- Steps to reproduce
- Expected behavior vs actual behavior
- Python version, OS, Claude Code version

## Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes
4. Ensure all hooks still run standalone (stdlib only — no external dependencies)
5. Test hooks with the smoke tests in the README
6. Commit using conventional commits (`type(scope): description`)
7. Open a pull request

## Code Standards

- **Python hooks**: stdlib only. No `pip install`. No external imports.
- **Skill files**: Markdown. Procedures must be self-contained and actionable.
- **Language**: English for all code, comments, and documentation.
- **Naming**: kebab-case for files, snake_case for Python.

## What We Accept

- New detection patterns (with rationale and false-positive analysis)
- Improvements to existing hooks (performance, accuracy)
- Bug fixes
- Documentation improvements
- New operation procedures (with threat model justification)

## What We Don't Accept

- External dependencies in hooks (this is a hard rule)
- Features that require API keys or cloud services for core functionality
- Changes that break the local-first principle

## Security Vulnerabilities

If you find a security vulnerability in Cerbero itself, please report it privately via GitHub's security advisory feature rather than opening a public issue.
