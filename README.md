Your agent writes vulnerable code, this catches it.

security-doctor scans JavaScript and TypeScript codebases for the vulnerabilities AI coding agents actually tend to introduce: hardcoded secrets, disabled TLS checks, SQL and NoSQL injection, command injection, path traversal, XSS, insecure cookies, and sensitive data stored in the browser. It gives you a 0-100 health score, then installs its rules directly into your coding agent so the same mistake doesn't come back.

## Install

### 1. Quick start

Run this at your project root to get an audit.

```
npx security-doctor@latest
```

### 2. Install for agents

Once you have an audit, install the rules as guidance for your coding agent so it stops writing the same issues.

```
npx security-doctor@latest --install
```

Detects and writes to Cursor (`.cursorrules`), Claude Code (`CLAUDE.md`), and GitHub Copilot (`.github/copilot-instructions.md`). If none are found, you'll be offered the choice to create one or copy the rules to your clipboard instead.

### 3. Run in CI

Add automated scanning on every pull request:

```
npx security-doctor@latest --install-ci
```

This writes a GitHub Actions workflow that scans changed files on every PR and fails the build below a configurable score threshold.

### 4. Scan changed files only

In a git repo, security-doctor can scope a scan to just what changed on your current branch:

```
npx security-doctor@latest --diff main
```

### 5. Consume JSON

Use `--json` for machine-readable output, useful for custom CI integrations or piping into other tools.

## What it catches

**Pattern-based (single-file):**
- Hardcoded secrets, including env-var fallback patterns (`process.env.X || 'literal'`)
- `eval()` / `new Function()` / unsafe `exec()`
- Disabled TLS certificate verification
- Wildcard CORS
- Weak hashing algorithms (MD5, SHA1)
- Cookies missing `httpOnly` / `secure`
- Sensitive data (tokens, secrets, passwords) written to `localStorage` / `sessionStorage`

**Taint-tracked (data flow within a single function):**
- SQL injection
- Command injection
- Path traversal
- Cross-site scripting (XSS) via unescaped `innerHTML` / `outerHTML`
- NoSQL injection (MongoDB operator injection, `$where` abuse)

## What it doesn't do

Being upfront about this matters more than a longer feature list:

- **No dependency vulnerability scanning.** This isn't a replacement for `npm audit`, Snyk, or Dependabot, it looks at code you wrote, not packages you installed.
- **No cross-function taint tracking.** If a value picks up taint in one function and gets passed through two or three helper calls before reaching a dangerous sink, current rules won't trace it. Single-function tracking catches the large majority of real cases, but this is a known limit, not an oversight.
- **No general accessibility, performance, or architecture rules.** This is a security tool specifically.

If you hit a false positive or a real vulnerability it misses, please open an issue, this is early and the rule set is actively being refined against real-world code.

## Configuration

Suppress specific rules or exclude paths via `security-doctor.config.json` at your project root, or a `securityDoctor` key in `package.json`.

## Contributing

Issues and pull requests welcome.

MIT-licensed