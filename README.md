# security-doctor 🩺

`security-doctor` is a security-focused CLI scanning tool and AI instruction generator for JavaScript and TypeScript codebases. It parses code into an AST, scans for high-entropy secrets and unsafe patterns, calculates a project health score, and automatically installs security rules for AI coding assistants.

---

## 🚀 Quick Start

### Installation
```bash
# Clone the repository
git clone <repo-url>
cd security-doctor

# Install dependencies
npm install

# Build the project
npm run build
```

### Usage
Run the scanner against any directory (defaults to current directory):
```bash
# Scan a directory
node dist/cli.js /path/to/project

# Scan in JSON mode
node dist/cli.js /path/to/project --json

# Fail CI/CD if health score is under 80
node dist/cli.js /path/to/project --fail-under 80

# Run in PR/Diff mode (only report findings on newly modified lines)
node dist/cli.js /path/to/project --diff origin/main
```

### Install AI Agent Rules
Automatically detects and appends security rules to your AI coding agents (`.cursorrules`, `CLAUDE.md`, or `.github/copilot-instructions.md`):
```bash
node dist/cli.js --install
```

---

## 🛠️ Tech Stack & Architecture

- **Language:** TypeScript
- **Runtime:** Node.js (v22.18.0+)
- **Parser & AST Tooling:** `@babel/parser` (configured with TS/JSX/decorators plugins) and `@babel/traverse`
- **Testing:** `vitest`
- **CLI & Output:** `commander` + `picocolors`

### Core Components

```
src/
├── cli.ts                # Commander CLI setup and entry point
├── engine.ts             # Scan coordinator (globbing, AST parsing, rule execution)
├── score.ts              # Scoring logic (Base 100 with severity deductions)
├── agent-installer.ts    # Agent detection and rule appending
├── rules/                # Visitor implementations for SEC001 - SEC006
└── utils/
    ├── entropy.ts        # Shannon entropy calculation and secrets classifier
    ├── diff.ts           # Unified git diff hunk range parser
    └── reporter.ts       # Console and JSON format outputs
```

---

## 🏷️ Rule Taxonomy (v1 Scope)

| Rule ID | Severity | Description |
|---|---|---|
| **SEC001** | `critical` | Hardcoded secrets (API keys, passwords) verified via Shannon entropy and format detectors. |
| **SEC002** | `high` | Unsafe dynamic code execution (`eval()`, `new Function()`, `exec()`, `execSync()`). |
| **SEC003** | `high` | Disabled TLS certificate verification (`rejectUnauthorized: false` or `NODE_TLS_REJECT_UNAUTHORIZED = 0`). |
| **SEC004** | `medium` | Permissive CORS wildcard configuration (`origin: '*'` or `Access-Control-Allow-Origin: '*'`). |
| **SEC005** | `high` | Weak or outdated cryptographic hash algorithms (`md5`, `sha1`). |
| **SEC006** | `medium` | Cookie configuration missing or disabling `httpOnly` or `secure` flags. |

---

## 🎯 Migration Context & Handover

If migrating this repository to another IDE (such as VS Code, Cursor, Zed, or Claude Code) or handoff to another developer:

### Current Project Status
- **Build Status:** Compiles clean with zero warnings (`npm run build`).
- **Test Status:** 100% of Vitest test suites are passing (`npm test`).
- **Scoring Engine:** A perfect code health score is `100`. Severity deductions are applied as follows: Critical (`-15`), High (`-8`), Medium (`-3`), Low (`-1`).

### Tuning & Edge Cases Handled
1. **Secrets Detection Heuristics (`src/utils/entropy.ts`)**:
   - The Shannon entropy threshold is tuned to `3.5`.
   - Values matching common placeholder prefixes/suffixes (`placeholder`, `dummy`, `your-`, `todo`) are ignored.
   - High-entropy UUIDs and long CSS class names (such as Tailwind class strings) are ignored.
   - PEM private keys starting with `-----BEGIN` are immediately flagged regardless of spaces or newlines.
2. **PR / Diff Intersection (`src/utils/diff.ts`)**:
   - Executes `git diff -U0 <base>` and parses the unified diff hunks.
   - Translates lines modified/added into a line set per file, and intersects this with finding starting lines in `src/engine.ts`.
3. **Idempotent Agent Installer (`src/agent-installer.ts`)**:
   - Detects active agent config directories/files in the workspace root.
   - Appends positive security guidelines (the inverse of our rules) to the rule files.
   - Skips writing if the block containing the `security-doctor` marker is already present.

### Future Roadmap (v2)
- **Taint-Tracking Engine**: Transition from simple pattern matching to a dataflow analysis engine to support command injection, SQL injection, path traversal, and prototype pollution analysis.
- **Rule Configuration**: Allow overriding rules and target directories via a local `security-doctor.config.json` configuration file.
- **GitHub Action**: Build a packaged GitHub Action to run the scanner on PRs and comment with the health score.
