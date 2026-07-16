#!/usr/bin/env node

import { Command } from 'commander';
import { Scanner } from './engine.js';
import { calculateScore } from './score.js';
import { reportConsole, reportJson } from './utils/reporter.js';
import { getChangedLines } from './utils/diff.js';
import { installAgentInstructions } from './agent-installer.js';
import * as fs from 'fs';
import * as path from 'path';
import * as readline from 'readline';
import pc from 'picocolors';

const WORKFLOW_TEMPLATE = `name: Security Doctor Scan

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      
      - name: Run Security Doctor Scan
        uses: NKD52/security-doctor@main
`;

function askQuestion(query: string): Promise<string> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });
  return new Promise(resolve => {
    rl.question(query, answer => {
      rl.close();
      resolve(answer);
    });
  });
}

async function offerCiIntegration() {
  const workflowDir = path.resolve(process.cwd(), '.github/workflows');
  const workflowPath = path.resolve(workflowDir, 'security-doctor.yml');

  if (
    process.stdout.isTTY &&
    process.env.GITHUB_ACTIONS !== 'true' &&
    !fs.existsSync(workflowPath)
  ) {
    try {
      const answer = await askQuestion('\nAdd security-doctor to GitHub Actions? Scans every pull request automatically. (y/N) ');
      if (answer.trim().toLowerCase() === 'y') {
        if (!fs.existsSync(workflowDir)) {
          fs.mkdirSync(workflowDir, { recursive: true });
        }
        fs.writeFileSync(workflowPath, WORKFLOW_TEMPLATE, 'utf8');
        console.log(pc.green(`\n✔ Configured GitHub Action successfully!`));
        console.log(pc.gray(`Created workflow configuration at: `) + pc.cyan('.github/workflows/security-doctor.yml'));
      }
    } catch (err) {
      console.error(pc.red(`\nFailed to configure GitHub Action: ${(err as Error).message}`));
    }
  }
}

const program = new Command();

program
  .name('security-doctor')
  .description('A security scanner and AI instruction generator for JS/TS codebases.')
  .version('1.0.0')
  .argument('[dir]', 'directory to scan', '.')
  .option('--json', 'output findings in JSON format')
  .option('--diff <base>', 'only report findings on lines changed since <base> commit/branch')
  .option('--fail-under <score>', 'exit with code 1 if health score is under this threshold', parseInt)
  .option('--install', 'detect active AI coding agents and append security guidelines')
  .option('--verbose', 'print full findings list in interactive terminal')
  .option('--scan-list', 'display the list of all scanned files')
  .action(async (dir, options) => {
    if (options.install) {
      installAgentInstructions(process.cwd());
      process.exit(0);
    }

    try {
      let diffLines: Record<string, Set<number>> | undefined = undefined;

      if (options.diff) {
        diffLines = getChangedLines(options.diff, process.cwd());
      }

      const scanner = new Scanner({
        cwd: process.cwd(),
        diffLines
      });

      const isInteractive = process.stdout.isTTY && !options.json;
      if (isInteractive) {
        process.stdout.write(pc.cyan('🔍 Scanning codebase...'));
      }

      const findings = await scanner.scan(dir);
      const score = calculateScore(findings);

      if (isInteractive) {
        process.stdout.write('\r' + ' '.repeat(30) + '\r');
      }

      if (options.scanList && !options.json) {
        console.log(pc.bold(`Scanned files (${scanner.scannedFiles.length}):`));
        for (const file of scanner.scannedFiles) {
          console.log(pc.gray(`  - ${file}`));
        }
        console.log('');
      }

      if (options.json) {
        reportJson(findings, score);
      } else {
        reportConsole(findings, score, { verbose: !!options.verbose });
        await offerCiIntegration();
      }

      if (options.failUnder !== undefined && score < options.failUnder) {
        process.exit(1);
      }
      
      process.exit(0);
    } catch (err) {
      console.error(`Scan failed: ${(err as Error).message}`);
      process.exit(1);
    }
  });

program.parse(process.argv);
