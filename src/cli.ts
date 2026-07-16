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
import { execSync } from 'child_process';
import clipboardy from 'clipboardy';

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

function getBaseBranch(): string | null {
  try {
    execSync('git rev-parse --is-inside-work-tree', { stdio: 'ignore' });
  } catch {
    return null;
  }

  for (const ref of ['main', 'master', 'origin/main', 'origin/master']) {
    try {
      execSync(`git rev-parse --verify ${ref}`, { stdio: 'ignore' });
      return ref;
    } catch {}
  }
  return null;
}

function getCurrentBranch(): string {
  try {
    return execSync('git rev-parse --abbrev-ref HEAD', { encoding: 'utf8' }).trim();
  } catch {
    return 'HEAD';
  }
}

function getChangedFilesCount(base: string): number {
  try {
    const output = execSync(`git diff --name-only ${base}`, { encoding: 'utf8' });
    return output.trim().split(/\r?\n/).filter(line => line.length > 0).length;
  } catch {
    return 0;
  }
}

function generateFixPrompt(findings: any[], topIssueOnly: boolean = false): string {
  if (findings.length === 0) return '';
  const grouped: Record<string, any[]> = {};
  
  if (topIssueOnly) {
    const severityWeights: Record<string, number> = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1
    };
    let topIssue = findings[0];
    for (const f of findings) {
      if (severityWeights[f.severity] > severityWeights[topIssue.severity]) {
        topIssue = f;
      }
    }
    const relPath = path.relative(process.cwd(), topIssue.filePath).replace(/\\/g, '/');
    let prompt = `Fix the following security issue in ${relPath}:\n`;
    prompt += `- ${topIssue.ruleId} (${topIssue.severity.toUpperCase()}): ${topIssue.message}\n`;
    if (topIssue.suggestedFix) {
      prompt += `  👉 Fix: ${topIssue.suggestedFix}\n`;
    }
    return prompt.trim();
  } else {
    let prompt = 'Please fix the following security vulnerabilities in the codebase:\n\n';
    for (const f of findings) {
      const relPath = path.relative(process.cwd(), f.filePath).replace(/\\/g, '/');
      if (!grouped[relPath]) grouped[relPath] = [];
      grouped[relPath].push(f);
    }
    for (const [relPath, fileFindings] of Object.entries(grouped)) {
      prompt += `File: ${relPath}\n`;
      for (const f of fileFindings) {
        prompt += `- ${f.ruleId} (${f.severity.toUpperCase()}): ${f.message}\n`;
        if (f.suggestedFix) {
          prompt += `  👉 Fix: ${f.suggestedFix}\n`;
        }
      }
      prompt += '\n';
    }
    return prompt.trim();
  }
}

function copyToClipboard(text: string, label: string) {
  try {
    clipboardy.writeSync(text);
    console.log(pc.green('\n✔ Copied to your clipboard.'));
  } catch (err) {
    console.log(pc.yellow('\n⚠ Clipboard unavailable — prompt printed below instead:\n'));
    console.log(pc.bold(`---------------- 📋 ${label.toUpperCase()} ----------------`));
    console.log(text);
    console.log('------------------------------------------------------------');
  }
}

async function runActionMenu(findings: any[], score: number, scannedFilesCount: number, verbose: boolean) {
  if (findings.length === 0) return;

  while (true) {
    console.log(''); // full blank line before menu
    console.log('What\'s next?');
    console.log('  [1] Fix this now with an AI coding agent');
    if (verbose) {
      console.log(`  [2] Copy a fix prompt for all ${findings.length} findings to clipboard`);
    } else {
      console.log('  [2] Copy a fix prompt for the top issue to clipboard');
    }
    console.log('  [3] Install these rules as a coding-agent skill');
    console.log('  [4] Add automated scanning to GitHub Actions');
    console.log('  [5] Nothing, exit\n');

    const answer = await askQuestion('> ');
    const choice = answer.trim();

    if (choice === '1') {
      const prompt = generateFixPrompt(findings, false);
      copyToClipboard(prompt, 'AI Agent Handoff Prompt');
    } else if (choice === '2') {
      if (verbose) {
        const prompt = generateFixPrompt(findings, false);
        copyToClipboard(prompt, 'All Findings Fix Prompt');
      } else {
        const prompt = generateFixPrompt(findings, true);
        copyToClipboard(prompt, 'Top Issue Fix Prompt');
      }
    } else if (choice === '3') {
      installAgentInstructions(process.cwd());
    } else if (choice === '4') {
      const workflowDir = path.resolve(process.cwd(), '.github/workflows');
      const workflowPath = path.resolve(workflowDir, 'security-doctor.yml');
      try {
        if (!fs.existsSync(workflowDir)) {
          fs.mkdirSync(workflowDir, { recursive: true });
        }
        fs.writeFileSync(workflowPath, WORKFLOW_TEMPLATE, 'utf8');
        console.log(pc.green(`\n✔ Configured GitHub Action successfully!`));
        console.log(pc.gray(`Created workflow configuration at: `) + pc.cyan('.github/workflows/security-doctor.yml'));
      } catch (err) {
        console.error(pc.red(`\nFailed to configure GitHub Action: ${(err as Error).message}`));
      }
    } else if (choice === '5' || choice === '') {
      break;
    } else {
      break;
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
      } else if (process.stdout.isTTY && !options.json && process.env.GITHUB_ACTIONS !== 'true') {
        const baseBranch = getBaseBranch();
        if (baseBranch) {
          const currentBranch = getCurrentBranch();
          const changedCount = getChangedFilesCount(baseBranch);
          
          console.log('? Choose what to scan');
          console.log('  [1] Full codebase');
          console.log(`  [2] Changed files on ${currentBranch} vs ${baseBranch} (${changedCount} files)\n`);
          
          const answer = await askQuestion('> ');
          if (answer.trim() === '2') {
            diffLines = getChangedLines(baseBranch, process.cwd());
          }
          console.log('');
        }
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
        reportConsole(findings, score, {
          verbose: !!options.verbose,
          scannedFilesCount: scanner.scannedFiles.length
        });
        if (process.stdout.isTTY && process.env.GITHUB_ACTIONS !== 'true') {
          await runActionMenu(findings, score, scanner.scannedFiles.length, !!options.verbose);
        }
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
