#!/usr/bin/env node

import { Command } from 'commander';
import { Scanner } from './engine.js';
import { calculateScore } from './score.js';
import { reportConsole, reportJson } from './utils/reporter.js';
import { getChangedLines } from './utils/diff.js';
import { installAgentInstructions } from './agent-installer.js';

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

      const findings = await scanner.scan(dir);
      const score = calculateScore(findings);

      if (options.json) {
        reportJson(findings, score);
      } else {
        reportConsole(findings, score);
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
