import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { reportConsole, reportJson } from '../src/utils/reporter.js';
import { Finding } from '../src/rules/types.js';
import { Scanner } from '../src/engine.js';
import { calculateScore } from '../src/score.js';

describe('CLI Console Reporter Formatting', () => {
  let logSpy: any;
  let originalTTY: any;

  beforeEach(() => {
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    originalTTY = process.stdout.isTTY;
  });

  afterEach(() => {
    vi.restoreAllMocks();
    process.stdout.isTTY = originalTTY;
  });

  const mockFindings: Finding[] = [
    {
      ruleId: 'SEC001',
      severity: 'critical',
      message: 'Potential hardcoded secret found.',
      filePath: '/absolute/path/test.ts',
      startLine: 10,
      startColumn: 5,
      endLine: 10,
      endColumn: 20
    },
    {
      ruleId: 'SEC006',
      severity: 'medium',
      message: 'Cookie created without httpOnly.',
      filePath: '/absolute/path/test.ts',
      startLine: 12,
      startColumn: 8,
      endLine: 12,
      endColumn: 30
    }
  ];

  it('should format output as plain text when isTTY is false', async () => {
    process.stdout.isTTY = false;
    const score = calculateScore(mockFindings, 50); // 82
    await reportConsole(mockFindings, score, { scannedFilesCount: 50 });

    const loggedOutput = logSpy.mock.calls.map((c: any) => c[0]).join('\n');
    
    // Should NOT contain the ASCII gauge border box characters
    expect(loggedOutput).not.toContain('┌─');
    expect(loggedOutput).not.toContain('🚨 TOP ISSUE');
    
    // Should contain plain formatting
    expect(loggedOutput).toContain('/absolute/path/test.ts');
    expect(loggedOutput).toContain('SEC001');
    expect(loggedOutput).toContain('SEC006');
    expect(loggedOutput).toContain('Health Score:');
    expect(loggedOutput).toContain('82/100');
  });

  it('should format output with ASCII gauge and Top Issue box when isTTY is true (non-verbose)', async () => {
    process.stdout.isTTY = true;
    const score = calculateScore(mockFindings, 50); // 82
    await reportConsole(mockFindings, score, { verbose: false, scannedFilesCount: 50 });

    const loggedOutput = logSpy.mock.calls.map((c: any) => c[0]).join('\n');
    
    // Should contain the ASCII gauge border box characters
    expect(loggedOutput).toContain('┌' + '─'.repeat(58) + '┐');
    expect(loggedOutput).toContain('Health Score: [████████████████░░░░] 82/100');
    expect(loggedOutput).toContain('Fair');
    expect(loggedOutput).toContain('└' + '─'.repeat(58) + '┘');

    // Should contain the metrics summary
    expect(loggedOutput).toContain('Scanned 50 files · 2 issues found · 1 files affected');
    expect(loggedOutput).toContain('Security > 1 critical, 1 medium');

    // Should contain the Top Issue box with relative paths and impact delta
    expect(loggedOutput).toContain('🚨 TOP ISSUE');
    expect(loggedOutput).toContain('SEC001');
    expect(loggedOutput).toContain('test.ts:10:5');
    expect(loggedOutput).toContain('📈 Impact: Fixing this raises your score to 97/100 (+15)');

    // Should contain the help tip
    expect(loggedOutput).toContain('💡 Tip: Found 2 total vulnerabilities. Use the --verbose flag to display the full list of findings.');

    // Since non-verbose, it should NOT print the full findings list below
    expect(loggedOutput).not.toContain('All 2 findings:');
  });

  it('should format output with ASCII gauge and full list when isTTY is true and verbose is true', async () => {
    process.stdout.isTTY = true;
    const score = calculateScore(mockFindings, 50); // 82
    await reportConsole(mockFindings, score, { verbose: true, scannedFilesCount: 50 });

    const loggedOutput = logSpy.mock.calls.map((c: any) => c[0]).join('\n');
    
    // Should contain the ASCII gauge border box characters
    expect(loggedOutput).toContain('┌' + '─'.repeat(58) + '┐');
    
    // Should contain metrics summary and severity summary
    expect(loggedOutput).toContain('Scanned 50 files · 2 issues found · 1 files affected');
    expect(loggedOutput).toContain('Security > 1 critical, 1 medium');

    // Should contain the Top Issue box
    expect(loggedOutput).toContain('🚨 TOP ISSUE');
    
    // Since verbose, it SHOULD print the full findings list below with relative paths
    expect(loggedOutput).toContain('All 2 findings:');
    expect(loggedOutput).toContain('SEC001');
    expect(loggedOutput).toContain('SEC006');

    // Should contain closing improvement target score
    expect(loggedOutput).toContain('You could improve to 100/100 by fixing all 2 issues.');
  });

  it('should track scanned files list in Scanner.scannedFiles', async () => {
    const scanner = new Scanner({ cwd: process.cwd() });
    await scanner.scan('test');
    expect(scanner.scannedFiles.length).toBeGreaterThan(0);
    expect(scanner.scannedFiles.some(f => f.endsWith('rules.test.ts') || f.endsWith('cli.test.ts'))).toBe(true);
  });

  describe('Impact Delta Floor Handling', () => {
    it('deeply floored score (3 criticals) - delta reflects real formula (+0)', async () => {
      process.stdout.isTTY = true;
      const findings: Finding[] = Array(3).fill(null).map((_, i) => ({
        ruleId: 'SEC001',
        severity: 'critical',
        message: `Leak ${i}`,
        filePath: '/absolute/path/test.ts',
        startLine: 10 + i,
        startColumn: 5
      }));
      const score = calculateScore(findings, 10); // 0
      await reportConsole(findings, score, { scannedFilesCount: 10 });
      const loggedOutput = logSpy.mock.calls.map((c: any) => c[0]).join('\n');
      expect(loggedOutput).toContain('📈 Impact: Fixing this raises your score to 0/100 (+0)');
    });

    it('floored score (2 criticals) where removing top issue lifts unclamped score above 0 - delta is +25', async () => {
      process.stdout.isTTY = true;
      const findings: Finding[] = Array(2).fill(null).map((_, i) => ({
        ruleId: 'SEC001',
        severity: 'critical',
        message: `Leak ${i}`,
        filePath: '/absolute/path/test.ts',
        startLine: 10 + i,
        startColumn: 5
      }));
      const score = calculateScore(findings, 10); // 0
      await reportConsole(findings, score, { scannedFilesCount: 10 });
      const loggedOutput = logSpy.mock.calls.map((c: any) => c[0]).join('\n');
      expect(loggedOutput).toContain('📈 Impact: Fixing this raises your score to 25/100 (+25)');
    });

    it('non-floored score regression - delta remains correct', async () => {
      process.stdout.isTTY = true;
      const findings: Finding[] = [
        {
          ruleId: 'SEC001',
          severity: 'critical',
          message: 'Leak',
          filePath: '/absolute/path/test.ts',
          startLine: 10,
          startColumn: 5
        }
      ];
      const score = calculateScore(findings, 10); // 25
      await reportConsole(findings, score, { scannedFilesCount: 10 });
      const loggedOutput = logSpy.mock.calls.map((c: any) => c[0]).join('\n');
      expect(loggedOutput).toContain('📈 Impact: Fixing this raises your score to 100/100 (+75)');
    });
  });
});
