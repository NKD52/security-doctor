import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { reportConsole, reportJson } from '../src/utils/reporter.js';
import { Finding } from '../src/rules/types.js';

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
      filePath: 'test.ts',
      startLine: 10,
      startColumn: 5,
      endLine: 10,
      endColumn: 20
    },
    {
      ruleId: 'SEC006',
      severity: 'medium',
      message: 'Cookie created without httpOnly.',
      filePath: 'test.ts',
      startLine: 12,
      startColumn: 8,
      endLine: 12,
      endColumn: 30
    }
  ];

  it('should format output as plain text when isTTY is false', () => {
    process.stdout.isTTY = false;
    reportConsole(mockFindings, 73);

    const loggedOutput = logSpy.mock.calls.map((c: any) => c[0]).join('\n');
    
    // Should NOT contain the ASCII gauge border box characters
    expect(loggedOutput).not.toContain('┌─');
    expect(loggedOutput).not.toContain('🚨 TOP ISSUE:');
    
    // Should contain plain formatting
    expect(loggedOutput).toContain('test.ts');
    expect(loggedOutput).toContain('SEC001');
    expect(loggedOutput).toContain('SEC006');
    expect(loggedOutput).toContain('Health Score:');
    expect(loggedOutput).toContain('73/100');
  });

  it('should format output with ASCII gauge and Top Issue box when isTTY is true (non-verbose)', () => {
    process.stdout.isTTY = true;
    reportConsole(mockFindings, 73, { verbose: false });

    const loggedOutput = logSpy.mock.calls.map((c: any) => c[0]).join('\n');
    
    // Should contain the ASCII gauge border box characters
    expect(loggedOutput).toContain('┌' + '─'.repeat(58) + '┐');
    expect(loggedOutput).toContain('Health Score: [███████████████░░░░░] 73/100');
    expect(loggedOutput).toContain('Fair');
    expect(loggedOutput).toContain('└' + '─'.repeat(58) + '┘');

    // Should contain the vulnerable files list
    expect(loggedOutput).toContain('Vulnerable files:');
    expect(loggedOutput).toContain('test.ts');

    // Should contain the Top Issue box
    expect(loggedOutput).toContain('🚨 TOP ISSUE:');
    expect(loggedOutput).toContain('SEC001');
    expect(loggedOutput).toContain('(test.ts:10:5)');
    expect(loggedOutput).toContain('Severity:');
    expect(loggedOutput).toContain('CRITICAL');
    expect(loggedOutput).toContain('Message:  Potential hardcoded secret found.');
    expect(loggedOutput).toContain('🛡️ Impact:');
    expect(loggedOutput).toContain('Fixing this prevents accidental leakage of private API credentials');

    // Should contain the help tip
    expect(loggedOutput).toContain('💡 Tip: Found 2 total vulnerabilities. Use the --verbose flag to display the full list of findings.');

    // Since non-verbose, it should NOT print the full findings list below (e.g. details of SEC006 shouldn't be printed)
    expect(loggedOutput).not.toContain('SEC006: Cookie created without httpOnly.');
  });

  it('should format output with ASCII gauge and full list when isTTY is true and verbose is true', () => {
    process.stdout.isTTY = true;
    reportConsole(mockFindings, 73, { verbose: true });

    const loggedOutput = logSpy.mock.calls.map((c: any) => c[0]).join('\n');
    
    // Should contain the ASCII gauge border box characters
    expect(loggedOutput).toContain('┌' + '─'.repeat(58) + '┐');
    
    // Should contain vulnerable files
    expect(loggedOutput).toContain('Vulnerable files:');
    expect(loggedOutput).toContain('test.ts');

    // Should contain the Top Issue box
    expect(loggedOutput).toContain('🚨 TOP ISSUE:');
    
    // Since verbose, it SHOULD print the full findings list below
    expect(loggedOutput).toContain('Found 2 vulnerabilities:');
    expect(loggedOutput).toContain('test.ts');
    expect(loggedOutput).toContain('SEC001');
    expect(loggedOutput).toContain('SEC006');
  });
});
