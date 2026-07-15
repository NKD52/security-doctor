import { describe, it, expect } from 'vitest';
import * as path from 'path';
import { Scanner } from '../src/engine.js';
import { isLikelySecret } from '../src/utils/entropy.js';
import { calculateScore } from '../src/score.js';
import { validSecrets, falsePositives } from './entropy.fixtures.js';

describe('Entropy & Secrets Classification', () => {
  it('should flag real secrets', () => {
    for (const secret of validSecrets) {
      const flagged = isLikelySecret(secret.varName, secret.value);
      expect(flagged).toBe(true);
    }
  });

  it('should ignore false positives', () => {
    for (const fp of falsePositives) {
      const flagged = isLikelySecret(fp.varName, fp.value);
      expect(flagged).toBe(false);
    }
  });
});

describe('Security Rules AST Scanning', () => {
  const scanner = new Scanner();

  it('SEC001: Hardcoded Secrets', () => {
    const code = `
      // Positive cases (Should trigger findings)
      const apiKey = "SG.yO3R8r3_T3W_cK9J1Vp2bA.d9G8h7i6j5k4l3m2n1o0p9q8r7s6t5u4v3w2x1y0z1";
      const config = {
        slackSecret: "slack_tok_val_shannon_entropy_test_passed_abc_123_xyz"
      };
      db_password = "sUp3r_SeCr3t_P@ss_123_!";

      // Negative cases (Should NOT trigger findings)
      const normalString = "hello world";
      const userId = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"; // UUIDs ignored
      const classNames = "flex items-center justify-between p-4 bg-slate-900 border-b"; // Long style strings ignored
      const stripePlaceholder = "sk_test_placeholder"; // Ignored due to placeholder string
      const password = "dummy_pwd"; // Ignored due to placeholder string
      const token = "TODO_insert_token"; // Ignored due to placeholder string
      const db_password_short = "123"; // Too short
    `;
    const findings = scanner.scanFile('test.ts', code);
    expect(findings.length).toBe(3);
    findings.forEach(f => {
      expect(f.ruleId).toBe('SEC001');
      expect(f.severity).toBe('critical');
    });
  });

  it('SEC002: Eval/Exec usage', () => {
    const code = `
      // Positive cases (Should trigger findings)
      eval("const a = 1;");
      new Function("return 2;");
      exec("rm -rf /");
      child_process.execSync("ls");
      
      // Negative cases (Should NOT trigger findings)
      const val = obj[evalValue];
      const evaluate = "not eval";
      const execute = () => {};
    `;
    const findings = scanner.scanFile('test.ts', code);
    expect(findings.length).toBe(4);
    findings.forEach(f => {
      expect(f.ruleId).toBe('SEC002');
      expect(f.severity).toBe('high');
    });
  });

  it('SEC003: Disabled TLS Verification', () => {
    const code = `
      // Positive cases (Should trigger findings)
      const options = {
        rejectUnauthorized: false
      };
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = false;
      
      // Negative cases (Should NOT trigger findings)
      const safeOptions = {
        rejectUnauthorized: true
      };
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = 1;
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = true;
    `;
    const findings = scanner.scanFile('test.ts', code);
    expect(findings.length).toBe(4);
    findings.forEach(f => {
      expect(f.ruleId).toBe('SEC003');
      expect(f.severity).toBe('critical');
    });
  });

  it('SEC004: Insecure CORS Wildcard', () => {
    const code = `
      // Positive cases (Should trigger findings)
      const corsOptions = {
        origin: '*'
      };
      
      const headers = {
        'Access-Control-Allow-Origin': '*'
      };
      
      // Negative cases (Should NOT trigger findings)
      const safeCors = {
        origin: 'https://example.com'
      };
      const safeHeaders = {
        'Access-Control-Allow-Origin': 'https://example.com'
      };
      const multipleCors = {
        origin: ['https://a.com', 'https://b.com']
      };
    `;
    const findings = scanner.scanFile('test.ts', code);
    expect(findings.length).toBe(2);
    findings.forEach(f => {
      expect(f.ruleId).toBe('SEC004');
      expect(f.severity).toBe('medium');
    });
  });

  it('SEC005: Weak Cryptographic Algorithms', () => {
    const code = `
      // Positive cases (Should trigger findings)
      const hash1 = crypto.createHash('md5');
      const hash2 = createHash('sha1');
      
      // Negative cases (Should NOT trigger findings)
      const hash3 = crypto.createHash('sha256');
      const hash4 = createHash('sha512');
      const hash5 = crypto.createHash('sha384');
      const createHash = "just_a_variable_not_called";
    `;
    const findings = scanner.scanFile('test.ts', code);
    expect(findings.length).toBe(2);
    findings.forEach(f => {
      expect(f.ruleId).toBe('SEC005');
      expect(f.severity).toBe('medium');
    });
  });

  it('SEC006: Missing HTTPOnly/Secure Flags on Cookies', () => {
    const code = `
      // Positive cases (Should trigger findings)
      res.cookie('token', 'value', { httpOnly: false, secure: true }); // missing/disabled httpOnly
      res.cookie('auth', 'value', { httpOnly: true }); // missing secure
      res.cookie('simple', 'value'); // missing both (no options object)
      res.cookie('insecure', 'value', { httpOnly: true, secure: false }); // disabled secure
      
      // Negative cases (Should NOT trigger findings)
      res.cookie('session', 'value', { httpOnly: true, secure: true }); // safe
      res.cookie('session2', 'value', { secure: true, httpOnly: true, maxAge: 900000 }); // safe with extra options
    `;
    const findings = scanner.scanFile('test.ts', code);
    expect(findings.length).toBe(4);
    findings.forEach(f => {
      expect(f.ruleId).toBe('SEC006');
      expect(f.severity).toBe('medium');
    });
  });
});

describe('Scoring Logic', () => {
  it('should compute exact health scores based on severity deduplication', () => {
    const mockFindings: any[] = [
      { severity: 'critical' }, // -15
      { severity: 'high' },     // -8
      { severity: 'medium' },   // -3
      { severity: 'low' }       // -1
    ];
    
    // 100 - 15 - 8 - 3 - 1 = 73
    expect(calculateScore(mockFindings)).toBe(73);

    // Should floor at 0
    const worstFindings = Array(10).fill({ severity: 'critical' });
    expect(calculateScore(worstFindings)).toBe(0);
  });
});

describe('Diff Mode Filtering', () => {
  it('should filter findings that are not on modified lines', () => {
    const code = `
      eval("const a = 1;"); // line 2 (vulnerable)
      new Function("return 2;"); // line 3 (vulnerable)
    `;
    
    // Scan with diffLines containing only line 3
    const filePath = path.resolve('test-diff-file.ts');
    const diffLines = {
      [filePath]: new Set([3])
    };
    
    const scanner = new Scanner({ diffLines });
    const findings = scanner.scanFile(filePath, code);
    
    // Only the finding on line 3 should be reported
    expect(findings.length).toBe(1);
    expect(findings[0].startLine).toBe(3);
  });
});

