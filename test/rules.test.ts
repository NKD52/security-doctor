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
      const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_value_here_abc123xyz';
      const apiKeyFallback = process.env.API_KEY ?? 'sk_live_abc123xyz';

      // Negative cases (Should NOT trigger findings)
      const normalString = "hello world";
      const userId = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"; // UUIDs ignored
      const classNames = "flex items-center justify-between p-4 bg-slate-900 border-b"; // Long style strings ignored
      const stripePlaceholder = "sk_test_placeholder"; // Ignored due to placeholder string
      const password = "dummy_pwd"; // Ignored due to placeholder string
      const token = "TODO_insert_token"; // Ignored due to placeholder string
      const db_password_short = "123"; // Too short
      const timeout = process.env.TIMEOUT || 3000;
      const mode = process.env.NODE_ENV || 'development';
      const auth = process.env.AUTH || \`Bearer \${token}\`;
      const ENDPOINT_URL = "https://api.example.com/oauth/token"; // URLs ignored
      const webhook_secret_url = "http://localhost:3000/webhook"; // URLs ignored
    `;
    const findings = scanner.scanFile('test.ts', code);
    expect(findings.length).toBe(5);
    findings.forEach(f => {
      expect(f.ruleId).toBe('SEC001');
      expect(f.severity).toBe('critical');
    });

    const jwtFinding = findings.find(f => f.message.includes('fallback for "JWT_SECRET"'));
    expect(jwtFinding).toBeDefined();
    expect(jwtFinding!.message).toBe('Possible hardcoded credential used as a fallback for "JWT_SECRET". If the environment variable is unset, the app silently runs with this committed value instead of failing.');
    expect(jwtFinding!.suggestedFix).toBe("Throw an error if the environment variable is missing (fail closed): throw new Error('JWT_SECRET must be set')");

    const apiKeyFinding = findings.find(f => f.message.includes('fallback for "apiKeyFallback"'));
    expect(apiKeyFinding).toBeDefined();
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
      res.cookie('sid_bad', token, { httpOnly: true, secure: process.env.SOME_OTHER_VAR === 'yes' }); // invalid env check
      
      // Negative cases (Should NOT trigger findings)
      res.cookie('session', 'value', { httpOnly: true, secure: true }); // safe
      res.cookie('session2', 'value', { secure: true, httpOnly: true, maxAge: 900000 }); // safe with extra options
      res.cookie('session_env1', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' }); // safe env check
      res.cookie('session_env2', token, { httpOnly: true, secure: process.env.NODE_ENV !== 'development' }); // safe env check
      res.cookie('session_env3', token, { httpOnly: true, secure: 'production' === process.env.NODE_ENV }); // safe reversed env check
    `;
    const findings = scanner.scanFile('test.ts', code);
    expect(findings.length).toBe(5);
    findings.forEach(f => {
      expect(f.ruleId).toBe('SEC006');
      expect(f.severity).toBe('medium');
    });
  });
});

describe('Scoring Logic', () => {
  it('should compute exact health scores based on density-normalized scoring', () => {
    const mockFindings: any[] = [
      { severity: 'critical' }, // 15
      { severity: 'high' },     // 8
      { severity: 'medium' },   // 3
      { severity: 'low' }       // 1
    ];
    
    // total = 27. files = 100. penalty = 27 / 100 * 60 = 16.2. score = Math.round(100 - 16.2) = 84
    expect(calculateScore(mockFindings, 100)).toBe(84);

    // Should floor at 0
    const worstFindings = Array(10).fill({ severity: 'critical' });
    expect(calculateScore(worstFindings, 10)).toBe(0);
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

describe('Configuration Overrides', () => {
  it('should respect status overrides (string and object style)', () => {
    const code = `
      eval("const a = 1;"); // triggers SEC002
    `;

    // 1. Default config: triggers 1 finding (SEC002)
    const defaultScanner = new Scanner();
    expect(defaultScanner.scanFile('test.ts', code).length).toBe(1);

    // 2. String style 'off': should produce 0 findings
    const offStringScanner = new Scanner({
      config: {
        rules: {
          SEC002: 'off'
        }
      }
    });
    expect(offStringScanner.scanFile('test.ts', code).length).toBe(0);

    // 3. Object style status 'off': should produce 0 findings
    const offObjectScanner = new Scanner({
      config: {
        rules: {
          SEC002: { status: 'off' }
        }
      }
    });
    expect(offObjectScanner.scanFile('test.ts', code).length).toBe(0);
  });

  it('should respect severity overrides and correctly affect health scores', () => {
    const code = `
      eval("const a = 1;"); // triggers SEC002
    `;

    // 1. Default SEC002 has high severity (deducts 8 points)
    const scannerDefault = new Scanner();
    const findingsDefault = scannerDefault.scanFile('test.ts', code);
    expect(findingsDefault[0].severity).toBe('high');
    expect(calculateScore(findingsDefault, 100)).toBe(95); // 100 - 8/100*60 = 95.2 -> 95

    // 2. Override to critical (deducts 15 points)
    const scannerCritical = new Scanner({
      config: {
        rules: {
          SEC002: { severity: 'critical' }
        }
      }
    });
    const findingsCritical = scannerCritical.scanFile('test.ts', code);
    expect(findingsCritical[0].severity).toBe('critical');
    expect(calculateScore(findingsCritical, 100)).toBe(91); // 100 - 15/100*60 = 91

    // 3. Override to low (deducts 1 point)
    const scannerLow = new Scanner({
      config: {
        rules: {
          SEC002: { severity: 'low' }
        }
      }
    });
    const findingsLow = scannerLow.scanFile('test.ts', code);
    expect(findingsLow[0].severity).toBe('low');
    expect(calculateScore(findingsLow, 100)).toBe(99); // 100 - 1/100*60 = 99.4 -> 99
  });

  it('SEC012: Sensitive Data in Web Storage', () => {
    const code = `
      // Positive cases:
      localStorage.setItem('token', response.data.token);
      sessionStorage.setItem('apiKey', key);
      localStorage.setItem('password', pwd);
      sessionStorage.setItem("ligma:token", token);
      window.sessionStorage.setItem("ligma:token", token);
      window.localStorage.setItem("authToken", token);

      // Negative cases:
      localStorage.setItem('theme', 'dark');
      localStorage.setItem('authorId', post.authorId);
      localStorage.setItem('user', JSON.stringify(data.user));
      window.localStorage.setItem("app:theme", "dark");
      sessionStorage.setItem("homepage:settings:v2", JSON.stringify(settings));
    `;
    const scanner = new Scanner();
    const findings = scanner.scanFile('test-storage.ts', code);

    // Should have exactly 6 findings
    expect(findings.length).toBe(6);

    const tokenFinding = findings.find(f => f.message.includes('token') && !f.message.includes('ligma'));
    expect(tokenFinding).toBeDefined();
    expect(tokenFinding!.severity).toBe('high');

    const apiKeyFinding = findings.find(f => f.message.includes('apiKey'));
    expect(apiKeyFinding).toBeDefined();
    expect(apiKeyFinding!.severity).toBe('high');

    const pwdFinding = findings.find(f => f.message.includes('password'));
    expect(pwdFinding).toBeDefined();
    expect(pwdFinding!.severity).toBe('critical');

    // Verify colon-delimited and prefixed findings are flagged correctly
    const ligmaFindings = findings.filter(f => f.message.includes('ligma:token'));
    expect(ligmaFindings.length).toBe(2);
    expect(ligmaFindings.every(f => f.severity === 'high')).toBe(true);

    const authFinding = findings.find(f => f.message.includes('authToken'));
    expect(authFinding).toBeDefined();
    expect(authFinding!.severity).toBe('high');
  });
});

describe('SEC013: Row Level Security Cross-File Scanning', () => {
  it('should correctly flag tables missing RLS and pass tables with cross-file or same-file RLS', async () => {
    const scanner = new Scanner({
      cwd: process.cwd()
    });
    const findings = await scanner.scan('test/fixtures/sql');
    
    // Should find exactly 1 finding (foo is missing RLS)
    // bar has RLS in same file, baz has RLS in scripts/enable_baz.sql
    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe('SEC013');
    expect(findings[0].message).toContain('Table "foo" created in migrations is missing Row Level Security.');
    expect(findings[0].suggestedFix).toContain('Note: If RLS is enabled outside this repository\'s .sql files');
  });

  it('should not leak state between consecutive scans', async () => {
    const scanner = new Scanner({
      cwd: process.cwd()
    });
    
    // Scan 1
    const findings1 = await scanner.scan('test/fixtures/sql');
    expect(findings1.length).toBe(1);

    // Scan 2
    const findings2 = await scanner.scan('test/fixtures/sql');
    expect(findings2.length).toBe(1);
  });
});

