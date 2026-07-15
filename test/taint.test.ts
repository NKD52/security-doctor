import { describe, it, expect } from 'vitest';
import { Scanner } from '../src/engine.js';

describe('SEC007: SQL Injection Taint Tracking', () => {
  const scanner = new Scanner();

  it('should flag positive cases (vulnerable code)', () => {
    const code = `
      // Positive Case 1: Direct concatenation in query
      app.post('/login', (req, res) => {
        const email = req.body.email;
        const query = "SELECT * FROM users WHERE email = '" + email + "'";
        db.query(query);
      });

      // Positive Case 2: Template literal interpolation
      function getUser(req, res) {
        const { id } = req.query;
        const query = \`SELECT * FROM users WHERE id = \${id}\`;
        connection.execute(query);
      }
    `;

    const findings = scanner.scanFile('test-vulnerable.ts', code);
    expect(findings.length).toBe(2);
    
    expect(findings[0].ruleId).toBe('SEC007');
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].message).toContain('Potential SQL Injection vulnerability');

    expect(findings[1].ruleId).toBe('SEC007');
    expect(findings[1].severity).toBe('critical');
    expect(findings[1].message).toContain('Potential SQL Injection vulnerability');
  });

  it('should NOT flag negative cases (safe code / sanitizers)', () => {
    const code = `
      // Negative Case 1: Parameterized Query
      app.post('/login', (req, res) => {
        const email = req.body.email;
        db.query('SELECT * FROM users WHERE email = ?', [email]);
      });

      // Negative Case 2: ORM Method call (Short-circuit / omission)
      app.post('/login', (req, res) => {
        const email = req.body.email;
        User.findOne({ where: { email } });
      });

      // Negative Case 3: Parsed Input (Sanitizer)
      function getUser(req, res) {
        const id = parseInt(req.query.id, 10);
        const query = \`SELECT * FROM users WHERE id = \${id}\`;
        db.query(query);
      }

      // Negative Case 4: False Positive Prevention (Unrelated client name)
      function queryQueue(req, res) {
        const text = req.query.text;
        jobQueue.query(text); // method is query, but receiver 'jobQueue' is not a database client
      }
    `;

    const findings = scanner.scanFile('test-safe.ts', code);
    expect(findings.length).toBe(0);
  });

  it('should respect custom dbClients configured via Scanner options', () => {
    const code = `
      function getUser(req, res) {
        const id = req.query.id;
        const query = \`SELECT * FROM users WHERE id = \${id}\`;
        customClient.query(query);
      }
    `;

    // Without config override, customClient is not recognized as a database client (0 findings)
    const findingsDefault = scanner.scanFile('test-custom.ts', code);
    expect(findingsDefault.length).toBe(0);

    // With config override, customClient is recognized and flags a finding (1 finding)
    const customScanner = new Scanner({
      config: {
        dbClients: ['customClient']
      }
    });
    const findingsWithConfig = customScanner.scanFile('test-custom.ts', code);
    expect(findingsWithConfig.length).toBe(1);
    expect(findingsWithConfig[0].ruleId).toBe('SEC007');
    expect(findingsWithConfig[0].severity).toBe('critical');
  });
});
