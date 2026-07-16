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

  it('SEC008: should flag positive Command Injection cases and suppress SEC002', () => {
    const code = `
      // Positive Case 1: Direct exec with untrusted input string concatenation
      app.get('/run', (req, res) => {
        const cmd = req.query.cmd;
        exec("ping -c 1 " + cmd);
      });

      // Positive Case 2: Template literal command interpolation via member expression
      function executeCommand(req, res) {
        const { file } = req.body;
        child_process.execSync(\`ls -la \${file}\`);
      }
    `;

    const findings = scanner.scanFile('test-command-vulnerable.ts', code);
    
    // Expect exactly 2 findings (both should be SEC008, SEC002 should be suppressed)
    expect(findings.length).toBe(2);
    
    expect(findings[0].ruleId).toBe('SEC008');
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].message).toContain('Potential Command Injection vulnerability');

    expect(findings[1].ruleId).toBe('SEC008');
    expect(findings[1].severity).toBe('critical');
    expect(findings[1].message).toContain('Potential Command Injection vulnerability');
  });

  it('SEC008: should NOT flag safe Command Injection cases (execFile, spawn, numeric sanitizer, and ORM)', () => {
    const code = `
      // Negative Case 1: execFile call (Safe by Omission)
      app.get('/run', (req, res) => {
        const cmd = req.query.cmd;
        child_process.execFile('ping', ['-c', '1', cmd]);
      });

      // Negative Case 2: spawn call (Safe by Omission)
      app.get('/run', (req, res) => {
        const cmd = req.query.cmd;
        child_process.spawn('ping', ['-c', '1', cmd]);
      });

      // Negative Case 3: Numeric Sanitization (Short-circuit)
      app.get('/run', (req, res) => {
        const count = parseInt(req.query.count, 10);
        exec(\`ping -c \${count} 8.8.8.8\`);
      });
      
      // Negative Case 4: ORM/DB methods using the same inputs (No overlap)
      app.post('/login', (req, res) => {
        const cmd = req.body.cmd;
        User.findOne({ where: { cmd } });
      });
    `;

    const findings = scanner.scanFile('test-command-safe.ts', code);
    
    // SEC008 (Command Injection) should NOT trigger
    const sec008Findings = findings.filter(f => f.ruleId === 'SEC008');
    expect(sec008Findings.length).toBe(0);

    // SEC002 should trigger exactly once for Case 3 (untainted exec)
    const sec002Findings = findings.filter(f => f.ruleId === 'SEC002');
    expect(sec002Findings.length).toBe(1);
    expect(sec002Findings[0].severity).toBe('high');
  });

  it('should verify SEC002 vs SEC008 exact-count and overlap suppression', () => {
    // 1. Tainted command -> triggers SEC008 only (1 finding)
    const taintedCode = `
      function run(req, res) {
        const cmd = req.query.cmd;
        exec("ls " + cmd);
      }
    `;
    const taintedFindings = scanner.scanFile('tainted.ts', taintedCode);
    expect(taintedFindings.length).toBe(1);
    expect(taintedFindings[0].ruleId).toBe('SEC008');
    expect(taintedFindings[0].severity).toBe('critical');

    // 2. Untainted / Hardcoded command -> triggers SEC002 only (1 finding)
    const untaintedCode = `
      function run(req, res) {
        exec("ls -la 8.8.8.8");
      }
    `;
    const untaintedFindings = scanner.scanFile('untainted.ts', untaintedCode);
    expect(untaintedFindings.length).toBe(1);
    expect(untaintedFindings[0].ruleId).toBe('SEC002');
    expect(untaintedFindings[0].severity).toBe('high');
  });

  it('SEC009: should flag positive Path Traversal cases including unsafe startsWith prefix checks', () => {
    const code = `
      // Positive Case 1: Unsanitized File Access
      app.get('/read', (req, res) => {
        const file = req.query.file;
        fs.readFile(file, 'utf8', (err, data) => {});
      });

      // Positive Case 2: Insecure startsWith prefix check (no trailing separator)
      app.get('/read', (req, res) => {
        const file = req.query.file;
        const safePath = path.resolve('/var/www/uploads', file);
        if (safePath.startsWith('/var/www/uploads')) { // Vulnerable to uploads-evil prefix bypass
          fs.readFile(safePath, 'utf8', (err, data) => {});
        }
      });
    `;

    const findings = scanner.scanFile('test-path-vulnerable.ts', code);
    expect(findings.length).toBe(2);
    
    expect(findings[0].ruleId).toBe('SEC009');
    expect(findings[0].severity).toBe('critical');
    
    expect(findings[1].ruleId).toBe('SEC009');
    expect(findings[1].severity).toBe('critical');
  });

  it('SEC009: should NOT flag safe Path Traversal cases (proper startsWith checks, safe path.sep checks)', () => {
    const code = `
      // Negative Case 1: Path resolved and verified using startsWith with trailing slash
      app.get('/read', (req, res) => {
        const file = req.query.file;
        const safePath = path.resolve('/var/www/uploads', file);
        if (safePath.startsWith('/var/www/uploads/')) { // Safe trailing slash
          fs.readFile(safePath, 'utf8', (err, data) => {});
        }
      });

      // Negative Case 2: Path resolved and verified using startsWith + path.sep
      app.get('/read', (req, res) => {
        const file = req.query.file;
        const safePath = path.resolve(base, file);
        if (safePath.startsWith(base + path.sep)) { // Safe path.sep
          fs.readFile(safePath, 'utf8', (err, data) => {});
        }
      });
    `;

    const findings = scanner.scanFile('test-path-safe.ts', code);
    expect(findings.length).toBe(0);
  });

  it('SEC010: XSS / HTML Injection', () => {
    const code = `
      // Server-side Positive Case: Tainted value in HTML response (XSS)
      app.get('/xss', (req, res) => {
        const name = req.query.name;
        res.send("<div>" + name + "</div>");
      });

      // Server-side Negative Case 1: Sanitized response (safe)
      app.get('/clean1', (req, res) => {
        const name = req.query.name;
        const clean = escapeHtml(name);
        res.send("<div>" + clean + "</div>");
      });

      // Server-side Negative Case 2: API Response (JSON, safe)
      app.get('/json', (req, res) => {
        const name = req.query.name;
        res.json({ user: name });
      });

      // Client-side Positive Case 1: Unsanitized template literal innerHTML
      function renderNavbar(user) {
        navLinks.innerHTML = \`<li>Profile (\${user.username})</li>\`;
      }

      // Client-side Positive Case 2: Loop concatenation and rendering
      function renderProducts(products) {
        let cardsHTML = '';
        products.forEach(p => {
          cardsHTML += \`<h3>\${p.name}</h3>\`;
        });
        grid.innerHTML = cardsHTML;
      }

      // Client-side Negative Case 1: Sanitized template literal
      function renderNavbarSafe(user) {
        el.innerHTML = \`<li>Profile (\${escapeHtml(user.username)})</li>\`;
      }

      // Client-side Negative Case 2: Static content
      function renderStatic() {
        el.innerHTML = '<li>Static content</li>';
      }

      // Client-side Negative Case 3: Safe textContent assignment
      function renderText(anything) {
        el.textContent = \`\${anything}\`;
      }
    `;
    const findings = scanner.scanFile('test-xss.ts', code);
    expect(findings.length).toBe(3);
    
    const sec010Findings = findings.filter(f => f.ruleId === 'SEC010');
    expect(sec010Findings.length).toBe(3);
    
    // Check that one of the findings is on the grid.innerHTML assignment
    const gridFinding = sec010Findings.find(f => f.message.includes("assigned to 'innerHTML'") && f.startLine > 25);
    expect(gridFinding).toBeDefined();
  });

  it('SEC011: NoSQL Injection', () => {
    const code = `
      // Positive Case 1: Entire filter object user-controlled
      app.get('/nosql1', (req, res) => {
        const filter = req.query;
        db.collection.find(filter);
      });

      // Positive Case 2: Tainted target inside operator ($where evaluation)
      app.get('/nosql2', (req, res) => {
        const user = req.body.username;
        db.users.findOne({ $where: "this.username === '" + user + "'" });
      });

      // Negative Case 1: Hardcoded keys with leaf taint (safe)
      app.get('/nosql-safe1', (req, res) => {
        const user = req.body.username;
        db.users.find({ username: user });
      });

      // Negative Case 2: Sanitized / Coerced values (safe)
      app.get('/nosql-safe2', (req, res) => {
        const user = req.body.username;
        db.users.findOne({ $where: String(user) });
      });

      // Negative Case 3: Types.ObjectId coercion (safe)
      app.get('/nosql-safe3', (req, res) => {
        const id = req.query.id;
        db.users.deleteOne({ _id: mongoose.Types.ObjectId(id) });
      });

      // Negative Case 4: Array.find False Positive Check (safe)
      app.get('/array-find', (req, res) => {
        const id = req.query.id;
        const user = items.find(x => x.id === id);
      });
    `;
    const findings = scanner.scanFile('test-nosql.ts', code);
    expect(findings.length).toBe(2);
    
    expect(findings[0].ruleId).toBe('SEC011');
    expect(findings[0].severity).toBe('critical');
    expect(findings[0].message).toContain('entire query filter object');

    expect(findings[1].ruleId).toBe('SEC011');
    expect(findings[1].severity).toBe('critical');
    expect(findings[1].message).toContain('query operator');
  });
});
