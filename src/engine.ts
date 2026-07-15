import * as fs from 'fs';
import * as path from 'path';
import { parse } from '@babel/parser';
import _traverse from '@babel/traverse';
import fg from 'fast-glob';
import { rules } from './rules/index.js';
import { Finding, Rule, RuleContext, Config } from './rules/types.js';

// Workaround for Babel traverse ESM/CJS import issues
const traverse = (_traverse as any).default || _traverse;

export function loadConfig(cwd: string = process.cwd()): Config {
  const configPath = path.resolve(cwd, 'security-doctor.config.json');
  if (fs.existsSync(configPath)) {
    try {
      return JSON.parse(fs.readFileSync(configPath, 'utf8'));
    } catch (e) {
      console.warn(`Warning: Failed to parse security-doctor.config.json: ${(e as Error).message}`);
    }
  }
  
  const pkgPath = path.resolve(cwd, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      if (pkg.securityDoctor) {
        return pkg.securityDoctor;
      }
    } catch (e) {}
  }
  
  return {};
}

export interface ScanOptions {
  cwd?: string;
  diffLines?: Record<string, Set<number>>;
  config?: Config;
}

export class Scanner {
  private cwd: string;
  private config: Config;
  private diffLines?: Record<string, Set<number>>;

  constructor(options: ScanOptions = {}) {
    this.cwd = options.cwd || process.cwd();
    this.config = options.config || loadConfig(this.cwd);
    if (options.diffLines) {
      this.diffLines = {};
      for (const [key, value] of Object.entries(options.diffLines)) {
        const normalizedKey = key.replace(/\\/g, '/');
        this.diffLines[normalizedKey] = value;
      }
    }
  }

  async scan(targetDir: string = '.'): Promise<Finding[]> {
    const absoluteTargetDir = path.resolve(this.cwd, targetDir);
    
    // Resolve ignore patterns
    const defaultIgnores = [
      '**/node_modules/**',
      '**/dist/**',
      '**/build/**',
      '**/.git/**',
      '**/.next/**',
      '**/coverage/**'
    ];
    const customIgnores = this.config.ignorePaths || [];
    const ignorePatterns = [...defaultIgnores, ...customIgnores];

    // Find all JS/TS files
    const entries = await fg(['**/*.{js,ts,jsx,tsx}'], {
      cwd: absoluteTargetDir,
      absolute: true,
      ignore: ignorePatterns,
      dot: true
    });

    const allFindings: Finding[] = [];
    const enabledRules = rules.filter(r => {
      const ruleConfig = this.config.rules?.[r.id];
      return ruleConfig !== 'off';
    });

    for (const filePath of entries) {
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        const fileFindings = this.scanFile(filePath, content, enabledRules);
        allFindings.push(...fileFindings);
      } catch (err) {
        // Log parser errors or reading errors as warnings but don't fail the whole process
        console.warn(`Warning: Failed to scan file ${filePath}: ${(err as Error).message}`);
      }
    }

    return allFindings;
  }

  public scanFile(filePath: string, content: string, enabledRules: Rule[] = rules): Finding[] {
    const fileFindings: Finding[] = [];
    
    // Parse the code to AST
    const ast = parse(content, {
      sourceType: 'module',
      allowImportExportEverywhere: true,
      plugins: [
        'typescript',
        'jsx',
        ['decorators', { decoratorsBeforeExport: true }],
        'classProperties',
        'classPrivateProperties',
        'classPrivateMethods',
        'objectRestSpread',
        'dynamicImport',
        'exportDefaultFrom'
      ]
    });

    // Run rules
    for (const rule of enabledRules) {
      const context: RuleContext = {
        filePath,
        report: (nodeOrPath, message, suggestedFix) => {
          const node = nodeOrPath && (nodeOrPath.node ? nodeOrPath.node : nodeOrPath);
          const loc = node ? node.loc : null;
          if (loc) {
            fileFindings.push({
              ruleId: rule.id,
              severity: rule.severity,
              message,
              filePath,
              startLine: loc.start.line,
              startColumn: loc.start.column,
              endLine: loc.end.line,
              endColumn: loc.end.column,
              suggestedFix
            });
          }
        },
        reportAt: (line, column, message, suggestedFix) => {
          fileFindings.push({
            ruleId: rule.id,
            severity: rule.severity,
            message,
            filePath,
            startLine: line,
            startColumn: column,
            suggestedFix
          });
        },
        config: this.config
      };

      const visitor = rule.createVisitor(context);
      traverse(ast, visitor);
    }

    if (this.diffLines) {
      const normalizedPath = filePath.replace(/\\/g, '/');
      const changedLines = this.diffLines[normalizedPath];
      if (changedLines) {
        return fileFindings.filter(f => changedLines.has(f.startLine));
      }
      return [];
    }

    return fileFindings;
  }
}
