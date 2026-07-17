import * as fs from 'fs';
import * as path from 'path';
import { parse } from '@babel/parser';
import _traverse from '@babel/traverse';
import fg from 'fast-glob';
import pc from 'picocolors';
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
  public scannedFiles: string[] = [];

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

  private shouldSkipMinified(filePath: string, content: string): string | false {
    // 1. Sourcemap check
    const mapPath = filePath + '.map';
    if (fs.existsSync(mapPath)) {
      return 'sibling .map file detected';
    }

    const suffix = content.slice(-200);
    if (suffix.includes('//# sourceMappingURL=')) {
      return 'sourcemap comment detected';
    }

    // Exclude .sql files from the average-line-length minification skip
    if (filePath.endsWith('.sql')) {
      return false;
    }

    // 2. Average line length check
    const lines = content.split(/\r?\n/);
    const lineCount = lines.length || 1;
    const avgLineLen = content.length / lineCount;
    if (avgLineLen > 200) {
      return `avg line length ${Math.round(avgLineLen)} exceeds threshold`;
    }

    return false;
  }

  async scan(targetDir: string = '.', onProgress?: (index: number, total: number) => void): Promise<Finding[]> {
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

    // Find all JS/TS/SQL files
    const entries = await fg(['**/*.{js,ts,jsx,tsx,sql}'], {
      cwd: absoluteTargetDir,
      absolute: true,
      ignore: ignorePatterns,
      dot: true
    });

    this.scannedFiles = [...entries];

    const allFindings: Finding[] = [];
    const enabledRules = rules.filter(r => {
      const ruleConfig = this.config.rules?.[r.id] as any;
      if (ruleConfig) {
        if (typeof ruleConfig === 'string') {
          return ruleConfig !== 'off';
        }
        if (typeof ruleConfig === 'object') {
          return ruleConfig.status !== 'off';
        }
      }
      return true;
    });

    // Reset cross-file state for enabled rules
    for (const rule of enabledRules) {
      if (rule.reset) {
        rule.reset();
      }
    }

    const isJsonMode = process.argv.includes('--json');
    let index = 0;
    const total = entries.length;

    for (const filePath of entries) {
      try {
        index++;
        if (onProgress) {
          onProgress(index, total);
        }
        const content = fs.readFileSync(filePath, 'utf8');
        const skipReason = this.shouldSkipMinified(filePath, content);
        if (skipReason) {
          if (!isJsonMode) {
            const relPath = path.relative(this.cwd, filePath).replace(/\\/g, '/');
            console.log(pc.gray(`skipped ${relPath}: ${skipReason}`));
          }
          continue;
        }

        if (filePath.endsWith('.sql')) {
          for (const rule of enabledRules) {
            if (rule.scanSql) {
              rule.scanSql(filePath, content, this.config);
            }
          }
          continue;
        }

        const fileFindings = this.scanFile(filePath, content, enabledRules);
        allFindings.push(...fileFindings);
      } catch (err) {
        // Log parser errors or reading errors as warnings but don't fail the whole process
        console.warn(`Warning: Failed to scan file ${filePath}: ${(err as Error).message}`);
      }
    }

    // Resolve cross-file rules
    for (const rule of enabledRules) {
      if (rule.resolve) {
        const resolvedFindings = rule.resolve(this.config);
        allFindings.push(...resolvedFindings);
      }
    }

    return allFindings;
  }

  public scanFile(filePath: string, content: string, enabledRules?: Rule[]): Finding[] {
    const fileFindings: Finding[] = [];

    const targetRules = enabledRules || rules.filter(r => {
      const ruleConfig = this.config.rules?.[r.id] as any;
      if (ruleConfig) {
        if (typeof ruleConfig === 'string') {
          return ruleConfig !== 'off';
        }
        if (typeof ruleConfig === 'object') {
          return ruleConfig.status !== 'off';
        }
      }
      return true;
    });
    
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
    for (const rule of targetRules) {
      const context: RuleContext = {
        filePath,
        report: (nodeOrPath, message, suggestedFix, customSeverity) => {
          const node = nodeOrPath && (nodeOrPath.node ? nodeOrPath.node : nodeOrPath);
          const loc = node ? node.loc : null;
          if (loc) {
            let severity = customSeverity || rule.severity;
            const ruleConfig = this.config.rules?.[rule.id] as any;
            if (ruleConfig && typeof ruleConfig === 'object' && ruleConfig.severity) {
              severity = ruleConfig.severity as any;
            }
            fileFindings.push({
              ruleId: rule.id,
              severity,
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
        reportAt: (line, column, message, suggestedFix, customSeverity) => {
          let severity = customSeverity || rule.severity;
          const ruleConfig = this.config.rules?.[rule.id] as any;
          if (ruleConfig && typeof ruleConfig === 'object' && ruleConfig.severity) {
            severity = ruleConfig.severity as any;
          }
          fileFindings.push({
            ruleId: rule.id,
            severity,
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
