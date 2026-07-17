import { Rule, Finding } from './types.js';
import * as path from 'path';

interface TableLocation {
  filePath: string;
  line: number;
  column: number;
}

let tablesCreated = new Map<string, TableLocation>();
let rlsEnabled = new Set<string>();

export const sec013Rls: Rule = {
  id: 'SEC013',
  title: 'Postgres Row Level Security (RLS) Missing',
  severity: 'critical',
  description: 'Supabase/Postgres tables created in migration scripts must have Row Level Security enabled.',
  agentInstruction: 'Always ensure ALTER TABLE {table} ENABLE ROW LEVEL SECURITY; is executed for all tables created in migrations.',
  
  createVisitor() {
    return {};
  },

  reset() {
    tablesCreated.clear();
    rlsEnabled.clear();
  },

  scanSql(filePath: string, content: string) {
    const relPath = path.relative(process.cwd(), filePath).replace(/\\/g, '/');
    const isMigration = relPath.includes('supabase/migrations/') ||
                        relPath.includes('migrations/') ||
                        relPath.includes('db/migrations/');

    const lines = content.split(/\r?\n/);
    
    // 1. Scan for CREATE TABLE if it's in migration directories
    if (isMigration) {
      const createTableRegex = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:[a-zA-Z0-9_"]+\.)?([a-zA-Z0-9_"]+)/i;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const match = createTableRegex.exec(line);
        if (match) {
          const tableName = match[1].replace(/"/g, '').toLowerCase();
          if (!tablesCreated.has(tableName)) {
            const startCol = match.index;
            tablesCreated.set(tableName, {
              filePath,
              line: i + 1,
              column: startCol + 1
            });
          }
        }
      }
    }

    // 2. Scan for ALTER TABLE ... ENABLE ROW LEVEL SECURITY globally across all files
    const rlsRegex = /ALTER\s+TABLE\s+(?:(?:[a-zA-Z0-9_"]+\.)?([a-zA-Z0-9_"]+))\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY/i;
    for (const line of lines) {
      const match = rlsRegex.exec(line);
      if (match) {
        const tableName = match[1].replace(/"/g, '').toLowerCase();
        rlsEnabled.add(tableName);
      }
    }
  },

  resolve(): Finding[] {
    const findings: Finding[] = [];
    for (const [tableName, loc] of tablesCreated.entries()) {
      if (!rlsEnabled.has(tableName)) {
        findings.push({
          ruleId: 'SEC013',
          severity: 'critical',
          message: `Table "${tableName}" created in migrations is missing Row Level Security.`,
          filePath: loc.filePath,
          startLine: loc.line,
          startColumn: loc.column,
          suggestedFix: `Enable row level security: ALTER TABLE ${tableName} ENABLE ROW LEVEL SECURITY. Note: If RLS is enabled outside this repository's .sql files (e.g. via the Supabase dashboard, an API call, or a naming/whitespace variant this scan doesn't recognize), this may be a false positive — verify directly before treating as a gap.`
        });
      }
    }
    return findings;
  }
};
