import { Rule, Finding } from './types.js';
import * as path from 'path';

let findings: Finding[] = [];

export const sec014PermissivePolicy: Rule = {
  id: 'SEC014',
  title: 'Permissive Supabase RLS Policy',
  severity: 'high',
  description: 'Supabase/Postgres RLS policies should not use USING (true) or WITH CHECK (true) as they grant unrestricted access.',
  agentInstruction: 'Avoid USING (true) or WITH CHECK (true) in RLS policies. Restrict access based on auth.uid() or other role-based checks.',

  createVisitor() {
    return {};
  },

  reset() {
    findings = [];
  },

  scanSql(filePath: string, content: string) {
    const relPath = path.relative(process.cwd(), filePath).replace(/\\/g, '/');
    const isMigration = relPath.includes('supabase/migrations/') ||
                        relPath.includes('migrations/') ||
                        relPath.includes('db/migrations/');
    if (!isMigration) return;

    const policyRegex = /CREATE\s+POLICY\s+(?:(?:"[^"]*")|(?:[a-zA-Z0-9_ -]+))\s+ON\s+(?:(?:[a-zA-Z0-9_"]+\.)?[a-zA-Z0-9_"]+)\s+[^;]*?(USING\s*\(\s*true\s*\)|WITH\s+CHECK\s*\(\s*true\s*\))/gi;

    let match;
    policyRegex.lastIndex = 0;
    while ((match = policyRegex.exec(content)) !== null) {
      const matchIdx = match.index;
      const precedingNewlines = content.slice(0, matchIdx).split('\n').length;
      findings.push({
        ruleId: 'SEC014',
        severity: 'high',
        message: `Permissive RLS policy detected. Policy allows unrestricted access via USING(true) or WITH CHECK(true).`,
        filePath,
        startLine: precedingNewlines,
        startColumn: 1,
        suggestedFix: `Restrict policy access using auth.uid() or specific role checks instead of (true).`
      });
    }
  },

  resolve() {
    return findings;
  }
};
