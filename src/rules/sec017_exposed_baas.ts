import { Rule, Finding } from './types.js';
import fg from 'fast-glob';
import * as fs from 'fs';
import * as path from 'path';

let findings: Finding[] = [];

export const sec017ExposedBaas: Rule = {
  id: 'SEC017',
  title: 'BaaS Configuration and Sensitive Fields Exposed in Build Output',
  severity: 'medium',
  description: 'Detects Supabase or Firebase client configurations bundled alongside sensitive authorization fields or table references in production build files.',
  agentInstruction: 'Avoid embedding backend credentials or exposing sensitive collection/field structures directly in client-side bundles.',

  createVisitor() {
    return {};
  },

  reset() {
    findings = [];
  },

  resolve(config, targetDir) {
    const projectRoot = process.cwd();
    const files = fg.sync(
      ['**/dist/**/*.{js,css,html}', '**/build/**/*.{js,css,html}', '**/.next/**/*.{js,css,html}'],
      { cwd: projectRoot, absolute: true, dot: true }
    );

    const filterDir = targetDir ? path.resolve(targetDir) : projectRoot;
    const filteredFiles = files.filter(file => {
      const relative = path.relative(filterDir, file);
      return !relative.startsWith('..') && !path.isAbsolute(relative);
    });

    const baasPatterns = [
      /supabase\.co/gi,
      /firebaseio\.com/gi,
      /createClient\(/gi,
      /initializeApp\(/gi
    ];
    
    const sensitiveFields = ['role', 'admin', 'tenant_id', 'org_id', 'owner_id', 'is_admin'];

    for (const filePath of filteredFiles) {
      try {
        const content = fs.readFileSync(filePath, 'utf8');

        for (const pattern of baasPatterns) {
          let match;
          pattern.lastIndex = 0;
          while ((match = pattern.exec(content)) !== null) {
            const matchIdx = match.index;
            const start = Math.max(0, matchIdx - 1000);
            const end = Math.min(content.length, matchIdx + 1000);
            const windowText = content.slice(start, end);

            const foundField = sensitiveFields.find(field => {
              const regex = new RegExp(`\\b${field}\\b`, 'i');
              return regex.test(windowText);
            });

            if (foundField) {
              const precedingNewlines = content.slice(0, matchIdx).split('\n').length;
              findings.push({
                ruleId: 'SEC017',
                severity: 'medium',
                message: `BaaS config and sensitive field '${foundField}' exposed in build output. Note: Manual verification is needed to confirm if this exposes access controls.`,
                filePath,
                startLine: precedingNewlines,
                startColumn: 1,
                suggestedFix: `Restrict client-side queries or enforce Server-Side Rendering (SSR) for sensitive operations so database configurations and keys are not bundled in build output.`
              });
              break;
            }
          }
          if (findings.some(f => f.filePath === filePath)) {
            break;
          }
        }
      } catch (err) {
        // Ignore read errors
      }
    }

    return findings;
  }
};
