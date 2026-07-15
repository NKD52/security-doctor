import pc from 'picocolors';
import { Finding } from '../rules/types.js';

export function reportConsole(findings: Finding[], score: number): void {
  if (findings.length === 0) {
    console.log(pc.green('\n✔ No security vulnerabilities found!'));
    console.log(`${pc.bold('Health Score:')} ${pc.green(`${score}/100`)}\n`);
    return;
  }

  console.log(pc.bold(`\nFound ${findings.length} vulnerabilities:\n`));

  // Group by file
  const grouped: Record<string, Finding[]> = {};
  for (const f of findings) {
    if (!grouped[f.filePath]) {
      grouped[f.filePath] = [];
    }
    grouped[f.filePath].push(f);
  }

  for (const [filePath, fileFindings] of Object.entries(grouped)) {
    console.log(pc.underline(pc.cyan(filePath)));
    for (const f of fileFindings) {
      const sevColor = 
        f.severity === 'critical' ? pc.red :
        f.severity === 'high' ? pc.yellow :
        f.severity === 'medium' ? pc.magenta :
        pc.blue;
        
      const badge = sevColor(`[${f.severity.toUpperCase()}]`);
      const loc = pc.gray(`${f.startLine}:${f.startColumn}`);
      console.log(`  ${loc}  ${badge} ${pc.bold(f.ruleId)}: ${f.message}`);
      if (f.suggestedFix) {
        console.log(pc.green(`    👉 Suggested Fix: ${f.suggestedFix}`));
      }

      if (process.env.GITHUB_ACTIONS === 'true') {
        const annotationType = (f.severity === 'critical' || f.severity === 'high') ? 'error' : 'warning';
        console.log(`::${annotationType} file=${f.filePath},line=${f.startLine},col=${f.startColumn},title=${f.ruleId}::${f.message}`);
      }
    }
    console.log('');
  }

  // Score coloring
  const scoreColor = 
    score >= 90 ? pc.green :
    score >= 70 ? pc.yellow :
    pc.red;

  console.log(`${pc.bold('Health Score:')} ${scoreColor(`${score}/100`)}`);
  if (score < 100) {
    console.log(pc.gray(`Deductions based on severity levels: Critical (-15), High (-8), Medium (-3), Low (-1)`));
  }
  console.log('');
}

export function reportJson(findings: Finding[], score: number): void {
  console.log(JSON.stringify({ score, findings }, null, 2));
}
