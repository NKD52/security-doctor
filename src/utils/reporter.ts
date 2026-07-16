import pc from 'picocolors';
import { Finding } from '../rules/types.js';

export function reportConsole(findings: Finding[], score: number): void {
  if (findings.length === 0) {
    console.log(pc.green('\n✔ No security vulnerabilities found!'));
    console.log(`${pc.bold('Health Score:')} ${pc.green(`${score}/100`)}\n`);
    return;
  }

  // Check if we are running in an interactive terminal (TTY)
  if (process.stdout.isTTY) {
    const barLength = 20;
    const filledCount = Math.round((score / 100) * barLength);
    const emptyCount = barLength - filledCount;
    const bar = '█'.repeat(filledCount) + '░'.repeat(emptyCount);
    
    let label = 'Good';
    let labelColor = pc.green;
    if (score < 50) {
      label = 'Critical';
      labelColor = pc.red;
    } else if (score < 70) {
      label = 'Poor';
      labelColor = pc.red;
    } else if (score < 90) {
      label = 'Fair';
      labelColor = pc.yellow;
    }

    const scoreText = `${score}/100`;
    const rawLine = `  Health Score: [${bar}] ${scoreText} (${label})`;
    const totalBoxWidth = 60;
    const paddingNeeded = totalBoxWidth - rawLine.length - 4; // 4 for '│ ' and ' │'
    const coloredLine = `│  Health Score: [${bar}] ${scoreText} (${labelColor(label)})` + ' '.repeat(Math.max(0, paddingNeeded)) + '│';

    console.log('\n┌' + '─'.repeat(totalBoxWidth - 2) + '┐');
    console.log(coloredLine);
    console.log('└' + '─'.repeat(totalBoxWidth - 2) + '┘\n');

    // SURFACING TOP ISSUE
    const severityWeights: Record<string, number> = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1
    };

    let topIssue = findings[0];
    for (const f of findings) {
      if (severityWeights[f.severity] > severityWeights[topIssue.severity]) {
        topIssue = f;
      }
    }

    const topSevColor = 
      topIssue.severity === 'critical' ? pc.red :
      topIssue.severity === 'high' ? pc.yellow :
      topIssue.severity === 'medium' ? pc.magenta :
      pc.blue;

    console.log(pc.bold(pc.red('🚨 TOP ISSUE:')));
    console.log(`  ${pc.bold(topIssue.ruleId)} (${topIssue.filePath}:${topIssue.startLine}:${topIssue.startColumn})`);
    console.log(`  Severity: ${topSevColor(topIssue.severity.toUpperCase())}`);
    console.log(`  Message:  ${topIssue.message}`);
    if (topIssue.suggestedFix) {
      console.log(pc.green(`  👉 Fix:    ${topIssue.suggestedFix}`));
    }
    console.log('\n' + pc.gray('─'.repeat(totalBoxWidth)) + '\n');
  }

  console.log(pc.bold(`Found ${findings.length} vulnerabilities:\n`));

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
