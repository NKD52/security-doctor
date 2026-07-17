import pc from 'picocolors';
import * as path from 'path';
import * as readline from 'readline';
import { Finding } from '../rules/types.js';
import { calculateScore } from '../score.js';

function getImprovementMessage(ruleId: string): string {
  switch (ruleId) {
    case 'SEC001':
      return 'Fixing this prevents accidental leakage of private API credentials and stops unauthorized API usage.';
    case 'SEC002':
      return 'Eliminating dynamic strings in execution prevents attackers from running arbitrary OS commands on the server.';
    case 'SEC003':
      return 'Enabling SSL verification prevents Man-in-the-Middle (MitM) attacks and ensures secure, encrypted remote connections.';
    case 'SEC004':
      return 'Restricting CORS wildcards ensures sensitive API endpoints cannot be queried by unauthorized cross-origin sites.';
    case 'SEC005':
      return 'Upgrading to modern cryptographic functions protects user data hashes against rapid offline brute-force cracking.';
    case 'SEC006':
      return 'Setting httpOnly and secure flags blocks client-side scripts from reading session ID cookies, mitigating XSS and session hijacking.';
    case 'SEC007':
      return 'Using parameterized queries makes SQL injection impossible, protecting the database against unauthorized access or destruction.';
    case 'SEC008':
      return 'Using safe argument arrays instead of string concatenation guarantees that users cannot execute arbitrary shell commands.';
    case 'SEC009':
      return 'Resolving and verifying boundaries prevents directory traversal, stopping users from reading or writing sensitive files on the disk.';
    case 'SEC010':
      return "Escaping or sanitizing dynamic HTML content prevents malicious scripts from executing in other users' browsers.";
    case 'SEC011':
      return 'Sanitizing query targets and restricting operator keys secures NoSQL queries against parameter-pollution bypasses and server-side JS execution.';
    default:
      return 'Improves overall application security compliance and reduces attack surface.';
  }
}

function getDeduction(severity: string): number {
  switch (severity) {
    case 'critical': return 15;
    case 'high': return 8;
    case 'medium': return 3;
    case 'low': return 1;
    default: return 0;
  }
}

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

function pause(message: string): Promise<void> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });
  return new Promise(resolve => {
    rl.question(message, () => {
      rl.close();
      resolve();
    });
  });
}

async function printGroupedFindings(
  findings: Finding[],
  isTTY: boolean,
  opts: { all?: boolean; paginationThreshold?: number }
): Promise<void> {
  const severities = ['critical', 'high', 'medium', 'low'] as const;
  const threshold = opts.paginationThreshold ?? 10;
  let accumulatedCount = 0;
  
  const severityWeights: Record<string, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1
  };

  const sortedFindings = [...findings].sort((a, b) => {
    const wa = severityWeights[a.severity] || 0;
    const wb = severityWeights[b.severity] || 0;
    return wb - wa;
  });

  console.log('\n' + pc.bold(`All ${findings.length} findings:\n`));

  for (let i = 0; i < severities.length; i++) {
    const sev = severities[i];
    const sevFindings = sortedFindings.filter(f => f.severity === sev);
    if (sevFindings.length === 0) continue;

    const grouped: Record<string, Finding[]> = {};
    for (const f of sevFindings) {
      if (!grouped[f.filePath]) {
        grouped[f.filePath] = [];
      }
      grouped[f.filePath].push(f);
    }

    const sevColor = 
      sev === 'critical' ? pc.red :
      sev === 'high' ? pc.yellow :
      sev === 'medium' ? pc.magenta :
      pc.blue;
    
    console.log(pc.bold(`${sevColor(sev.toUpperCase())} (${sevFindings.length})`));

    for (const [filePath, fileFindings] of Object.entries(grouped)) {
      const relPath = path.relative(process.cwd(), filePath).replace(/\\/g, '/');
      console.log(`  ${pc.underline(pc.cyan(relPath))}`);
      for (const f of fileFindings) {
        const loc = pc.gray(`${f.startLine}:${f.startColumn}`);
        console.log(`    ${loc}  ${pc.bold(f.ruleId)}: ${f.message}`);
        if (f.suggestedFix) {
          console.log(pc.green(`      👉 ${f.suggestedFix}`));
        }
        
        if (process.env.GITHUB_ACTIONS === 'true') {
          const annotationType = (f.severity === 'critical' || f.severity === 'high') ? 'error' : 'warning';
          console.log(`::${annotationType} file=${f.filePath},line=${f.startLine},col=${f.startColumn},title=${f.ruleId}::${f.message}`);
        }
      }
    }
    console.log('');

    accumulatedCount += sevFindings.length;

    if (isTTY && opts.all !== true && accumulatedCount >= threshold && accumulatedCount < sortedFindings.length) {
      const remaining = sortedFindings.length - accumulatedCount;
      const pauseMsg = pc.gray(`── ${remaining} more findings — press enter to continue, or Ctrl+C to stop, or re-run with --all to print everything at once ──`);
      await pause(pauseMsg + '\n');
    }
  }
}

export async function reportConsole(
  findings: Finding[],
  score: number,
  opts: { verbose?: boolean; scannedFilesCount?: number; all?: boolean; paginationThreshold?: number } = {}
): Promise<void> {
  if (findings.length === 0) {
    console.log(pc.green('\n✔ No security vulnerabilities found!'));
    console.log(`${pc.bold('Health Score:')} ${pc.green(`${score}/100`)}\n`);
    return;
  }

  const isVerbose = !!opts.verbose;

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
    await sleep(200);

    // Scanned files metrics summary
    const filesAffectedCount = new Set(findings.map(f => f.filePath)).size;
    console.log(pc.gray(`Scanned ${opts.scannedFilesCount || 0} files · ${findings.length} issues found · ${filesAffectedCount} files affected`));
    await sleep(200);

    // Category/severity counts compact one-line summary
    const critical = findings.filter(f => f.severity === 'critical').length;
    const high = findings.filter(f => f.severity === 'high').length;
    const medium = findings.filter(f => f.severity === 'medium').length;
    const low = findings.filter(f => f.severity === 'low').length;

    const severityParts: string[] = [];
    if (critical > 0) severityParts.push(`${critical} critical`);
    if (high > 0) severityParts.push(`${high} high`);
    if (medium > 0) severityParts.push(`${medium} medium`);
    if (low > 0) severityParts.push(`${low} low`);

    const severitySummary = severityParts.length > 0 ? `Security > ${severityParts.join(', ')}` : '';
    if (severitySummary) {
      console.log(pc.gray(severitySummary));
    }
    await sleep(200);
    console.log(''); // Blank line before Top Issue

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

    const remainingFindings = findings.filter(f => f !== topIssue);
    const scoreWithFinding = calculateScore(findings);
    const scoreWithoutTopIssue = calculateScore(remainingFindings);
    const delta = scoreWithoutTopIssue - scoreWithFinding;
    const newScore = scoreWithoutTopIssue;
    const topIssueRelPath = path.relative(process.cwd(), topIssue.filePath).replace(/\\/g, '/');

    console.log(pc.bold(pc.red('🚨 TOP ISSUE')));
    console.log(`  ${pc.bold(topIssue.ruleId)} · ${topIssue.severity.toUpperCase()} · ${topIssueRelPath}:${topIssue.startLine}:${topIssue.startColumn}`);
    console.log('');
    console.log(`  ${topIssue.message}`);
    if (topIssue.suggestedFix) {
      console.log(pc.green(`  👉 Fix: ${topIssue.suggestedFix}`));
    }
    console.log(pc.cyan(`  📈 Impact: Fixing this raises your score to ${newScore}/100 (+${delta})`));
    console.log('\n' + pc.gray('─'.repeat(totalBoxWidth)));
    await sleep(200);

    // If not verbose, skip printing full list details and print help tip
    if (!isVerbose) {
      console.log('\n' + pc.gray(`💡 Tip: Found ${findings.length} total vulnerabilities. Use the --verbose flag to display the full list of findings.`));
      return;
    }

    // Verbose TTY Output
    await printGroupedFindings(findings, true, opts);

    const totalDeduction = findings.reduce((sum, f) => sum + getDeduction(f.severity), 0);
    const maxPossibleScore = Math.min(100, score + totalDeduction);
    console.log(`You could improve to ${maxPossibleScore}/100 by fixing all ${findings.length} issues.`);
    console.log(pc.gray('─'.repeat(totalBoxWidth)));
    return;
  }

  // Non-interactive Mode (plain output)
  if (isVerbose) {
    await printGroupedFindings(findings, false, opts);
  } else {
    console.log(pc.bold(`Found ${findings.length} vulnerabilities:\n`));

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
          console.log(pc.green(`    👉 ${f.suggestedFix}`));
        }

        if (process.env.GITHUB_ACTIONS === 'true') {
          const annotationType = (f.severity === 'critical' || f.severity === 'high') ? 'error' : 'warning';
          console.log(`::${annotationType} file=${f.filePath},line=${f.startLine},col=${f.startColumn},title=${f.ruleId}::${f.message}`);
        }
      }
      console.log('');
    }
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
