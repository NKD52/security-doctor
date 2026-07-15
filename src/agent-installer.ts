import * as fs from 'fs';
import * as path from 'path';
import pc from 'picocolors';
import { rules } from './rules/index.js';

function getInstructionBlock(): string {
  const lines = [
    '### AI Security Guidelines (via security-doctor)',
    '',
    'To prevent security vulnerabilities, always adhere to the following guidelines during code generation and modification:'
  ];

  let index = 1;
  for (const rule of rules) {
    if (rule.agentInstruction) {
      lines.push(`${index}. **${rule.title} (${rule.id})**: ${rule.agentInstruction}`);
      index++;
    }
  }

  return lines.join('\n') + '\n';
}

export function installAgentInstructions(cwd: string = process.cwd()): void {
  let detectedCount = 0;
  
  // 1. Cursor Check
  const cursorDirExists = fs.existsSync(path.resolve(cwd, '.cursor'));
  const cursorRulesPath = path.resolve(cwd, '.cursorrules');
  const cursorRulesExists = fs.existsSync(cursorRulesPath);
  
  if (cursorDirExists || cursorRulesExists) {
    detectedCount++;
    updateRuleFile(cursorRulesPath, 'Cursor (.cursorrules)');
  }
  
  // 2. Claude Code Check
  const claudeDirExists = fs.existsSync(path.resolve(cwd, '.claude'));
  const claudeMdPath = path.resolve(cwd, 'CLAUDE.md');
  const claudeMdExists = fs.existsSync(claudeMdPath);
  
  if (claudeDirExists || claudeMdExists) {
    detectedCount++;
    updateRuleFile(claudeMdPath, 'Claude Code (CLAUDE.md)');
  }
  
  // 3. GitHub Copilot Check
  const githubDirExists = fs.existsSync(path.resolve(cwd, '.github'));
  const copilotInstructionsPath = path.resolve(cwd, '.github/copilot-instructions.md');
  const copilotInstructionsExists = fs.existsSync(copilotInstructionsPath);
  
  if (githubDirExists || copilotInstructionsExists) {
    detectedCount++;
    // Create .github dir if it doesn't exist but github directory exists
    if (!fs.existsSync(path.resolve(cwd, '.github'))) {
      fs.mkdirSync(path.resolve(cwd, '.github'));
    }
    updateRuleFile(copilotInstructionsPath, 'GitHub Copilot (.github/copilot-instructions.md)');
  }
  
  if (detectedCount === 0) {
    console.log(pc.yellow('\n⚠ No active AI agent configurations detected in the workspace.'));
    console.log(pc.gray('Checked for: .cursorrules, CLAUDE.md, .github/copilot-instructions.md, or agent configuration directories (.cursor/, .claude/, .github/).'));
    console.log(`\nIf you want to initialize them manually, you can create a ${pc.cyan('.cursorrules')} or ${pc.cyan('CLAUDE.md')} file and run ${pc.bold('security-doctor --install')} again.`);
  } else {
    console.log(pc.green(`\n✔ Completed! Updated instructions for ${detectedCount} detected coding agent(s).\n`));
  }
}

function updateRuleFile(filePath: string, agentName: string): void {
  try {
    let content = '';
    if (fs.existsSync(filePath)) {
      content = fs.readFileSync(filePath, 'utf8');
    }
    
    if (content.includes('security-doctor')) {
      console.log(pc.gray(`- ${agentName} already has security-doctor instructions. Skipping.`));
      return;
    }
    
    const separator = content.length > 0 ? '\n\n' : '';
    const instructionBlock = getInstructionBlock();
    fs.writeFileSync(filePath, content + separator + instructionBlock.trim() + '\n', 'utf8');
    console.log(pc.green(`- Updated ${agentName} successfully.`));
  } catch (err) {
    console.error(pc.red(`Error writing to ${filePath}: ${(err as Error).message}`));
  }
}
