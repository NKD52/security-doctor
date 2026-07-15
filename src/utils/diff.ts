import { execSync } from 'child_process';
import * as path from 'path';

/**
 * Parses git diff output to find the exact lines that were modified/added in each file.
 * Returns a mapping of absolute file paths to a Set of modified line numbers.
 */
export function getChangedLines(base: string, cwd: string = process.cwd()): Record<string, Set<number>> {
  const result: Record<string, Set<number>> = {};
  
  try {
    // Run git diff with unified diff format (0 context lines is best, but default 3 is fine)
    // We use -U0 to only get the exact modified lines and no context lines, making parsing simpler!
    const diffOutput = execSync(`git diff -U0 ${base}`, { cwd, encoding: 'utf8', maxBuffer: 10 * 1024 * 1024 });
    
    let currentFilePath: string | null = null;
    let currentLine = 0;
    
    const lines = diffOutput.split(/\r?\n/);
    for (const line of lines) {
      if (line.startsWith('diff --git')) {
        // Parse file path from: diff --git a/src/cli.ts b/src/cli.ts
        const match = line.match(/^diff --git a\/(.+) b\/(.+)$/);
        if (match) {
          const relativePath = match[2];
          currentFilePath = path.resolve(cwd, relativePath);
          result[currentFilePath] = new Set<number>();
        } else {
          currentFilePath = null;
        }
        continue;
      }
      
      if (!currentFilePath) continue;
      
      if (line.startsWith('@@')) {
        // Parse hunk header: @@ -10,6 +10,8 @@ or @@ -1 +1 @@
        // We look for the second part (the new file: +10,8 or +1)
        const match = line.match(/^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,(\d+))?\s+@@/);
        if (match) {
          currentLine = parseInt(match[1], 10);
        }
        continue;
      }
      
      if (line.startsWith('+') && !line.startsWith('+++')) {
        // Line added or modified
        result[currentFilePath].add(currentLine);
        currentLine++;
      } else if (line.startsWith(' ') || line.startsWith('-')) {
        // Space means context line (if we didn't use -U0)
        // Minus means deleted line (does not exist in new version)
        if (line.startsWith(' ')) {
          currentLine++;
        }
      }
    }
  } catch (error) {
    console.error(`Error running git diff: ${(error as Error).message}`);
  }
  
  return result;
}
