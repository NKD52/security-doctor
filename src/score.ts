import { Finding } from './rules/types.js';

export function calculateScore(findings: Finding[]): number {
  let score = 100;
  for (const f of findings) {
    switch (f.severity) {
      case 'critical':
        score -= 15;
        break;
      case 'high':
        score -= 8;
        break;
      case 'medium':
        score -= 3;
        break;
      case 'low':
        score -= 1;
        break;
    }
  }
  return Math.max(0, score);
}
