import { Finding } from './rules/types.js';

export function calculateScore(findings: Finding[], totalFilesScanned: number): number {
  const scalingFactor = 50; // provisional placeholder to be tuned
  let totalWeight = 0;
  for (const f of findings) {
    switch (f.severity) {
      case 'critical':
        totalWeight += 15;
        break;
      case 'high':
        totalWeight += 8;
        break;
      case 'medium':
        totalWeight += 3;
        break;
      case 'low':
        totalWeight += 1;
        break;
    }
  }
  const filesCount = Math.max(1, totalFilesScanned);
  const densityPenalty = (totalWeight / filesCount) * scalingFactor;
  return Math.max(0, Math.round(100 - densityPenalty));
}
