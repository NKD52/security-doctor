import { Visitor } from '@babel/traverse';

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface Finding {
  ruleId: string;
  severity: Severity;
  message: string;
  filePath: string;
  startLine: number;
  startColumn: number;
  endLine?: number;
  endColumn?: number;
  suggestedFix?: string;
}

export interface RuleContext {
  filePath: string;
  report: (nodePath: any, message: string, suggestedFix?: string) => void;
  reportAt: (line: number, column: number, message: string, suggestedFix?: string) => void;
}

export interface Rule {
  id: string;
  severity: Severity;
  description: string;
  createVisitor: (context: RuleContext) => Visitor;
}
