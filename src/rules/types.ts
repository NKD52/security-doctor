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

export interface Config {
  ignorePaths?: string[];
  rules?: Record<string, 'off' | string | { status?: 'on' | 'off'; severity?: Severity }>;
  ignoredSecrets?: string[];
  dbClients?: string[];
}

export interface RuleContext {
  filePath: string;
  report: (nodePath: any, message: string, suggestedFix?: string, severity?: Severity) => void;
  reportAt: (line: number, column: number, message: string, suggestedFix?: string, severity?: Severity) => void;
  config?: Config;
}

export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  description: string;
  agentInstruction?: string;
  createVisitor: (context: RuleContext) => Visitor;
}
