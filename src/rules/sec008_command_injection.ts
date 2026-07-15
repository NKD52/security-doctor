import { Rule } from './types.js';
import { COMMAND_SINKS } from './sinks.js';
import { isSourceNode, expressionContainsTaint, extractIdentifiers } from '../utils/taint.js';

export function isCommandSinkCall(node: any): boolean {
  if (!node || node.type !== 'CallExpression') return false;
  const callee = node.callee;
  if (callee.type === 'Identifier') {
    return COMMAND_SINKS.methods.includes(callee.name);
  }
  if (
    callee.type === 'MemberExpression' &&
    callee.property.type === 'Identifier'
  ) {
    return COMMAND_SINKS.methods.includes(callee.property.name);
  }
  return false;
}

export const sec008CommandInjection: Rule = {
  id: 'SEC008',
  severity: 'critical',
  description: 'Detects potential command injection vulnerabilities where untrusted user input flows into a system shell execution call.',
  createVisitor(context) {
    function analyzeFunction(path: any) {
      const taintedVars = new Set<string>();

      path.traverse({
        VariableDeclarator(declPath: any) {
          if (declPath.getFunctionParent() !== path) return;

          const { id, init } = declPath.node;
          if (init) {
            if (isSourceNode(init)) {
              const vars = extractIdentifiers(id);
              for (const v of vars) {
                taintedVars.add(v);
              }
            } else if (expressionContainsTaint(init, taintedVars)) {
              const vars = extractIdentifiers(id);
              for (const v of vars) {
                taintedVars.add(v);
              }
            } else {
              const vars = extractIdentifiers(id);
              for (const v of vars) {
                taintedVars.delete(v);
              }
            }
          }
        },
        AssignmentExpression(assignPath: any) {
          if (assignPath.getFunctionParent() !== path) return;

          const { left, right } = assignPath.node;
          if (left.type === 'Identifier') {
            const name = left.name;
            if (isSourceNode(right)) {
              taintedVars.add(name);
            } else if (expressionContainsTaint(right, taintedVars)) {
              taintedVars.add(name);
            } else {
              taintedVars.delete(name);
            }
          }
        },
        CallExpression(callPath: any) {
          if (callPath.getFunctionParent() !== path) return;

          if (isCommandSinkCall(callPath.node)) {
            const args = callPath.node.arguments;
            if (args.length > 0) {
              const cmdArg = args[0];
              if (expressionContainsTaint(cmdArg, taintedVars)) {
                context.report(
                  callPath,
                  'Potential Command Injection vulnerability. Untrusted user input flows directly into a system execution command.',
                  'Use execFile() or spawn() with safe arguments arrays instead of concatenating strings for system shell execution.'
                );
              }
            }
          }
        }
      });
    }

    return {
      FunctionDeclaration: analyzeFunction,
      FunctionExpression: analyzeFunction,
      ArrowFunctionExpression: analyzeFunction
    };
  }
};
