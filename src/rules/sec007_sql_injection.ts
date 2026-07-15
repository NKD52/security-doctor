import { Rule } from './types.js';
import { isSourceNode, expressionContainsTaint, isSinkCall } from '../utils/taint.js';

function extractIdentifiers(node: any): string[] {
  if (!node) return [];
  if (node.type === 'Identifier') {
    return [node.name];
  }
  if (node.type === 'ObjectPattern') {
    const names: string[] = [];
    for (const prop of node.properties) {
      if (prop.type === 'ObjectProperty' && prop.value.type === 'Identifier') {
        names.push(prop.value.name);
      }
    }
    return names;
  }
  if (node.type === 'ArrayPattern') {
    const names: string[] = [];
    for (const elem of node.elements) {
      if (elem && elem.type === 'Identifier') {
        names.push(elem.name);
      }
    }
    return names;
  }
  return [];
}

export const sec007SqlInjection: Rule = {
  id: 'SEC007',
  severity: 'critical',
  description: 'Detects potential SQL Injection vulnerabilities from untrusted user inputs flowing into raw database queries.',
  createVisitor(context) {
    function analyzeFunction(path: any) {
      const taintedVars = new Set<string>();

      // Traverse the local function body scope
      path.traverse({
        VariableDeclarator(declPath: any) {
          // Avoid descending into nested functions to prevent variable leakage/crossover
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

          if (isSinkCall(callPath.node, context.config?.dbClients)) {
            const args = callPath.node.arguments;
            if (args.length > 0) {
              const queryArg = args[0];
              if (expressionContainsTaint(queryArg, taintedVars)) {
                context.report(
                  callPath,
                  'Potential SQL Injection vulnerability. Untrusted user input is concatenated or interpolated directly into a database query.',
                  'Use parameterized queries (prepared statements) or ORM execution methods instead of concatenating strings.'
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
