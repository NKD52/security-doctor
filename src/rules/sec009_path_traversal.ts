import { Rule } from './types.js';
import { PATH_SINKS } from './sinks.js';
import { isSourceNode, expressionContainsTaint, extractIdentifiers, isSafeBoundaryArg } from '../utils/taint.js';

export function isPathSinkCall(node: any): boolean {
  if (!node || node.type !== 'CallExpression') return false;
  const callee = node.callee;
  // direct call e.g. readFile(...)
  if (callee.type === 'Identifier') {
    return PATH_SINKS.methods.includes(callee.name);
  }
  // property call e.g. fs.readFile(...) or promises.readFile(...)
  if (
    callee.type === 'MemberExpression' &&
    callee.object.type === 'Identifier' &&
    callee.property.type === 'Identifier'
  ) {
    const receiver = callee.object.name;
    const method = callee.property.name;
    return PATH_SINKS.receivers.includes(receiver) && PATH_SINKS.methods.includes(method);
  }
  return false;
}

export const sec009PathTraversal: Rule = {
  id: 'SEC009',
  title: 'Prevent Path Traversal',
  severity: 'critical',
  description: 'Detects potential path traversal vulnerabilities where untrusted user input flows into a file system operation.',
  agentInstruction: 'Resolve and verify boundaries before accessing paths. Use path.resolve() combined with startsWith() verification containing a trailing separator.',
  createVisitor(context) {
    function analyzeFunction(path: any) {
      const taintedVars = new Set<string>();

      const visitors = {
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

          if (isPathSinkCall(callPath.node)) {
            const args = callPath.node.arguments;
            if (args.length > 0) {
              const pathArg = args[0];
              if (expressionContainsTaint(pathArg, taintedVars)) {
                context.report(
                  callPath,
                  'Potential Path Traversal vulnerability. Untrusted user input is passed directly to a filesystem operation.',
                  'Resolve and verify boundaries before accessing paths. Use path.resolve() combined with startsWith() verification containing a trailing separator.'
                );
              }
            }
          }
        },
        IfStatement(ifPath: any) {
          if (ifPath.getFunctionParent() !== path) return;

          const test = ifPath.node.test;
          let sanitizedVar: string | null = null;

          // Match: varName.startsWith(...)
          if (
            test.type === 'CallExpression' &&
            test.callee.type === 'MemberExpression' &&
            test.callee.object.type === 'Identifier' &&
            test.callee.property.type === 'Identifier' &&
            test.callee.property.name === 'startsWith'
          ) {
            // Verify directory separator presence to prevent prefix-matching bypass
            if (isSafeBoundaryArg(test.arguments[0])) {
              sanitizedVar = test.callee.object.name;
            }
          }

          // Match: varName.indexOf(...) === 0
          if (
            test.type === 'BinaryExpression' &&
            (test.operator === '===' || test.operator === '==') &&
            test.left.type === 'CallExpression' &&
            test.left.callee.type === 'MemberExpression' &&
            test.left.callee.object.type === 'Identifier' &&
            test.left.callee.property.type === 'Identifier' &&
            test.left.callee.property.name === 'indexOf' &&
            test.right.type === 'NumericLiteral' &&
            test.right.value === 0
          ) {
            if (isSafeBoundaryArg(test.left.arguments[0])) {
              sanitizedVar = test.left.callee.object.name;
            }
          }

          if (sanitizedVar && taintedVars.has(sanitizedVar)) {
            // Temporarily untaint variable for consequent block (if body)
            taintedVars.delete(sanitizedVar);

            // Traverse consequent block manually
            ifPath.get('consequent').traverse(visitors);

            // Restore the variable to the tainted list
            taintedVars.add(sanitizedVar);

            // Traverse the alternate block (else body) with taint restored
            if (ifPath.node.alternate) {
              ifPath.get('alternate').traverse(visitors);
            }

            // Skip default traversal of this IfStatement to avoid double-visiting
            ifPath.skip();
          }
        }
      };

      path.traverse(visitors);
    }

    return {
      FunctionDeclaration: analyzeFunction,
      FunctionExpression: analyzeFunction,
      ArrowFunctionExpression: analyzeFunction
    };
  }
};
