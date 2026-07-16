import { Rule } from './types.js';
import { isSourceNode, expressionContainsTaint, extractIdentifiers } from '../utils/taint.js';

const XSS_SANITIZERS = [
  'DOMPurify.sanitize',
  'he.encode',
  'escapeHtml',
  'sanitizeHtml',
  'escape'
];

export const sec010Xss: Rule = {
  id: 'SEC010',
  title: 'Prevent XSS and HTML Injection',
  severity: 'critical',
  description: 'Detects potential Cross-Site Scripting (XSS) or HTML Injection vulnerabilities where untrusted user input is sent directly to responses or assigned to innerHTML/outerHTML.',
  agentInstruction: 'Always sanitize untrusted user input with DOMPurify.sanitize() or an escape function before rendering it as HTML or sending it in a response.',
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
            } else if (expressionContainsTaint(init, taintedVars, XSS_SANITIZERS)) {
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
          
          // Check innerHTML/outerHTML assignments
          if (
            left.type === 'MemberExpression' &&
            left.property.type === 'Identifier' &&
            (left.property.name === 'innerHTML' || left.property.name === 'outerHTML')
          ) {
            if (expressionContainsTaint(right, taintedVars, XSS_SANITIZERS)) {
              context.report(
                assignPath,
                `Potential XSS vulnerability. Untrusted user input is assigned to '${left.property.name}' without HTML escaping.`,
                `Use textContent / value instead, or pass the input through a sanitizer (e.g. DOMPurify.sanitize()).`
              );
            }
            return;
          }

          // Standard variable assignment
          if (left.type === 'Identifier') {
            const name = left.name;
            if (isSourceNode(right)) {
              taintedVars.add(name);
            } else if (expressionContainsTaint(right, taintedVars, XSS_SANITIZERS)) {
              taintedVars.add(name);
            } else {
              taintedVars.delete(name);
            }
          }
        },
        CallExpression(callPath: any) {
          if (callPath.getFunctionParent() !== path) return;

          const callee = callPath.node.callee;
          if (callee.type === 'MemberExpression' && callee.property.type === 'Identifier') {
            const receiverName = callee.object.type === 'Identifier' ? callee.object.name : '';
            const propName = callee.property.name;

            // Match res.send() / res.write()
            if (receiverName === 'res' && (propName === 'send' || propName === 'write')) {
              const args = callPath.node.arguments;
              if (args.length > 0) {
                const sendArg = args[0];
                if (expressionContainsTaint(sendArg, taintedVars, XSS_SANITIZERS)) {
                  context.report(
                    callPath,
                    'Potential HTML Injection / XSS vulnerability. Untrusted user input is sent directly in a response.',
                    'Escape user input before rendering it, or use res.json() to return data instead of HTML.'
                  );
                }
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
