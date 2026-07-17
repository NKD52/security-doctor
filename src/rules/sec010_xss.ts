import { Rule } from './types.js';
import { isSourceNode, expressionContainsTaint, extractIdentifiers } from '../utils/taint.js';

const XSS_SANITIZERS = [
  'DOMPurify.sanitize',
  'he.encode',
  'escapeHtml',
  'sanitizeHtml',
  'escape'
];

function getMemberExpressionName(node: any): string | null {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'MemberExpression') {
    const obj = getMemberExpressionName(node.object);
    const prop = node.property.type === 'Identifier' ? node.property.name : null;
    if (obj && prop) return `${obj}.${prop}`;
  }
  return null;
}

function isSanitizedExpression(node: any): boolean {
  if (!node || node.type !== 'CallExpression') return false;
  const callee = node.callee;
  
  if (callee.type === 'Identifier') {
    const nameLower = callee.name.toLowerCase();
    if (nameLower.includes('escape') || nameLower.includes('sanitize')) {
      return true;
    }
  }
  
  if (callee.type === 'MemberExpression') {
    const propName = callee.property.type === 'Identifier' ? callee.property.name : '';
    if (propName) {
      const propLower = propName.toLowerCase();
      if (propLower.includes('escape') || propLower.includes('sanitize')) {
        return true;
      }
    }
    const fullName = getMemberExpressionName(callee);
    if (fullName && (fullName === 'DOMPurify.sanitize' || fullName === 'he.encode')) {
      return true;
    }
  }
  
  return false;
}

function isStringOrStatic(node: any): boolean {
  if (!node) return true;
  if (node.type === 'StringLiteral') return true;
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) return true;
  return false;
}

function isUnsanitizedDynamic(node: any, xssDirtyVars: Set<string>): boolean {
  if (!node) return false;
  if (isStringOrStatic(node)) return false;
  if (isSanitizedExpression(node)) return false;

  if (node.type === 'Identifier') {
    return xssDirtyVars.has(node.name);
  }

  if (node.type === 'MemberExpression') {
    return isUnsanitizedDynamic(node.object, xssDirtyVars);
  }

  if (node.type === 'TemplateLiteral') {
    return node.expressions.some((expr: any) => {
      if (isStringOrStatic(expr) || isSanitizedExpression(expr)) {
        return false;
      }
      return true;
    });
  }

  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const checkSide = (side: any) => {
      if (isStringOrStatic(side) || isSanitizedExpression(side)) {
        return false;
      }
      return true;
    };
    return checkSide(node.left) || checkSide(node.right) || isUnsanitizedDynamic(node.left, xssDirtyVars) || isUnsanitizedDynamic(node.right, xssDirtyVars);
  }

  if (node.type === 'CallExpression') {
    return node.arguments.some((arg: any) => isUnsanitizedDynamic(arg, xssDirtyVars));
  }

  if (node.type === 'LogicalExpression') {
    return isUnsanitizedDynamic(node.left, xssDirtyVars) || isUnsanitizedDynamic(node.right, xssDirtyVars);
  }

  if (node.type === 'ConditionalExpression') {
    return isUnsanitizedDynamic(node.consequent, xssDirtyVars) || isUnsanitizedDynamic(node.alternate, xssDirtyVars);
  }

  return false;
}

function isJSXDynamicExpression(node: any): boolean {
  if (!node) return false;
  if (
    node.type === 'StringLiteral' ||
    node.type === 'NumericLiteral' ||
    node.type === 'BooleanLiteral' ||
    node.type === 'NullLiteral'
  ) {
    return false;
  }
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) {
    return false;
  }
  if (isSanitizedExpression(node)) {
    return false;
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    return isJSXDynamicExpression(node.left) || isJSXDynamicExpression(node.right);
  }
  return true;
}

export const sec010Xss: Rule = {
  id: 'SEC010',
  title: 'Prevent XSS and HTML Injection',
  severity: 'critical',
  description: 'Detects potential Cross-Site Scripting (XSS) or HTML Injection vulnerabilities where untrusted user input is sent directly to responses or assigned to innerHTML/outerHTML.',
  agentInstruction: 'Always sanitize untrusted user input with DOMPurify.sanitize() or an escape function before rendering it as HTML or sending it in a response.',
  createVisitor(context) {
    function analyzeFunction(path: any) {
      const taintedVars = new Set<string>();
      const xssDirtyVars = new Set<string>();

      path.traverse({
        VariableDeclarator(declPath: any) {
          if (declPath.getFunctionParent() !== path) return;
          const { id, init } = declPath.node;
          if (init) {
            // Server-side
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

            // Client-side
            if (isUnsanitizedDynamic(init, xssDirtyVars)) {
              const vars = extractIdentifiers(id);
              for (const v of vars) {
                xssDirtyVars.add(v);
              }
            } else {
              const vars = extractIdentifiers(id);
              for (const v of vars) {
                xssDirtyVars.delete(v);
              }
            }
          }
        },
        AssignmentExpression(assignPath: any) {
          const { left, right, operator } = assignPath.node;
          
          // Check innerHTML/outerHTML assignments
          if (
            left.type === 'MemberExpression' &&
            left.property.type === 'Identifier' &&
            (left.property.name === 'innerHTML' || left.property.name === 'outerHTML')
          ) {
            if (assignPath.getFunctionParent() !== path) {
              let parent = assignPath.getFunctionParent();
              let isNested = false;
              while (parent) {
                if (parent === path) {
                  isNested = true;
                  break;
                }
                parent = parent.getFunctionParent();
              }
              if (!isNested) return;
            }

            if (isUnsanitizedDynamic(right, xssDirtyVars)) {
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
            const binding = assignPath.scope.getBinding(name);
            const belongsToCurrentFunction = binding && (binding.scope.getFunctionParent() === path.scope);
            
            if (assignPath.getFunctionParent() !== path && !belongsToCurrentFunction) {
              return;
            }

            // Server-side
            if (operator === '=') {
              if (isSourceNode(right)) {
                taintedVars.add(name);
              } else if (expressionContainsTaint(right, taintedVars, XSS_SANITIZERS)) {
                taintedVars.add(name);
              } else {
                taintedVars.delete(name);
              }
            } else if (operator === '+=') {
              if (isSourceNode(right) || expressionContainsTaint(right, taintedVars, XSS_SANITIZERS)) {
                taintedVars.add(name);
              }
            }

            // Client-side
            if (operator === '=') {
              if (isUnsanitizedDynamic(right, xssDirtyVars)) {
                xssDirtyVars.add(name);
              } else {
                xssDirtyVars.delete(name);
              }
            } else if (operator === '+=') {
              if (isUnsanitizedDynamic(right, xssDirtyVars)) {
                xssDirtyVars.add(name);
              }
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
        },
        JSXAttribute(attrPath: any) {
          if (attrPath.getFunctionParent() !== path) {
            let parent = attrPath.getFunctionParent();
            let isNested = false;
            while (parent) {
              if (parent === path) {
                isNested = true;
                break;
              }
              parent = parent.getFunctionParent();
            }
            if (!isNested) return;
          }

          const node = attrPath.node;
          if (node.name && node.name.name === 'dangerouslySetInnerHTML') {
            const value = node.value;
            if (value && value.type === 'JSXExpressionContainer') {
              const expr = value.expression;
              if (expr && expr.type === 'ObjectExpression') {
                const htmlProp = expr.properties.find((p: any) =>
                  p.type === 'ObjectProperty' &&
                  ((p.key.type === 'Identifier' && p.key.name === '__html') ||
                   (p.key.type === 'StringLiteral' && p.key.value === '__html'))
                );
                if (htmlProp) {
                  const htmlValue = htmlProp.value;
                  if (isJSXDynamicExpression(htmlValue)) {
                    context.report(
                      attrPath,
                      `Potential XSS vulnerability. Untrusted user input is passed to 'dangerouslySetInnerHTML' without HTML escaping.`,
                      `Pass the input through a sanitizer (e.g. DOMPurify.sanitize()) before assigning it to dangerouslySetInnerHTML.`
                    );
                  }
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
