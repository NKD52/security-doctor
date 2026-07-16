import { Rule } from './types.js';

function isProcessEnvNodeEnv(node: any): boolean {
  if (!node || node.type !== 'MemberExpression') return false;
  const obj = node.object;
  const prop = node.property;
  if (
    obj.type === 'MemberExpression' &&
    obj.object.type === 'Identifier' &&
    obj.object.name === 'process' &&
    obj.property.type === 'Identifier' &&
    obj.property.name === 'env' &&
    prop.type === 'Identifier' &&
    prop.name === 'NODE_ENV'
  ) {
    return true;
  }
  return false;
}

function isStringLiteralWithValue(node: any, val: string): boolean {
  if (!node) return false;
  if (node.type === 'StringLiteral' && node.value === val) {
    return true;
  }
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0 && node.quasis.length === 1) {
    return (node.quasis[0].value.cooked ?? '') === val;
  }
  return false;
}

function isSecureFlagSafe(node: any): boolean {
  if (!node) return false;
  
  // 1. Literal true
  if (node.type === 'BooleanLiteral' && node.value === true) {
    return true;
  }
  
  // 2. BinaryExpression environment comparisons
  if (node.type === 'BinaryExpression') {
    const { left, right, operator } = node;
    
    // process.env.NODE_ENV === 'production'
    if (operator === '===' || operator === '==') {
      if (
        (isProcessEnvNodeEnv(left) && isStringLiteralWithValue(right, 'production')) ||
        (isProcessEnvNodeEnv(right) && isStringLiteralWithValue(left, 'production'))
      ) {
        return true;
      }
    }
    
    // process.env.NODE_ENV !== 'development'
    if (operator === '!==' || operator === '!=') {
      if (
        (isProcessEnvNodeEnv(left) && isStringLiteralWithValue(right, 'development')) ||
        (isProcessEnvNodeEnv(right) && isStringLiteralWithValue(left, 'development'))
      ) {
        return true;
      }
    }
  }
  
  return false;
}

export const sec006Cookies: Rule = {
  id: 'SEC006',
  title: 'Secure Session Cookies',
  severity: 'medium',
  description: 'Detects cookie configurations missing httpOnly or secure flags.',
  agentInstruction: 'Always set httpOnly: true and secure: true when creating cookies to mitigate XSS and session hijacking.',
  createVisitor(context) {
    return {
      CallExpression(path) {
        const { callee, arguments: args } = path.node;
        
        // Match res.cookie(...)
        if (
          callee.type === 'MemberExpression' &&
          callee.property.type === 'Identifier' &&
          callee.property.name === 'cookie'
        ) {
          if (args.length === 2) {
            context.report(
              path,
              `Cookie created without 'httpOnly' and 'secure' flags.`,
              `Provide options with { httpOnly: true, secure: true }, or gate secure on environment with secure: process.env.NODE_ENV === 'production' for local HTTP development.`
            );
            return;
          }
          
          if (args.length >= 3) {
            const options = args[2];
            if (options.type === 'ObjectExpression') {
              let hasHttpOnly = false;
              let hasSecure = false;
              let isHttpOnlyTrue = false;
              let isSecureTrue = false;
              
              for (const prop of options.properties) {
                if (prop.type === 'ObjectProperty') {
                  const name = prop.key.type === 'Identifier' 
                    ? prop.key.name 
                    : prop.key.type === 'StringLiteral' 
                    ? prop.key.value 
                    : '';
                  
                  if (name === 'httpOnly') {
                    hasHttpOnly = true;
                    if (prop.value.type === 'BooleanLiteral') {
                      isHttpOnlyTrue = prop.value.value;
                    }
                  } else if (name === 'secure') {
                    hasSecure = true;
                    isSecureTrue = isSecureFlagSafe(prop.value);
                  }
                }
              }
              
              if (!hasHttpOnly || !isHttpOnlyTrue) {
                context.report(
                  options,
                  `Cookie created with 'httpOnly' set to false or missing.`,
                  `Ensure 'httpOnly: true' is set to prevent client-side script access (mitigating XSS).`
                );
              }
              if (!hasSecure || !isSecureTrue) {
                context.report(
                  options,
                  `Cookie created with 'secure' set to false or missing.`,
                  `Ensure 'secure: true' is set, or gate secure on environment with secure: process.env.NODE_ENV === 'production' for local HTTP development.`
                );
              }
            }
          }
        }
      }
    };
  }
};
