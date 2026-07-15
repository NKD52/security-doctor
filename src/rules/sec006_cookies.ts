import { Rule } from './types.js';

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
              `Provide options with { httpOnly: true, secure: true } to restrict access and restrict to HTTPS.`
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
                    if (prop.value.type === 'BooleanLiteral') {
                      isSecureTrue = prop.value.value;
                    }
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
                  `Ensure 'secure: true' is set to force transmission over HTTPS.`
                );
              }
            }
          }
        }
      }
    };
  }
};
