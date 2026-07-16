import { Rule } from './types.js';

function getStringValue(node: any): string | null {
  if (!node) return null;
  if (node.type === 'StringLiteral') {
    return node.value;
  }
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0 && node.quasis.length === 1) {
    return node.quasis[0].value.cooked ?? null;
  }
  return null;
}

const SENSITIVE_WORDS = ['key', 'secret', 'password', 'passwd', 'pwd', 'token', 'auth', 'credential', 'private'];
const PASSWORD_WORDS = ['password', 'passwd', 'pwd'];

function isSuspiciousStorageKey(key: string): { isSuspicious: boolean; isPassword: boolean } {
  // Split key by camelCase, snake_case, or kebab-case boundaries
  const words = key
    .replace(/([A-Z])/g, '_$1')
    .split(/[_-]/)
    .map(w => w.toLowerCase())
    .filter(w => w.length > 0);

  const isSuspicious = words.some(w => SENSITIVE_WORDS.includes(w));
  const isPassword = words.some(w => PASSWORD_WORDS.includes(w));

  return { isSuspicious, isPassword };
}

export const sec012Storage: Rule = {
  id: 'SEC012',
  title: 'Sensitive Data in Web Storage',
  severity: 'high',
  description: 'Detects sensitive credentials, tokens, or passwords stored in localStorage or sessionStorage.',
  agentInstruction: 'Avoid storing sensitive credentials or plaintext passwords in web storage (localStorage or sessionStorage). Prefer secure, httpOnly cookies or memory storage.',
  createVisitor(context) {
    return {
      CallExpression(path) {
        const callee = path.node.callee;
        if (
          callee.type === 'MemberExpression' &&
          callee.object.type === 'Identifier' &&
          (callee.object.name === 'localStorage' || callee.object.name === 'sessionStorage') &&
          callee.property.type === 'Identifier' &&
          callee.property.name === 'setItem'
        ) {
          const args = path.node.arguments;
          if (args.length >= 1) {
            const keyNode = args[0];
            const keyVal = getStringValue(keyNode);
            if (keyVal) {
              const { isSuspicious, isPassword } = isSuspiciousStorageKey(keyVal);
              if (isSuspicious) {
                if (isPassword) {
                  context.report(
                    path,
                    `Sensitive password-shaped value '${keyVal}' is stored in web storage. Leaking plaintext passwords can lead to credential stuffing attacks and broad user compromise since users frequently reuse passwords across sites.`,
                    `Avoid storing plaintext passwords in web storage. Use session-based authentication or keep them in transient memory.`,
                    'critical'
                  );
                } else {
                  context.report(
                    path,
                    `Sensitive data '${keyVal}' is stored in web storage. Web storage is vulnerable to cross-site scripting (XSS) attacks, risking exposure of session tokens or API keys.`,
                    `Use secure, httpOnly cookies for session tokens, or keep sensitive API keys in backend code.`,
                    'high'
                  );
                }
              }
            }
          }
        }
      }
    };
  }
};
