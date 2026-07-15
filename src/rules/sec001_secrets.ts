import { Rule } from './types.js';
import { isLikelySecret } from '../utils/entropy.js';

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

export const sec001Secrets: Rule = {
  id: 'SEC001',
  title: 'No Hardcoded Secrets',
  severity: 'critical',
  description: 'Detects hardcoded secrets, api keys, or passwords with high Shannon entropy.',
  agentInstruction: 'Never hardcode api keys, secrets, passwords, or private keys. Always reference them from environment variables (e.g. process.env).',
  createVisitor(context) {
    return {
      VariableDeclarator(path) {
        if (path.node.id.type === 'Identifier' && path.node.init) {
          const val = getStringValue(path.node.init);
          if (val && isLikelySecret(path.node.id.name, val)) {
            context.report(
              path,
              `Potential hardcoded secret found in variable '${path.node.id.name}'.`,
              `Move the secret to environment variables (e.g., process.env.${path.node.id.name.toUpperCase()}).`
            );
          }
        }
      },
      ObjectProperty(path) {
        let name: string | null = null;
        if (path.node.key.type === 'Identifier') {
          name = path.node.key.name;
        } else if (path.node.key.type === 'StringLiteral') {
          name = path.node.key.value;
        }
        
        if (name && path.node.value) {
          const val = getStringValue(path.node.value);
          if (val && isLikelySecret(name, val)) {
            context.report(
              path,
              `Potential hardcoded secret found in property '${name}'.`,
              `Reference this secret dynamically or use an environment variable.`
            );
          }
        }
      },
      AssignmentExpression(path) {
        if (path.node.left.type === 'Identifier' && path.node.right) {
          const val = getStringValue(path.node.right);
          if (val && isLikelySecret(path.node.left.name, val)) {
            context.report(
              path,
              `Potential hardcoded secret assigned to '${path.node.left.name}'.`,
              `Avoid assigning hardcoded secret values. Use environment variables.`
            );
          }
        }
      }
    };
  }
};
