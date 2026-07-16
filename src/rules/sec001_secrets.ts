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

interface SecretResult {
  value: string;
  isFallback: boolean;
}

function findSecretValues(node: any, varName: string): SecretResult[] {
  if (!node) return [];

  // 1. Direct string/template literal check
  const directVal = getStringValue(node);
  if (directVal) {
    if (isLikelySecret(varName, directVal)) {
      return [{ value: directVal, isFallback: false }];
    }
  }

  // 2. Logical expression (|| or ??)
  if (node.type === 'LogicalExpression' && (node.operator === '||' || node.operator === '??')) {
    const leftSecrets = findSecretValues(node.left, varName);
    const rightSecrets = findSecretValues(node.right, varName);
    const all = [...leftSecrets, ...rightSecrets];
    return all.map(s => ({ value: s.value, isFallback: true }));
  }

  // 3. ConditionalExpression (ternary)
  if (node.type === 'ConditionalExpression') {
    const consequentSecrets = findSecretValues(node.consequent, varName);
    const alternateSecrets = findSecretValues(node.alternate, varName);
    const all = [...consequentSecrets, ...alternateSecrets];
    return all.map(s => ({ value: s.value, isFallback: true }));
  }

  return [];
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
          const varName = path.node.id.name;
          const secrets = findSecretValues(path.node.init, varName);
          for (const s of secrets) {
            if (s.isFallback) {
              context.report(
                path,
                `Possible hardcoded credential used as a fallback for "${varName}". If the environment variable is unset, the app silently runs with this committed value instead of failing.`,
                `Throw an error if the environment variable is missing (fail closed): throw new Error('${varName} must be set')`
              );
            } else {
              context.report(
                path,
                `Potential hardcoded secret found in variable '${varName}'.`,
                `Move the secret to environment variables (e.g., process.env.${varName.toUpperCase()}).`
              );
            }
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
          const secrets = findSecretValues(path.node.value, name);
          for (const s of secrets) {
            if (s.isFallback) {
              context.report(
                path,
                `Possible hardcoded credential used as a fallback for "${name}". If the environment variable is unset, the app silently runs with this committed value instead of failing.`,
                `Throw an error if the environment variable is missing (fail closed): throw new Error('${name} must be set')`
              );
            } else {
              context.report(
                path,
                `Potential hardcoded secret found in property '${name}'.`,
                `Reference this secret dynamically or use an environment variable.`
              );
            }
          }
        }
      },
      AssignmentExpression(path) {
        if (path.node.left.type === 'Identifier' && path.node.right) {
          const varName = path.node.left.name;
          const secrets = findSecretValues(path.node.right, varName);
          for (const s of secrets) {
            if (s.isFallback) {
              context.report(
                path,
                `Possible hardcoded credential used as a fallback for "${varName}". If the environment variable is unset, the app silently runs with this committed value instead of failing.`,
                `Throw an error if the environment variable is missing (fail closed): throw new Error('${varName} must be set')`
              );
            } else {
              context.report(
                path,
                `Potential hardcoded secret assigned to '${varName}'.`,
                `Avoid assigning hardcoded secret values. Use environment variables.`
              );
            }
          }
        }
      }
    };
  }
};
