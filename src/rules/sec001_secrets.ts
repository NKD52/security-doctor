import { Rule } from './types.js';
import { isLikelySecret, shannonEntropy } from '../utils/entropy.js';

let reportedLocations = new Set<string>();

const CONFIDENT_SECRET_REGEXES = [
  /sk_live_[a-zA-Z0-9_]{12,}/,
  /sk_test_[a-zA-Z0-9_]{12,}/,
  /pk_live_[a-zA-Z0-9_]{12,}/,
  /pk_test_[a-zA-Z0-9_]{12,}/,
  /xox[bapr]-[a-zA-Z0-9_]{10,}/,
  /ghp_[a-zA-Z0-9_]{30,}/,
  /github_pat_[a-zA-Z0-9_]{30,}/,
  /AKIA[0-9A-Z]{16}/,
  /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i,
  /sq0csp-[0-9A-Za-z\-_]{22}/,
  /sq0atp-[0-9A-Za-z\-_]{22}/
];

function reportSecret(context: any, path: any, msg: string, fix: string, secretValue: string) {
  const key = `${context.filePath}:${secretValue}`;
  if (reportedLocations.has(key)) return;
  reportedLocations.add(key);
  context.report(path, msg, fix);
}

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
    if (directVal.startsWith('http://') || directVal.startsWith('https://')) {
      return [];
    }
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
  reset() {
    reportedLocations.clear();
  },
  createVisitor(context) {
    return {
      VariableDeclarator(path) {
        if (path.node.id.type === 'Identifier' && path.node.init) {
          const varName = path.node.id.name;
          const secrets = findSecretValues(path.node.init, varName);
          for (const s of secrets) {
            if (s.isFallback) {
              reportSecret(
                context,
                path,
                `Possible hardcoded credential used as a fallback for "${varName}". If the environment variable is unset, the app silently runs with this committed value instead of failing.`,
                `Throw an error if the environment variable is missing (fail closed): throw new Error('${varName} must be set')`,
                s.value
              );
            } else {
              reportSecret(
                context,
                path,
                `Potential hardcoded secret found in variable '${varName}'.`,
                `Move the secret to environment variables (e.g., process.env.${varName.toUpperCase()}).`,
                s.value
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
              reportSecret(
                context,
                path,
                `Possible hardcoded credential used as a fallback for "${name}". If the environment variable is unset, the app silently runs with this committed value instead of failing.`,
                `Throw an error if the environment variable is missing (fail closed): throw new Error('${name} must be set')`,
                s.value
              );
            } else {
              reportSecret(
                context,
                path,
                `Potential hardcoded secret found in property '${name}'.`,
                `Reference this secret dynamically or use an environment variable.`,
                s.value
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
              reportSecret(
                context,
                path,
                `Possible hardcoded credential used as a fallback for "${varName}". If the environment variable is unset, the app silently runs with this committed value instead of failing.`,
                `Throw an error if the environment variable is missing (fail closed): throw new Error('${varName} must be set')`,
                s.value
              );
            } else {
              reportSecret(
                context,
                path,
                `Potential hardcoded secret assigned to '${varName}'.`,
                `Avoid assigning hardcoded secret values. Use environment variables.`,
                s.value
              );
            }
          }
        }
      },
      StringLiteral(path) {
        const val = path.node.value;
        if (!val) return;

        // 1. Known-prefix fast-path
        for (const regex of CONFIDENT_SECRET_REGEXES) {
          if (regex.test(val)) {
            reportSecret(
              context,
              path,
              `Potential hardcoded credential or API key found with known prefix.`,
              `Move the credential or secret to environment variables.`,
              val
            );
            return;
          }
        }

        // 2. Tokenized entropy scan
        const tokens = val.split(/[?&=/\s:;!@#$%^&*()+\-[\]{}|\\"'`<>,.]+/);
        for (let i = 0; i < tokens.length; i++) {
          const token = tokens[i];
          if (token.length >= 8) {
            // Context-Aware Path
            const precedingToken = i > 0 ? tokens[i - 1] : '';
            if (precedingToken) {
              const precedingLower = precedingToken.toLowerCase();
              const isSecretName = /api[_-]?key|secret|password|passwd|token|private[_-]?key|access[_-]?key|client[_-]?secret|auth|authorization/i.test(precedingLower);
              if (isSecretName && isLikelySecret(precedingToken, token)) {
                reportSecret(
                  context,
                  path,
                  `Potential hardcoded secret found in parameter/key '${precedingToken}'.`,
                  `Reference this secret dynamically or use an environment variable.`,
                  val
                );
                return;
              }
            }

            // Unlabeled Fallback Path
            if (token.length >= 20 && !token.startsWith('data:')) {
              const entropy = shannonEntropy(token);
              if (entropy > 4.5) {
                reportSecret(
                  context,
                  path,
                  `Potential hardcoded secret found (unlabeled high-entropy string).`,
                  `Move the credential or secret to environment variables.`,
                  val
                );
                return;
              }
            }
          }
        }
      },
      TemplateLiteral(path) {
        for (const quasi of path.node.quasis) {
          const val = quasi.value.cooked;
          if (!val) continue;

          for (const regex of CONFIDENT_SECRET_REGEXES) {
            if (regex.test(val)) {
              reportSecret(
                context,
                path,
                `Potential hardcoded credential or API key found with known prefix.`,
                `Move the credential or secret to environment variables.`,
                val
              );
              return;
            }
          }

          const tokens = val.split(/[?&=/\s:;!@#$%^&*()+\-[\]{}|\\"'`<>,.]+/);
          for (let i = 0; i < tokens.length; i++) {
            const token = tokens[i];
            if (token.length >= 8) {
              const precedingToken = i > 0 ? tokens[i - 1] : '';
              if (precedingToken) {
                const precedingLower = precedingToken.toLowerCase();
                const isSecretName = /api[_-]?key|secret|password|passwd|token|private[_-]?key|access[_-]?key|client[_-]?secret|auth|authorization/i.test(precedingLower);
                if (isSecretName && isLikelySecret(precedingToken, token)) {
                  reportSecret(
                    context,
                    path,
                    `Potential hardcoded secret found in parameter/key '${precedingToken}'.`,
                    `Reference this secret dynamically or use an environment variable.`,
                    val
                  );
                  return;
                }
              }

              if (token.length >= 20 && !token.startsWith('data:')) {
                const entropy = shannonEntropy(token);
                if (entropy > 4.5) {
                  reportSecret(
                    context,
                    path,
                    `Potential hardcoded secret found (unlabeled high-entropy string).`,
                    `Move the credential or secret to environment variables.`,
                    val
                  );
                  return;
                }
              }
            }
          }
        }
      }
    };
  }
};
