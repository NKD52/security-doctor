import { Rule } from './types.js';

export const sec005Crypto: Rule = {
  id: 'SEC005',
  severity: 'high',
  description: 'Detects usage of weak or outdated cryptographic hash functions (MD5, SHA1).',
  createVisitor(context) {
    return {
      CallExpression(path) {
        const { callee, arguments: args } = path.node;
        let isCreateHash = false;
        
        if (callee.type === 'Identifier' && callee.name === 'createHash') {
          isCreateHash = true;
        } else if (
          callee.type === 'MemberExpression' &&
          callee.property.type === 'Identifier' &&
          callee.property.name === 'createHash'
        ) {
          isCreateHash = true;
        }
        
        if (isCreateHash && args.length > 0) {
          const firstArg = args[0];
          if (firstArg.type === 'StringLiteral') {
            const algorithm = firstArg.value.toLowerCase();
            if (algorithm === 'md5' || algorithm === 'sha1') {
              context.report(
                path,
                `Weak cryptographic hashing algorithm '${algorithm.toUpperCase()}' used.`,
                `Upgrade to a secure hashing algorithm like 'sha256' or 'sha512'. For passwords, use 'bcrypt', 'argon2', or 'scrypt'.`
              );
            }
          }
        }
      }
    };
  }
};
