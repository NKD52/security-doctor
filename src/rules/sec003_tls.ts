import { Rule } from './types.js';

export const sec003Tls: Rule = {
  id: 'SEC003',
  title: 'Enforce SSL/TLS Verification',
  severity: 'critical',
  description: 'Detects disabled TLS/SSL certificate verification (e.g. rejectUnauthorized: false or NODE_TLS_REJECT_UNAUTHORIZED = 0).',
  agentInstruction: 'Do not set rejectUnauthorized: false or set NODE_TLS_REJECT_UNAUTHORIZED = 0.',
  createVisitor(context) {
    return {
      ObjectProperty(path) {
        const { key, value } = path.node;
        const name = key.type === 'Identifier' ? key.name : key.type === 'StringLiteral' ? key.value : '';
        if (name === 'rejectUnauthorized' && value.type === 'BooleanLiteral' && value.value === false) {
          context.report(
            path,
            'TLS certificate verification is disabled (rejectUnauthorized: false).',
            'Remove rejectUnauthorized: false or set it to true to ensure connections are secure and verified.'
          );
        }
      },
      AssignmentExpression(path) {
        const { left, right } = path.node;
        
        // Match process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0' / 0
        if (
          left.type === 'MemberExpression' &&
          left.object.type === 'MemberExpression' &&
          left.object.object.type === 'Identifier' &&
          left.object.object.name === 'process' &&
          left.object.property.type === 'Identifier' &&
          left.object.property.name === 'env' &&
          left.property.type === 'Identifier' &&
          left.property.name === 'NODE_TLS_REJECT_UNAUTHORIZED'
        ) {
          let isDisabling = false;
          if (right.type === 'StringLiteral' && right.value === '0') isDisabling = true;
          if (right.type === 'NumericLiteral' && right.value === 0) isDisabling = true;
          if (right.type === 'BooleanLiteral' && right.value === false) isDisabling = true;
          
          if (isDisabling) {
            context.report(
              path,
              'Disabling TLS verification globally using NODE_TLS_REJECT_UNAUTHORIZED = 0.',
              'Remove this assignment. Disabling TLS verification globally exposes the process to Man-In-The-Middle (MITM) attacks.'
            );
          }
        }
      }
    };
  }
};
