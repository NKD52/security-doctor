import { Rule } from './types.js';

export const sec004Cors: Rule = {
  id: 'SEC004',
  title: 'Secure CORS Configurations',
  severity: 'medium',
  description: 'Detects insecure CORS wildcard configurations allowing any origin (e.g. origin: "*").',
  agentInstruction: "Avoid configuring wildcards like origin: '*' or Access-Control-Allow-Origin: '*' for authenticated endpoints.",
  createVisitor(context) {
    return {
      ObjectProperty(path) {
        const { key, value } = path.node;
        const name = key.type === 'Identifier' ? key.name : key.type === 'StringLiteral' ? key.value : '';
        
        const isCorsKey = name.toLowerCase() === 'origin' || name.toLowerCase() === 'access-control-allow-origin';
        
        if (isCorsKey && value.type === 'StringLiteral' && value.value === '*') {
          context.report(
            path,
            `Insecure CORS wildcard origin allowed ('*').`,
            'Restrict cross-origin access by specifying trusted domains or dynamically validating the origin against an allowlist.'
          );
        }
      }
    };
  }
};
