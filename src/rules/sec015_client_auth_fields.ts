import { Rule } from './types.js';

export const sec015ClientAuthFields: Rule = {
  id: 'SEC015',
  title: 'Client Code Modifying Sensitive Auth Fields',
  severity: 'high',
  description: 'Detects client-side Supabase query calls that attempt to set sensitive authorization or tenant fields (like role, admin, tenant_id, org_id, etc.).',
  agentInstruction: 'Do not allow client-supplied parameters to write to authorization or multi-tenancy columns. Enforce these constraints server-side via RLS policies or database defaults.',

  createVisitor(context) {
    return {
      CallExpression(callPath: any) {
        const { callee, arguments: args } = callPath.node;
        if (
          callee.type === 'MemberExpression' &&
          callee.property.type === 'Identifier' &&
          ['insert', 'update', 'upsert'].includes(callee.property.name)
        ) {
          if (args.length > 0) {
            const firstArg = args[0];
            const objects: any[] = [];
            
            if (firstArg.type === 'ObjectExpression') {
              objects.push(firstArg);
            } else if (firstArg.type === 'ArrayExpression') {
              for (const elem of firstArg.elements) {
                if (elem && elem.type === 'ObjectExpression') {
                  objects.push(elem);
                }
              }
            }

            const sensitiveKeysRegex = /^(role|is_admin|admin|tenant_id|org_id|owner_id)$/i;

            for (const obj of objects) {
              for (const prop of obj.properties) {
                if (prop.type === 'ObjectProperty') {
                  let keyName = '';
                  if (prop.key.type === 'Identifier') {
                    keyName = prop.key.name;
                  } else if (prop.key.type === 'StringLiteral') {
                    keyName = prop.key.value;
                  }
                  
                  if (sensitiveKeysRegex.test(keyName)) {
                    context.report(
                      callPath,
                      `Potential security bypass. Client code is attempting to write to sensitive authorization field '${keyName}'.`,
                      `Ensure authorization fields like '${keyName}' are set on the server or enforced via Row Level Security (RLS) policies, not supplied by the client.`
                    );
                    break;
                  }
                }
              }
            }
          }
        }
      }
    };
  }
};
