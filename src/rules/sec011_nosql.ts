import { Rule } from './types.js';
import { isSourceNode, expressionContainsTaint, extractIdentifiers } from '../utils/taint.js';

const NOSQL_SANITIZERS = [
  'String',
  'ObjectId',
  'Types.ObjectId',
  'mongoose.Types.ObjectId'
];

function isNoSqlSinkCall(node: any): boolean {
  if (!node || node.type !== 'CallExpression') return false;
  const callee = node.callee;
  if (callee.type !== 'MemberExpression') return false;
  const propName = callee.property.type === 'Identifier' ? callee.property.name : '';
  const nosqlMethods = [
    'find', 'findOne', 'update', 'updateOne', 'updateMany',
    'deleteOne', 'deleteMany', 'delete', 'remove', 'replaceOne'
  ];
  if (!nosqlMethods.includes(propName)) return false;

  // Pre-condition: first argument must not be an anonymous function callback (e.g., Array.find)
  if (node.arguments.length > 0) {
    const firstArg = node.arguments[0];
    if (firstArg.type === 'ArrowFunctionExpression' || firstArg.type === 'FunctionExpression') {
      return false;
    }
  }

  return true;
}

function hasTaintedNoSqlOperator(node: any, taintedVars: Set<string>, sanitizers: string[]): boolean {
  if (!node) return false;

  if (node.type === 'ObjectExpression') {
    for (const prop of node.properties) {
      if (prop.type === 'ObjectProperty') {
        const key = prop.key.type === 'Identifier' 
          ? prop.key.name 
          : prop.key.type === 'StringLiteral' 
          ? prop.key.value 
          : '';

        if (key.startsWith('$')) {
          if (expressionContainsTaint(prop.value, taintedVars, sanitizers)) {
            return true;
          }
        }
        
        if (prop.value.type === 'ObjectExpression') {
          if (hasTaintedNoSqlOperator(prop.value, taintedVars, sanitizers)) {
            return true;
          }
        }
      }
    }
  }
  return false;
}

export const sec011NoSql: Rule = {
  id: 'SEC011',
  title: 'Prevent NoSQL Injection',
  severity: 'critical',
  description: 'Detects potential NoSQL Injection vulnerabilities where untrusted input controls query filters or is passed directly into operators like $where, $gt, or $ne.',
  agentInstruction: 'Avoid passing user-controlled objects directly as query filters. Always build queries with hardcoded keys, and sanitize/coerce values using String() or ObjectId().',
  createVisitor(context) {
    function analyzeFunction(path: any) {
      const taintedVars = new Set<string>();

      path.traverse({
        VariableDeclarator(declPath: any) {
          if (declPath.getFunctionParent() !== path) return;
          const { id, init } = declPath.node;
          if (init) {
            if (isSourceNode(init)) {
              const vars = extractIdentifiers(id);
              for (const v of vars) {
                taintedVars.add(v);
              }
            } else if (expressionContainsTaint(init, taintedVars, NOSQL_SANITIZERS)) {
              const vars = extractIdentifiers(id);
              for (const v of vars) {
                taintedVars.add(v);
              }
            } else {
              const vars = extractIdentifiers(id);
              for (const v of vars) {
                taintedVars.delete(v);
              }
            }
          }
        },
        AssignmentExpression(assignPath: any) {
          if (assignPath.getFunctionParent() !== path) return;
          const { left, right } = assignPath.node;
          if (left.type === 'Identifier') {
            const name = left.name;
            if (isSourceNode(right)) {
              taintedVars.add(name);
            } else if (expressionContainsTaint(right, taintedVars, NOSQL_SANITIZERS)) {
              taintedVars.add(name);
            } else {
              taintedVars.delete(name);
            }
          }
        },
        CallExpression(callPath: any) {
          if (callPath.getFunctionParent() !== path) return;

          if (isNoSqlSinkCall(callPath.node)) {
            const args = callPath.node.arguments;
            if (args.length > 0) {
              const queryArg = args[0];

              if (queryArg.type !== 'ObjectExpression') {
                if (expressionContainsTaint(queryArg, taintedVars, NOSQL_SANITIZERS)) {
                  context.report(
                    callPath,
                    'Potential NoSQL Injection vulnerability. The entire query filter object is user-controlled.',
                    'Build the query filter object explicitly using hardcoded keys and sanitized values.'
                  );
                }
              } else {
                if (hasTaintedNoSqlOperator(queryArg, taintedVars, NOSQL_SANITIZERS)) {
                  context.report(
                    callPath,
                    'Potential NoSQL Injection vulnerability. Untrusted user input is passed into a query operator (e.g. $where, $gt, $ne).',
                    'Sanitize the query input, or coerce the parameter to a strict string/type using String() or mongoose Types.ObjectId().'
                  );
                }
              }
            }
          }
        }
      });
    }

    return {
      FunctionDeclaration: analyzeFunction,
      FunctionExpression: analyzeFunction,
      ArrowFunctionExpression: analyzeFunction
    };
  }
};
