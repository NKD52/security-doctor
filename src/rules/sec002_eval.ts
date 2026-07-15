import { Rule } from './types.js';
import { isSourceNode, expressionContainsTaint, extractIdentifiers } from '../utils/taint.js';

export const sec002Eval: Rule = {
  id: 'SEC002',
  title: 'Safe Dynamic Execution',
  severity: 'high',
  description: 'Detects unsafe execution using eval(), new Function(), or child_process exec/execSync.',
  agentInstruction: 'Do not use eval(), new Function(), or child_process.exec() with unsanitized dynamic strings. Prefer JSON.parse() or child_process.spawn() with separate arguments.',
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
            } else if (expressionContainsTaint(init, taintedVars)) {
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
            } else if (expressionContainsTaint(right, taintedVars)) {
              taintedVars.add(name);
            } else {
              taintedVars.delete(name);
            }
          }
        },
        CallExpression(callPath: any) {
          if (callPath.getFunctionParent() !== path) return;

          const { callee, arguments: args } = callPath.node;
          let isDirectExec = callee.type === 'Identifier' && (callee.name === 'exec' || callee.name === 'execSync');
          let isMemberExec = false;
          let propName = '';

          if (callee.type === 'MemberExpression') {
            const prop = callee.property;
            if (prop.type === 'Identifier') {
              propName = prop.name;
            } else if (prop.type === 'StringLiteral') {
              propName = prop.value;
            }
            if (propName === 'exec' || propName === 'execSync') {
              isMemberExec = true;
            }
          }

          if (isDirectExec || isMemberExec) {
            if (args.length > 0) {
              const cmdArg = args[0];
              // If tainted, do NOT report SEC002 (let SEC008 handle it as critical command injection)
              if (expressionContainsTaint(cmdArg, taintedVars)) {
                return;
              }
            }
            // Report as SEC002 since the input is untainted
            const name = isDirectExec ? (callee as any).name : `child_process.${propName}`;
            context.report(
              callPath,
              `Unsafe shell execution using ${name}().`,
              'Use spawn() or execFile() with safe argument lists instead of passing raw command strings to shell execution.'
            );
          }

          // Match eval(...)
          if (callee.type === 'Identifier' && callee.name === 'eval') {
            context.report(
              callPath,
              'Unsafe execution using eval().',
              'Use safer alternatives like JSON.parse() or direct property access if evaluating dynamic properties.'
            );
          }
        },
        NewExpression(newPath: any) {
          if (newPath.getFunctionParent() !== path) return;

          const { callee } = newPath.node;
          if (callee.type === 'Identifier' && callee.name === 'Function') {
            context.report(
              newPath,
              'Unsafe execution using new Function().',
              'Avoid dynamically compiling code from strings. Use standard closures or modules.'
            );
          }
        }
      });
    }

    return {
      FunctionDeclaration: analyzeFunction,
      FunctionExpression: analyzeFunction,
      ArrowFunctionExpression: analyzeFunction,

      // Handle top-level scope checks for nodes outside functions
      CallExpression(callPath) {
        if (callPath.getFunctionParent()) return; // handled by function analyzer

        const { callee } = callPath.node;
        if (callee.type === 'Identifier' && callee.name === 'eval') {
          context.report(
            callPath,
            'Unsafe execution using eval().',
            'Use safer alternatives like JSON.parse() or direct property access if evaluating dynamic properties.'
          );
        } else if (callee.type === 'Identifier' && (callee.name === 'exec' || callee.name === 'execSync')) {
          context.report(
            callPath,
            `Unsafe shell execution using ${callee.name}().`,
            'Use spawn() or execFile() with safe argument lists instead of passing raw command strings to shell execution.'
          );
        } else if (callee.type === 'MemberExpression') {
          const prop = callee.property;
          const propName = prop.type === 'Identifier' ? prop.name : prop.type === 'StringLiteral' ? prop.value : '';
          if (propName === 'exec' || propName === 'execSync') {
            context.report(
              callPath,
              `Unsafe shell execution using child_process.${propName}().`,
              'Use spawn() or execFile() with safe arguments to prevent command injection.'
            );
          }
        }
      },
      NewExpression(newPath) {
        if (newPath.getFunctionParent()) return; // handled by function analyzer

        const { callee } = newPath.node;
        if (callee.type === 'Identifier' && callee.name === 'Function') {
          context.report(
            newPath,
            'Unsafe execution using new Function().',
            'Avoid dynamically compiling code from strings. Use standard closures or modules.'
          );
        }
      }
    };
  }
};
