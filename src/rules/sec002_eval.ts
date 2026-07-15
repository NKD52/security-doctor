import { Rule } from './types.js';

export const sec002Eval: Rule = {
  id: 'SEC002',
  severity: 'high',
  description: 'Detects unsafe execution using eval(), new Function(), or child_process exec/execSync.',
  createVisitor(context) {
    return {
      CallExpression(path) {
        const { callee } = path.node;
        
        // Match eval(...)
        if (callee.type === 'Identifier' && callee.name === 'eval') {
          context.report(
            path,
            'Unsafe execution using eval().',
            'Use safer alternatives like JSON.parse() or direct property access if evaluating dynamic properties.'
          );
          return;
        }

        // Match direct exec(...) or execSync(...)
        if (callee.type === 'Identifier' && (callee.name === 'exec' || callee.name === 'execSync')) {
          context.report(
            path,
            `Unsafe shell execution using ${callee.name}().`,
            'Use spawn() or execFile() with safe argument lists instead of passing raw command strings to shell execution.'
          );
          return;
        }

        // Match child_process.exec(...) or child_process.execSync(...)
        if (callee.type === 'MemberExpression') {
          const prop = callee.property;
          let propName = '';
          if (prop.type === 'Identifier') {
            propName = prop.name;
          } else if (prop.type === 'StringLiteral') {
            propName = prop.value;
          }

          if (propName === 'exec' || propName === 'execSync') {
            context.report(
              path,
              `Unsafe shell execution using child_process.${propName}().`,
              'Use spawn() or execFile() with safe arguments to prevent command injection.'
            );
          }
        }
      },
      NewExpression(path) {
        const { callee } = path.node;
        if (callee.type === 'Identifier' && callee.name === 'Function') {
          context.report(
            path,
            'Unsafe execution using new Function().',
            'Avoid dynamically compiling code from strings. Use standard closures or modules.'
          );
        }
      }
    };
  }
};
