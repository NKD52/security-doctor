import { Rule } from './types.js';

export const sec016IframeSandbox: Rule = {
  id: 'SEC016',
  title: 'Missing Sandbox Attribute on iframe',
  severity: 'medium',
  description: 'iframe elements should have a sandbox attribute to restrict their capabilities and mitigate risks of XSS or clickjacking.',
  agentInstruction: 'Always specify the sandbox attribute on iframe elements (e.g. sandbox=""). Only grant necessary permissions like allow-scripts or allow-same-origin.',

  createVisitor(context) {
    return {
      JSXOpeningElement(path: any) {
        const node = path.node;
        if (node.name.type === 'JSXIdentifier' && node.name.name === 'iframe') {
          const hasSandbox = node.attributes.some((attr: any) =>
            attr.type === 'JSXAttribute' && attr.name.name === 'sandbox'
          );
          if (!hasSandbox) {
            context.report(
              path,
              `Potential security issue. '<iframe>' element is missing the 'sandbox' attribute.`,
              `Add a 'sandbox' attribute to restrict the capabilities of the iframe (e.g. sandbox="").`
            );
          }
        }
      }
    };
  }
};
