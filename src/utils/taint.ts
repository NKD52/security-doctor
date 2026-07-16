import { TAINT_SOURCES } from '../rules/sources.js';
import { TAINT_SINKS } from '../rules/sinks.js';

const SANITIZERS = ['parseInt', 'parseFloat', 'Number'];

export function extractIdentifiers(node: any): string[] {
  if (!node) return [];
  if (node.type === 'Identifier') {
    return [node.name];
  }
  if (node.type === 'ObjectPattern') {
    const names: string[] = [];
    for (const prop of node.properties) {
      if (prop.type === 'ObjectProperty' && prop.value.type === 'Identifier') {
        names.push(prop.value.name);
      }
    }
    return names;
  }
  if (node.type === 'ArrayPattern') {
    const names: string[] = [];
    for (const elem of node.elements) {
      if (elem && elem.type === 'Identifier') {
        names.push(elem.name);
      }
    }
    return names;
  }
  return [];
}

export function isSourceNode(node: any): boolean {
  if (!node) return false;
  if (node.type === 'MemberExpression') {
    const obj = node.object;
    const prop = node.property;
    if (obj.type === 'Identifier' && TAINT_SOURCES.objects.includes(obj.name)) {
      if (prop.type === 'Identifier' && TAINT_SOURCES.properties.includes(prop.name)) {
        return true;
      }
    }
    return isSourceNode(obj);
  }
  return false;
}

function getMemberExpressionName(node: any): string | null {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'MemberExpression') {
    const obj = getMemberExpressionName(node.object);
    const prop = node.property.type === 'Identifier' ? node.property.name : null;
    if (obj && prop) return `${obj}.${prop}`;
  }
  return null;
}

export function expressionContainsTaint(
  node: any,
  taintedVars: Set<string>,
  customSanitizers: string[] = []
): boolean {
  if (!node) return false;

  // Short-circuit if it's a recognized sanitizer, otherwise propagate taint from arguments
  if (node.type === 'CallExpression') {
    const callee = node.callee;
    const allSanitizers = [...SANITIZERS, ...customSanitizers];

    if (callee.type === 'Identifier') {
      if (allSanitizers.includes(callee.name)) {
        return false;
      }
      const nameLower = callee.name.toLowerCase();
      if (nameLower.includes('escape') || nameLower.includes('sanitize')) {
        return false;
      }
    }

    if (callee.type === 'MemberExpression') {
      const propName = callee.property.type === 'Identifier' ? callee.property.name : '';
      if (propName) {
        if (allSanitizers.includes(propName)) {
          return false;
        }
        const propLower = propName.toLowerCase();
        if (propLower.includes('escape') || propLower.includes('sanitize')) {
          return false;
        }
      }

      const fullName = getMemberExpressionName(callee);
      if (fullName && allSanitizers.includes(fullName)) {
        return false;
      }
    }

    return node.arguments.some((arg: any) => expressionContainsTaint(arg, taintedVars, customSanitizers));
  }

  if (node.type === 'Identifier') {
    return taintedVars.has(node.name);
  }

  if (node.type === 'BinaryExpression') {
    return (
      expressionContainsTaint(node.left, taintedVars, customSanitizers) ||
      expressionContainsTaint(node.right, taintedVars, customSanitizers)
    );
  }

  if (node.type === 'TemplateLiteral') {
    return node.expressions.some((expr: any) => expressionContainsTaint(expr, taintedVars, customSanitizers));
  }

  if (node.type === 'MemberExpression') {
    return expressionContainsTaint(node.object, taintedVars, customSanitizers);
  }

  return false;
}

export function isSinkCall(node: any, customReceivers?: string[]): boolean {
  if (!node || node.type !== 'CallExpression') return false;
  const callee = node.callee;
  if (
    callee.type === 'MemberExpression' &&
    callee.object.type === 'Identifier' &&
    callee.property.type === 'Identifier'
  ) {
    const receiver = callee.object.name;
    const method = callee.property.name;
    const allowedReceivers = customReceivers 
      ? [...new Set([...TAINT_SINKS.receivers, ...customReceivers])] 
      : TAINT_SINKS.receivers;
    return allowedReceivers.includes(receiver) && TAINT_SINKS.methods.includes(method);
  }
  return false;
}

export function isSafeBoundaryArg(node: any): boolean {
  if (!node) return false;
  if (node.type === 'StringLiteral') {
    return node.value.endsWith('/') || node.value.endsWith('\\');
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    return isSafeBoundaryArg(node.right) || isSafeBoundaryArg(node.left);
  }
  if (
    node.type === 'MemberExpression' &&
    node.object.type === 'Identifier' &&
    node.object.name === 'path' &&
    node.property.type === 'Identifier' &&
    node.property.name === 'sep'
  ) {
    return true;
  }
  return false;
}
