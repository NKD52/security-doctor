import { TAINT_SOURCES } from '../rules/sources.js';
import { TAINT_SINKS } from '../rules/sinks.js';

const SANITIZERS = ['parseInt', 'parseFloat', 'Number'];

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

export function expressionContainsTaint(node: any, taintedVars: Set<string>): boolean {
  if (!node) return false;

  // Short-circuit if it's a recognized sanitizer
  if (node.type === 'CallExpression') {
    const callee = node.callee;
    if (callee.type === 'Identifier' && SANITIZERS.includes(callee.name)) {
      return false;
    }
  }

  if (node.type === 'Identifier') {
    return taintedVars.has(node.name);
  }

  if (node.type === 'BinaryExpression') {
    return (
      expressionContainsTaint(node.left, taintedVars) ||
      expressionContainsTaint(node.right, taintedVars)
    );
  }

  if (node.type === 'TemplateLiteral') {
    return node.expressions.some((expr: any) => expressionContainsTaint(expr, taintedVars));
  }

  if (node.type === 'MemberExpression') {
    return expressionContainsTaint(node.object, taintedVars);
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
