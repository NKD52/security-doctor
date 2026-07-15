// List of AST identifier and property patterns that represent untrusted user input sources.
// Keeping this as config data allows extending the sources without changing the core tracking engine.

export const TAINT_SOURCES = {
  // Common HTTP request object names
  objects: ['req', 'request'],
  
  // Untrusted property namespaces on the request object
  properties: ['query', 'body', 'params', 'headers']
};
