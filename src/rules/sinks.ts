// ORM methods are safe by omission, not by sanitizer recognition, don't add generic .query-like matching without checking this.

export const TAINT_SINKS = {
  // Recognized database client/connection variable names
  receivers: ['db', 'connection', 'pool', 'client', 'sequelize', 'knex', 'mysql', 'pg'],
  
  // Danger-prone query execution methods on database clients
  methods: ['query', 'execute', 'raw']
};

export const COMMAND_SINKS = {
  // Danger-prone shell execution methods
  methods: ['exec', 'execSync']
};

export const PATH_SINKS = {
  // Common file system module/promise names
  receivers: ['fs', 'promises', 'fsp'],
  
  // File operations that accept system paths
  methods: ['readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'createReadStream', 'createWriteStream']
};
