// A fixture containing various security vulnerabilities for testing the CLI tool.

const apiKey = "SG.yO3R8r3_T3W_cK9J1Vp2bA.d9G8h7i6j5k4l3m2n1o0p9q8r7s6t5u4v3w2x1y0z1";

function runCode(code) {
  eval(code);
}

const reqOptions = {
  rejectUnauthorized: false
};

const corsSettings = {
  origin: '*'
};

function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

function setupSession(res) {
  res.cookie('sid', '123456');
}

// SEC007: SQL Injection
function handleLogin(req, res) {
  const email = req.query.email;
  db.query("SELECT * FROM users WHERE email = " + email);
}

// SEC008: Command Injection
function handleDeploy(req, res) {
  const repo = req.body.repo;
  exec("git clone " + repo);
}

// SEC009: Path Traversal
function handleRead(req, res) {
  const file = req.query.file;
  fs.readFile(file, 'utf8', (err, data) => {});
}
