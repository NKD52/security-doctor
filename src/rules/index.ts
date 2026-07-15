import { Rule } from './types.js';
import { sec001Secrets } from './sec001_secrets.js';
import { sec002Eval } from './sec002_eval.js';
import { sec003Tls } from './sec003_tls.js';
import { sec004Cors } from './sec004_cors.js';
import { sec005Crypto } from './sec005_crypto.js';
import { sec006Cookies } from './sec006_cookies.js';
import { sec007SqlInjection } from './sec007_sql_injection.js';

export const rules: Rule[] = [
  sec001Secrets,
  sec002Eval,
  sec003Tls,
  sec004Cors,
  sec005Crypto,
  sec006Cookies,
  sec007SqlInjection
];

export * from './types.js';
