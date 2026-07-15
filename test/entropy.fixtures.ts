// Running list of secrets and false positives used for tuning the Shannon entropy threshold.
// Note: All keys here are fake/inactive but structured realistically.

export const validSecrets = [
  { varName: 'apiKey', value: 'SG.yO3R8r3_T3W_cK9J1Vp2bA.d9G8h7i6j5k4l3m2n1o0p9q8r7s6t5u4v3w2x1y0z1' }, // SendGrid format
  { varName: 'aws_secret_key', value: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' }, // AWS Secret format
  { varName: 'github_token', value: 'ghp_u9K8J7I6H5G4F3E2D1C0B9A8Z7Y6X5W4V3U2' }, // GitHub Token format
  { varName: 'stripeSecret', value: 'stripe_sec_val_shannon_entropy_test_passed_abc_123_xyz' }, // Stripe key mockup
  { varName: 'slack_token', value: 'slack_tok_val_shannon_entropy_test_passed_abc_123_xyz' }, // Slack token mockup
  { varName: 'privateKey', value: '-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3c5\n-----END PRIVATE KEY-----' },
  { varName: 'db_password', value: 'sUp3r_SeCr3t_P@ss_123_!' } // High entropy custom password
];

export const falsePositives = [
  // UUIDs (should be ignored since they are identifiers, not secrets)
  { varName: 'userId', value: 'f81d4fae-7dec-11d0-a765-00a0c91e6bf6' },
  { varName: 'transaction_id', value: '123e4567-e89b-12d3-a456-426614174000' },
  
  // Tailwind or long CSS/style class lists (often high entropy)
  { varName: 'className', value: 'flex items-center justify-between p-4 bg-slate-900 border-b border-slate-800 text-slate-100 hover:bg-slate-800 transition-colors duration-200' },
  { varName: 'style_class', value: 'grid grid-cols-1 md:grid-cols-3 gap-6 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12' },

  // Base64 hashed non-secrets or webpack outputs
  { varName: 'fontHash', value: 'aHR0cHM6Ly9mb250cy5nb29nbGVhcGlzLmNvbS9jc3M/ZmFtaWx5PUludGVyOjMwMCw0MDAsNTAwLDYwMCw3MDAmZGlzcGxheT1zd2Fw' },
  
  // Placeholders (should be recognized as safe)
  { varName: 'apiKey', value: 'your-api-key-here' },
  { varName: 'stripeSecret', value: 'sk_test_placeholder' },
  { varName: 'password', value: 'dummy_pwd' },
  { varName: 'token', value: 'TODO_insert_token' },
  
  // Short values (too short to have reliable entropy)
  { varName: 'db_password', value: '123' },
  { varName: 'app_secret', value: 'shh' }
];
