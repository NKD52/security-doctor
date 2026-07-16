export function shannonEntropy(str: string): number {
  if (!str) return 0;
  const len = str.length;
  const frequencies: Record<string, number> = {};
  for (let i = 0; i < len; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isLikelySecret(
  varName: string,
  value: string,
  ignoredValues: string[] = []
): boolean {
  // If the value is in the ignore list, skip it
  if (ignoredValues.includes(value)) return false;

  // Immediately flag PEM format keys
  if (value.trim().startsWith('-----BEGIN ')) {
    return true;
  }

  // Basic checks
  if (value.length < 8) return false; // Too short to be a meaningful secret
  if (value.includes(' ')) return false; // Secrets generally don't contain spaces
  if (UUID_REGEX.test(value)) return false; // UUIDs are not secrets (they are identifiers)

  // Check if variable name matches key secret/auth patterns
  const nameLower = varName.toLowerCase();
  const isSecretVar = /key|secret|password|pwd|token|auth|credential|private/i.test(nameLower);
  if (!isSecretVar) return false;

  // Filter out common placeholders and mock strings
  const valueLower = value.toLowerCase();
  const placeholders = [
    'placeholder',
    'dummy',
    'todo',
    'your_',
    'your-',
    'insert_',
    'insert-',
    'fake_',
    'fake-',
    'key_here',
    'token_here'
  ];
  if (placeholders.some(p => valueLower.includes(p))) return false;

  // Shannon entropy check
  const entropy = shannonEntropy(value);

  // We set a tunable threshold. Standard secrets like API keys or base64 keys
  // usually have an entropy greater than 3.5. Let's make it 3.5 by default.
  return entropy > 3.5;
}
