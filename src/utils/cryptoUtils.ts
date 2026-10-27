import { PasswordAnalysis } from '../types/security';

/**
 * Calculates SHA-256 hash using native Web Crypto API
 */
export async function computeSHA256(data: string | ArrayBuffer): Promise<string> {
  const buffer = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Calculates SHA-1 hash using Web Crypto API
 */
export async function computeSHA1(data: string | ArrayBuffer): Promise<string> {
  const buffer = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const hashBuffer = await crypto.subtle.digest('SHA-1', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Generates an MD5-like hex fingerprint from buffer
 */
export function pseudoMD5(str: string): string {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash) + str.charCodeAt(i);
    hash |= 0;
  }
  const hex1 = Math.abs(hash).toString(16).padStart(8, '0');
  const hex2 = (Math.abs(hash * 31) >>> 0).toString(16).padStart(8, '0');
  const hex3 = (Math.abs(hash * 127) >>> 0).toString(16).padStart(8, '0');
  const hex4 = (Math.abs(hash * 257) >>> 0).toString(16).padStart(8, '0');
  return `${hex1}${hex2}${hex3}${hex4}`.slice(0, 32);
}

/**
 * Computes Shannon Entropy of a string or buffer in bits
 */
export function calculateShannonEntropy(str: string): number {
  if (!str) return 0;
  const len = str.length;
  const frequencies = new Map<string, number>();

  for (const ch of str) {
    frequencies.set(ch, (frequencies.get(ch) || 0) + 1);
  }

  let entropy = 0;
  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return Number((entropy * len).toFixed(1));
}

const COMMON_PASSWORDS = new Set([
  'password', '123456', '123456789', 'qwerty', '12345678', '111111', '12345',
  'dragon', 'welcome', 'admin', 'iloveyou', 'monkey', 'sunshine', 'princess',
  'charlie', 'football', 'shadow', 'master', 'superman', 'test1234'
]);

/**
 * Comprehensive password analyzer based on NIST 800-63B and GPU cluster cracking benchmarks
 */
export function analyzePassword(pass: string): PasswordAnalysis {
  if (!pass) {
    return {
      password: '',
      length: 0,
      entropy: 0,
      score: 0,
      crackTimeText: 'Instant',
      crackTimeSeconds: 0,
      rules: {
        minLength: false,
        hasNumber: false,
        hasSymbol: false,
        hasMixedCase: false,
        noCommonWord: true,
      },
      classification: 'VERY_WEAK',
      suggestions: ['Enter a password to begin cryptographic audit.']
    };
  }

  const length = pass.length;
  const hasLower = /[a-z]/.test(pass);
  const hasUpper = /[A-Z]/.test(pass);
  const hasNumber = /\d/.test(pass);
  const hasSymbol = /[^a-zA-Z0-9]/.test(pass);
  const hasMixedCase = hasLower && hasUpper;
  const minLength = length >= 12;
  const isCommon = COMMON_PASSWORDS.has(pass.toLowerCase());

  // Character pool
  let poolSize = 0;
  if (hasLower) poolSize += 26;
  if (hasUpper) poolSize += 26;
  if (hasNumber) poolSize += 10;
  if (hasSymbol) poolSize += 33;

  // Raw Entropy: E = L * log2(R)
  let rawEntropy = length * (poolSize > 0 ? Math.log2(poolSize) : 0);

  // Penalties for repeating characters and sequential chars
  if (/(\w)\1{2,}/.test(pass)) rawEntropy -= 10;
  if (/123|abc|qwerty|asdf/i.test(pass)) rawEntropy -= 15;
  if (isCommon) rawEntropy = 5;

  const entropy = Math.max(0, Math.floor(rawEntropy));

  // Score computation 0 - 100
  let score = 0;
  if (length >= 8) score += 15;
  if (length >= 12) score += 20;
  if (length >= 16) score += 15;
  if (hasNumber) score += 15;
  if (hasSymbol) score += 20;
  if (hasMixedCase) score += 15;

  if (isCommon) score = Math.min(score, 10);
  score = Math.min(100, Math.max(5, score));

  // Crack Time Estimation
  // Model: High performance cracking cluster (8x NVIDIA RTX 4090: ~1.2e11 guesses/sec for NTLM/MD5)
  // Real world PBKDF2/bcrypt is slower, so we calculate based on fast offline hash attack
  const guessesPerSecond = 1e10; // 10 Billion guesses/sec
  const combinations = Math.pow(2, entropy);
  const secondsToCrack = combinations / (guessesPerSecond * 2);

  let crackTimeText = 'Instant (< 1 second)';
  if (secondsToCrack < 1) {
    crackTimeText = 'Instant (< 1 sec)';
  } else if (secondsToCrack < 60) {
    crackTimeText = `${Math.ceil(secondsToCrack)} seconds`;
  } else if (secondsToCrack < 3600) {
    crackTimeText = `${Math.ceil(secondsToCrack / 60)} minutes`;
  } else if (secondsToCrack < 86400) {
    crackTimeText = `${Math.ceil(secondsToCrack / 3600)} hours`;
  } else if (secondsToCrack < 86400 * 30) {
    crackTimeText = `${Math.ceil(secondsToCrack / 86400)} days`;
  } else if (secondsToCrack < 86400 * 365) {
    crackTimeText = `${Math.ceil(secondsToCrack / (86400 * 30))} months`;
  } else if (secondsToCrack < 86400 * 365 * 1000) {
    crackTimeText = `${Math.ceil(secondsToCrack / (86400 * 365))} years`;
  } else if (secondsToCrack < 86400 * 365 * 1e6) {
    crackTimeText = `${(secondsToCrack / (86400 * 365 * 1000)).toFixed(1)}k years`;
  } else {
    crackTimeText = 'Millions of centuries';
  }

  let classification: PasswordAnalysis['classification'] = 'VERY_WEAK';
  if (score >= 85 && entropy >= 65) {
    classification = 'CRYPTO_STRONG';
  } else if (score >= 70 && entropy >= 50) {
    classification = 'STRONG';
  } else if (score >= 45 && entropy >= 35) {
    classification = 'MODERATE';
  } else if (score >= 25) {
    classification = 'WEAK';
  }

  const suggestions: string[] = [];
  if (length < 12) suggestions.push('Increase length to 14+ characters for quantum & dictionary attack resistance.');
  if (!hasMixedCase) suggestions.push('Mix uppercase and lowercase letters.');
  if (!hasNumber) suggestions.push('Incorporate numeric digits (0-9).');
  if (!hasSymbol) suggestions.push('Add special symbols such as !, @, #, $, %, ^, &, *.');
  if (isCommon) suggestions.push('CRITICAL: This password appears in top compromised wordlists. Change immediately.');
  if (suggestions.length === 0) {
    suggestions.push('Excellent cryptographic entropy. Exceeds NIST 800-63B password requirements.');
  }

  return {
    password: pass,
    length,
    entropy,
    score,
    crackTimeText,
    crackTimeSeconds: secondsToCrack,
    rules: {
      minLength,
      hasNumber,
      hasSymbol,
      hasMixedCase,
      noCommonWord: !isCommon
    },
    classification,
    suggestions
  };
}

/**
 * Cryptographically secure random password generator
 */
export function generateSecurePassword(options: {
  length: number;
  useUpper: boolean;
  useLower: boolean;
  useNumbers: boolean;
  useSymbols: boolean;
  avoidAmbiguous: boolean;
}): string {
  let lowerChars = 'abcdefghijklmnopqrstuvwxyz';
  let upperChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  let numberChars = '0123456789';
  let symbolChars = '!@#$%^&*()_+-=[]{}|;:,.<>?';

  if (options.avoidAmbiguous) {
    lowerChars = lowerChars.replace(/[ilo]/g, '');
    upperChars = upperChars.replace(/[IO]/g, '');
    numberChars = numberChars.replace(/[01]/g, '');
    symbolChars = symbolChars.replace(/[|;:.]/g, '');
  }

  let charset = '';
  const mandatory: string[] = [];

  if (options.useLower) {
    charset += lowerChars;
    mandatory.push(lowerChars[cryptoRandomInt(lowerChars.length)]);
  }
  if (options.useUpper) {
    charset += upperChars;
    mandatory.push(upperChars[cryptoRandomInt(upperChars.length)]);
  }
  if (options.useNumbers) {
    charset += numberChars;
    mandatory.push(numberChars[cryptoRandomInt(numberChars.length)]);
  }
  if (options.useSymbols) {
    charset += symbolChars;
    mandatory.push(symbolChars[cryptoRandomInt(symbolChars.length)]);
  }

  if (!charset) charset = lowerChars + numberChars;

  const targetLength = Math.max(options.length, mandatory.length);
  const result: string[] = [...mandatory];

  while (result.length < targetLength) {
    result.push(charset[cryptoRandomInt(charset.length)]);
  }

  // Shuffle using Fisher-Yates with crypto random
  for (let i = result.length - 1; i > 0; i--) {
    const j = cryptoRandomInt(i + 1);
    [result[i], result[j]] = [result[j], result[i]];
  }

  return result.join('');
}

const MEMORABLE_WORDS = [
  'cyber', 'shield', 'quantum', 'cipher', 'vector', 'matrix', 'falcon', 'nebula',
  'sentinel', 'protocol', 'aurora', 'vertex', 'beacon', 'bastion', 'glacier', 'titan',
  'stellar', 'hydra', 'vortex', 'shadow', 'obsidian', 'horizon', 'solaris', 'echo'
];

/**
 * Generates an EFF / Diceware style multi-word passphrase
 */
export function generatePassphrase(wordCount: number = 4): string {
  const words: string[] = [];
  for (let i = 0; i < wordCount; i++) {
    words.push(MEMORABLE_WORDS[cryptoRandomInt(MEMORABLE_WORDS.length)]);
  }
  const suffix = cryptoRandomInt(900) + 100;
  const symbols = ['!', '#', '$', '%', '&', '*'];
  const sym = symbols[cryptoRandomInt(symbols.length)];
  return `${words.join('-')}-${suffix}${sym}`;
}

function cryptoRandomInt(max: number): number {
  const array = new Uint32Array(1);
  crypto.getRandomValues(array);
  return array[0] % max;
}
