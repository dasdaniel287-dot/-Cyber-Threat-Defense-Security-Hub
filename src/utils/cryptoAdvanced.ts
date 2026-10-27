/**
 * Advanced Cryptographic Algorithms & Cryptanalysis Sandbox
 * Hardware-accelerated Web Crypto API implementations (AES-256-GCM, RSA-OAEP 2048)
 * and classical frequency analysis / Index of Coincidence (IoC) cipher solvers.
 */

export interface AesEncryptionResult {
  ciphertextHex: string;
  ivHex: string;
  saltHex: string;
  iterations: number;
  tagHex: string;
  executionTimeMs: number;
}

export interface RsaKeyPairPem {
  publicKeyPem: string;
  privateKeyPem: string;
  keySizeBits: number;
}

// Standard English letter frequency distribution (A-Z) in percentages
export const ENGLISH_FREQUENCIES: Record<string, number> = {
  A: 8.2, B: 1.5, C: 2.8, D: 4.3, E: 12.7, F: 2.2, G: 2.0, H: 6.1, I: 7.0,
  J: 0.15, K: 0.77, L: 4.0, M: 2.4, N: 6.7, O: 7.5, P: 1.9, Q: 0.09, R: 6.0,
  S: 6.3, T: 9.1, U: 2.8, V: 0.98, W: 2.4, X: 0.15, Y: 2.0, Z: 0.07
};

/**
 * Calculates Index of Coincidence (IoC) of a text
 * Plaintext English IoC ≈ 0.0667; Random / Polyalphabetic IoC ≈ 0.0385
 */
export function calculateIndexOfCoincidence(text: string): number {
  const clean = text.toUpperCase().replace(/[^A-Z]/g, '');
  const N = clean.length;
  if (N <= 1) return 0;

  const counts: Record<string, number> = {};
  for (const ch of clean) {
    counts[ch] = (counts[ch] || 0) + 1;
  }

  let sum = 0;
  for (const count of Object.values(counts)) {
    sum += count * (count - 1);
  }

  return Number((sum / (N * (N - 1))).toFixed(4));
}

/**
 * Performs Chi-Squared goodness-of-fit against English language frequency
 */
export function calculateChiSquared(text: string): number {
  const clean = text.toUpperCase().replace(/[^A-Z]/g, '');
  const N = clean.length;
  if (N === 0) return 9999;

  const counts: Record<string, number> = {};
  for (const ch of clean) {
    counts[ch] = (counts[ch] || 0) + 1;
  }

  let chiSq = 0;
  for (let i = 65; i <= 90; i++) {
    const ch = String.fromCharCode(i);
    const observed = counts[ch] || 0;
    const expected = (ENGLISH_FREQUENCIES[ch] / 100) * N;
    if (expected > 0) {
      chiSq += Math.pow(observed - expected, 2) / expected;
    }
  }

  return Number(chiSq.toFixed(2));
}

/**
 * Automated Caesar Cipher Breaker via Chi-Squared frequency optimization
 */
export function crackCaesarCipher(ciphertext: string): { shift: number; plaintext: string; chiSquared: number }[] {
  const results: { shift: number; plaintext: string; chiSquared: number }[] = [];

  for (let shift = 0; shift < 26; shift++) {
    let candidate = '';
    for (let i = 0; i < ciphertext.length; i++) {
      const code = ciphertext.charCodeAt(i);
      if (code >= 65 && code <= 90) {
        candidate += String.fromCharCode(((code - 65 - shift + 26) % 26) + 65);
      } else if (code >= 97 && code <= 122) {
        candidate += String.fromCharCode(((code - 97 - shift + 26) % 26) + 97);
      } else {
        candidate += ciphertext[i];
      }
    }

    const chiSq = calculateChiSquared(candidate);
    results.push({ shift, plaintext: candidate, chiSquared: chiSq });
  }

  results.sort((a, b) => a.chiSquared - b.chiSquared);
  return results;
}

/**
 * Hardware AES-GCM-256 authenticated encryption using Web Crypto API
 */
export async function encryptAesGcm(plaintext: string, passphrase: string): Promise<AesEncryptionResult> {
  const start = performance.now();
  const enc = new TextEncoder();

  // Salt & IV generation
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV recommended for GCM

  // Derive 256-bit AES key via PBKDF2 (100,000 iterations)
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  const iterations = 100000;
  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  // Encrypt with 128-bit authentication tag appended
  const encryptedBuffer = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
      tagLength: 128
    },
    key,
    enc.encode(plaintext)
  );

  const encryptedBytes = new Uint8Array(encryptedBuffer);
  // Last 16 bytes is the GCM authentication tag
  const tagBytes = encryptedBytes.slice(encryptedBytes.length - 16);
  const cipherBytes = encryptedBytes.slice(0, encryptedBytes.length - 16);

  const toHex = (b: Uint8Array) => Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');

  return {
    ciphertextHex: toHex(cipherBytes),
    ivHex: toHex(iv),
    saltHex: toHex(salt),
    iterations,
    tagHex: toHex(tagBytes),
    executionTimeMs: Number((performance.now() - start).toFixed(2))
  };
}

/**
 * Decrypts AES-GCM-256 payload with integrity tag check
 */
export async function decryptAesGcm(
  cipherHex: string,
  ivHex: string,
  saltHex: string,
  tagHex: string,
  passphrase: string
): Promise<string> {
  const fromHex = (hex: string) => {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
  };

  const cipherBytes = fromHex(cipherHex);
  const ivBytes = fromHex(ivHex);
  const saltBytes = fromHex(saltHex);
  const tagBytes = fromHex(tagHex);

  // Combine cipher and tag for Web Crypto AES-GCM
  const combined = new Uint8Array(cipherBytes.length + tagBytes.length);
  combined.set(cipherBytes, 0);
  combined.set(tagBytes, cipherBytes.length);

  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  const decryptedBuffer = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: ivBytes,
      tagLength: 128
    },
    key,
    combined
  );

  return new TextDecoder().decode(decryptedBuffer);
}

/**
 * Generates real RSA-OAEP 2048-bit keypair in the browser
 */
export async function generateRsaKeyPair(): Promise<{
  keyPair: CryptoKeyPair;
  pem: RsaKeyPairPem;
}> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]), // 65537
      hash: 'SHA-256'
    },
    true,
    ['encrypt', 'decrypt']
  );

  const pubSpki = await crypto.subtle.exportKey('spki', keyPair.publicKey);
  const privPkcs8 = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

  const toBase64 = (buf: ArrayBuffer) => {
    const bytes = new Uint8Array(buf);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  };

  const formatPem = (b64: string, label: string) => {
    const lines = b64.match(/.{1,64}/g) || [];
    return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
  };

  const publicKeyPem = formatPem(toBase64(pubSpki), 'PUBLIC KEY');
  const privateKeyPem = formatPem(toBase64(privPkcs8), 'RSA PRIVATE KEY');

  return {
    keyPair,
    pem: {
      publicKeyPem,
      privateKeyPem,
      keySizeBits: 2048
    }
  };
}
