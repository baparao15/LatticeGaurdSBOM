/**
 * Quantum-Safe Crypto Mock & Real Classical Crypto Utilities
 * Uses standard Web Crypto API where possible.
 */

// Generate a real SHA-256 hash using Web Crypto API
export async function generateSHA256(text: string): Promise<string> {
  const msgBuffer = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Generate real classical keys (ECDSA as standard fallback for Ed25519 compatibility issues in some contexts)
export async function generateClassicalKeys(): Promise<CryptoKeyPair> {
  return await crypto.subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: "P-256",
    },
    true,
    ["sign", "verify"]
  );
}

// Sign data using real classical keys
export async function signClassical(data: string, privateKey: CryptoKey): Promise<string> {
  const msgBuffer = new TextEncoder().encode(data);
  const signatureBuffer = await crypto.subtle.sign(
    {
      name: "ECDSA",
      hash: { name: "SHA-256" },
    },
    privateKey,
    msgBuffer
  );
  const sigArray = Array.from(new Uint8Array(signatureBuffer));
  return sigArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Simulated ML-DSA-65 (FIPS 204) Logic
// Real ML-DSA requires WASM/OQS which is heavy for a UI demo.
export function generateMLDSAKeys() {
  // ML-DSA-65 public key size: 1952 bytes
  const pubBytes = new Uint8Array(1952);
  crypto.getRandomValues(pubBytes);
  const pubHex = Array.from(pubBytes).slice(0, 32).map(b => b.toString(16).padStart(2, '0')).join('');
  
  return {
    publicKeyHex: pubHex,
    publicKeyBytes: 1952,
    privateKeyBytes: 4032,
    securityLevel: "NIST Level 3"
  };
}

export function signMLDSA(): string {
  // ML-DSA-65 signature size: 2420 bytes
  // For demo visual purposes, we generate a 64-char hex string to represent the start of the 2420 byte sig
  const sigBytes = new Uint8Array(32); 
  crypto.getRandomValues(sigBytes);
  return Array.from(sigBytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function generateUUID(): string {
  return crypto.randomUUID();
}
