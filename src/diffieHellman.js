const crypto = require('crypto');

/**
 * Diffie-Hellman key exchange implementation
 * Uses prime numbers suitable for secure communication
 */

// Well-known group from RFC 3526 (2048-bit MODP Group)
const DHParameters = {
  p: BigInt('0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF'),
  g: BigInt(2)
};

class DiffieHellman {
  constructor() {
    this.p = DHParameters.p;
    this.g = DHParameters.g;
    this.privateKey = this.generatePrivateKey();
    this.publicKey = this.calculatePublicKey();
  }

  /**
   * Generate a random private key
   */
  generatePrivateKey() {
    // Generate a random number between 2 and p-2
    let key;
    do {
      const bytes = crypto.randomBytes(256);
      key = BigInt('0x' + bytes.toString('hex'));
      key = (key % (this.p - BigInt(2))) + BigInt(1);
    } while (key < BigInt(2));
    return key;
  }

  /**
   * Calculate public key: g^x mod p
   */
  calculatePublicKey() {
    return this.modExp(this.g, this.privateKey, this.p);
  }

  /**
   * Modular exponentiation using JavaScript's built-in BigInt
   */
  modExp(base, exp, mod) {
    if (mod === BigInt(1)) return BigInt(0);
    let result = BigInt(1);
    base = base % mod;
    while (exp > BigInt(0)) {
      if (exp % BigInt(2) === BigInt(1)) {
        result = (result * base) % mod;
      }
      exp = exp >> BigInt(1);
      base = (base * base) % mod;
    }
    return result;
  }

  /**
   * Get the public key as a hex string
   */
  getPublicKeyHex() {
    return this.publicKey.toString(16);
  }

  /**
   * Calculate the shared secret given the other party's public key
   * @param {string|BigInt} otherPublicKeyHex - Other party's public key as hex string or BigInt
   * @returns {Buffer} Shared secret
   */
  computeSharedSecret(otherPublicKeyHex) {
    let otherPublicKey;
    if (typeof otherPublicKeyHex === 'string') {
      otherPublicKey = BigInt('0x' + otherPublicKeyHex);
    } else {
      otherPublicKey = otherPublicKeyHex;
    }

    const sharedSecret = this.modExp(otherPublicKey, this.privateKey, this.p);
    const hexString = sharedSecret.toString(16);
    // Pad to even length
    const paddedHex = hexString.length % 2 === 0 ? hexString : '0' + hexString;
    return Buffer.from(paddedHex, 'hex');
  }

  /**
   * Get private key for testing/debugging (DANGEROUS - DO NOT USE IN PRODUCTION)
   */
  getPrivateKeyHex() {
    return this.privateKey.toString(16);
  }
}

/**
 * Derive an encryption key from shared secret using HKDF
 * @param {Buffer} sharedSecret - Shared secret from DH
 * @param {string} salt - Optional salt
 * @param {string} info - Optional info string
 * @returns {Buffer} 32-byte encryption key
 */
function deriveEncryptionKey(sharedSecret, salt = '', info = 'encryption') {
  const hash = crypto.createHash('sha256');
  hash.update(sharedSecret);
  hash.update(salt);
  return hash.digest();
}

module.exports = {
  DiffieHellman,
  DHParameters,
  deriveEncryptionKey
};
