const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Encryption and decryption utilities using AES-256-GCM
 */

class EncryptionManager {
  /**
   * Encrypt data using AES-256-GCM
   * @param {Buffer} data - Data to encrypt
   * @param {Buffer} key - 32-byte encryption key
   * @returns {Object} {ciphertext, iv, authTag, hash}
   */
  static encryptData(data, key) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

    let ciphertext = cipher.update(data);
    ciphertext = Buffer.concat([ciphertext, cipher.final()]);
    const authTag = cipher.getAuthTag();

    // Calculate hash of original data
    const hash = crypto.createHash('sha256').update(data).digest('hex');

    return {
      ciphertext: ciphertext.toString('hex'),
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
      hash: hash
    };
  }

  /**
   * Decrypt data using AES-256-GCM
   * @param {Object} encryptedData - {ciphertext, iv, authTag}
   * @param {Buffer} key - 32-byte encryption key
   * @returns {Buffer} Decrypted data
   */
  static decryptData(encryptedData, key) {
    const iv = Buffer.from(encryptedData.iv, 'hex');
    const ciphertext = Buffer.from(encryptedData.ciphertext, 'hex');
    const authTag = Buffer.from(encryptedData.authTag, 'hex');

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);

    let plaintext = decipher.update(ciphertext);
    plaintext = Buffer.concat([plaintext, decipher.final()]);

    return plaintext;
  }

  /**
   * Verify hash of decrypted data
   * @param {Buffer} data - Decrypted data
   * @param {string} expectedHash - Expected SHA256 hash
   * @returns {boolean} True if hash matches
   */
  static verifyHash(data, expectedHash) {
    const computedHash = crypto.createHash('sha256').update(data).digest('hex');
    return computedHash === expectedHash;
  }

  /**
   * Encrypt a file
   * @param {string} filePath - Path to file to encrypt
   * @param {Buffer} key - 32-byte encryption key
   * @returns {Object} {ciphertext, iv, authTag, hash, filename}
   */
  static encryptFile(filePath, key) {
    const data = fs.readFileSync(filePath);
    const filename = path.basename(filePath);
    const encrypted = this.encryptData(data, key);
    encrypted.filename = filename;
    return encrypted;
  }

  /**
   * Decrypt file data and save to disk
   * @param {Object} encryptedData - {ciphertext, iv, authTag, filename}
   * @param {Buffer} key - 32-byte encryption key
   * @param {string} outputDir - Directory to save decrypted file
   * @returns {string} Path to decrypted file
   */
  static decryptFile(encryptedData, key, outputDir) {
    const plaintext = this.decryptData(encryptedData, key);
    const filename = encryptedData.filename || 'downloaded_file';
    const outputPath = path.join(outputDir, filename);

    // Create unique filename if it already exists
    let finalPath = outputPath;
    let counter = 1;
    while (fs.existsSync(finalPath)) {
      const ext = path.extname(filename);
      const name = path.basename(filename, ext);
      finalPath = path.join(outputDir, `${name}_${counter}${ext}`);
      counter++;
    }

    fs.writeFileSync(finalPath, plaintext);
    return finalPath;
  }

  /**
   * Calculate hash of a buffer
   * @param {Buffer} data - Data to hash
   * @returns {string} SHA256 hash as hex string
   */
  static calculateHash(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
  }
}

module.exports = EncryptionManager;
