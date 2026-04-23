'use strict';

const { decrypt } = require('mongoose-aes-encryption');

const hexPattern = /^[0-9a-fA-F]+$/;

/**
 * Return true if every segment is a non-empty hex string.
 */
function allHex(parts) {
    return parts.every((p) => p.length > 0 && hexPattern.test(p));
}

/**
 * Detect whether a value already looks like a ciphertext produced by
 * @tsmx/mongoose-aes-encryption.
 *
 * Wire formats:
 *   AES-256-GCM  → iv|ciphertext|authTag  (3 pipe-separated hex parts)
 *   AES-256-CBC  → iv|ciphertext          (2 pipe-separated hex parts)
 *
 * The heuristic:
 *   1. Value must be a string.
 *   2. Split on '|' — must yield 2 or 3 parts, all valid hex.
 *   3. Attempt a decrypt() with the provided key — if it succeeds without
 *      throwing, the value is definitely already encrypted.
 *
 * Returns true if the value appears to be an existing ciphertext.
 */
function isAlreadyEncrypted(value, key) {
    if (typeof value !== 'string') return false;

    const parts = value.split('|');
    if (parts.length !== 2 && parts.length !== 3) return false;
    if (!allHex(parts)) return false;

    try {
        decrypt(value, { key, passNull: true });
        return true;
    } catch (_e) {
        return false;
    }
}

module.exports = { isAlreadyEncrypted };
