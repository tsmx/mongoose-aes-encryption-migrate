'use strict';

const { encrypt } = require('mongoose-aes-encryption');
const { isAlreadyEncrypted } = require('../lib/detect');

const KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const OTHER_KEY = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789';

test('returns false for non-string values', () => {
    expect(isAlreadyEncrypted(null, KEY)).toBe(false);
    expect(isAlreadyEncrypted(42, KEY)).toBe(false);
    expect(isAlreadyEncrypted({}, KEY)).toBe(false);
    expect(isAlreadyEncrypted(undefined, KEY)).toBe(false);
});

test('returns false for strings with wrong pipe count', () => {
    expect(isAlreadyEncrypted('nopipes', KEY)).toBe(false);
    expect(isAlreadyEncrypted('one|pipe', KEY)).toBe(false);  // 2 parts but not valid ciphertext
    expect(isAlreadyEncrypted('a|b|c|d', KEY)).toBe(false);  // 4 parts
});

test('returns false for non-hex segments', () => {
    expect(isAlreadyEncrypted('zzzz|yyyy|xxxx', KEY)).toBe(false);
    expect(isAlreadyEncrypted('ab12|zz00|cd34', KEY)).toBe(false);
});

test('returns false for valid hex pipe format but wrong key (decrypt throws)', () => {
    // Produce a genuine ciphertext with KEY, then try to detect with OTHER_KEY
    const ciphertext = encrypt('hello', { key: KEY, algorithm: 'aes-256-gcm' });
    expect(isAlreadyEncrypted(ciphertext, OTHER_KEY)).toBe(false);
});

test('returns true for genuine GCM ciphertext with correct key', () => {
    const ciphertext = encrypt('hello', { key: KEY, algorithm: 'aes-256-gcm' });
    expect(isAlreadyEncrypted(ciphertext, KEY)).toBe(true);
});

test('returns true for genuine CBC ciphertext with correct key', () => {
    const ciphertext = encrypt('hello', { key: KEY, algorithm: 'aes-256-cbc' });
    expect(isAlreadyEncrypted(ciphertext, KEY)).toBe(true);
});
