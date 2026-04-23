'use strict';

const crypto = require('crypto');
const { encrypt } = require('mongoose-aes-encryption');

// mongoose-encryption _ct layout:
//   byte  0      : version (1 byte)
//   bytes 1–16   : IV (16 bytes, AES-CBC block size)
//   bytes 17+    : AES-256-CBC ciphertext of JSON.stringify({ field: value, ... })

const CT_IV_START = 1;
const CT_IV_END = 17;   // exclusive
const CT_DATA_START = 17;

/**
 * Decrypt a mongoose-encryption _ct Buffer using the given base64 encryptionKey.
 * Returns the parsed JSON object bundled inside _ct.
 *
 * @param {Buffer} ctBuffer
 * @param {string} sourceKeyBase64  — base64-encoded 32-byte encryption key
 * @returns {object}
 */
function decryptMongooseEncryptionCt(ctBuffer, sourceKeyBase64) {
    const keyBuf = Buffer.from(sourceKeyBase64, 'base64');
    if (keyBuf.length !== 32) {
        throw new Error(
            `mongoose-aes-encryption-migrate: source key must be a 32-byte base64 string (got ${keyBuf.length} bytes). ` +
            'Provide the encryptionKey used with mongoose-encryption.'
        );
    }
    const iv = ctBuffer.slice(CT_IV_START, CT_IV_END);
    const ciphertext = ctBuffer.slice(CT_DATA_START);
    const decipher = crypto.createDecipheriv('aes-256-cbc', keyBuf, iv);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return JSON.parse(decrypted.toString('utf8'));
}

/**
 * Probe a single document to discover all field names bundled inside _ct.
 * Returns an array of field name strings, or null if the document has no _ct.
 */
function discoverCtFields(sampleDoc, sourceKeyBase64) {
    if (!sampleDoc || !sampleDoc._ct) return null;

    const ctBuffer = sampleDoc._ct.buffer
        ? Buffer.from(sampleDoc._ct.buffer)   // BSON Binary → Buffer
        : Buffer.from(sampleDoc._ct);

    const bundled = decryptMongooseEncryptionCt(ctBuffer, sourceKeyBase64);
    return Object.keys(bundled);
}

/**
 * Preflight for mongoose-encryption mode.
 *
 * Checks that every key found inside _ct is accounted for by either
 * `fields` (re-encrypt) or `plaintextFields` (restore as plaintext).
 *
 * Returns { discoveredFields, unaccountedFields }.
 */
function preflight(sampleDoc, fields, plaintextFields, sourceKeyBase64) {
    const discoveredFields = discoverCtFields(sampleDoc, sourceKeyBase64);
    if (!discoveredFields) {
        return { discoveredFields: [], unaccountedFields: [] };
    }
    const accounted = new Set([...fields, ...plaintextFields]);
    const unaccountedFields = discoveredFields.filter((f) => !accounted.has(f));
    return { discoveredFields, unaccountedFields };
}

/**
 * Migrate a single collection from mongoose-encryption → @tsmx/mongoose-aes-encryption.
 *
 * Options:
 *   collection      — MongoDB native Collection object
 *   fields          — string[]  field names from _ct to re-encrypt with the new plugin
 *   plaintextFields — string[]  field names from _ct to restore as plaintext
 *   key             — string    64-char hex target key
 *   sourceKeyBase64 — string    base64 encryptionKey used with mongoose-encryption
 *   algorithm       — string    default 'aes-256-gcm'
 *   batchSize       — number    default 100
 *   dryRun          — boolean   default false
 *   onProgress      — function(delta: number)
 *   onError         — async function(docId, err) → 'skip'|'abort'
 *
 * Returns { migrated, skipped, errors }
 */
async function migrateFromMongooseEncryption({
    collection,
    fields,
    plaintextFields = [],
    key,
    sourceKeyBase64,
    algorithm = 'aes-256-gcm',
    batchSize = 100,
    dryRun = false,
    onProgress,
    onError
}) {
    let migrated = 0;
    let skipped = 0;
    let errors = 0;

    const cursor = collection.find({}, { batchSize });

    for await (const doc of cursor) {
        // Skip documents that have already been migrated (no _ct present)
        if (!doc._ct) {
            skipped++;
            if (onProgress) onProgress(1);
            continue;
        }

        try {
            const ctBuffer = doc._ct.buffer
                ? Buffer.from(doc._ct.buffer)
                : Buffer.from(doc._ct);

            const bundled = decryptMongooseEncryptionCt(ctBuffer, sourceKeyBase64);

            const setPayload = {};
            const unsetPayload = { _ct: '', _ac: '' };

            for (const field of fields) {
                const value = bundled[field];
                if (value == null) {
                    setPayload[field] = value;
                } else {
                    setPayload[field] = encrypt(String(value), { key, algorithm, passNull: true });
                }
            }

            for (const field of plaintextFields) {
                setPayload[field] = bundled[field] !== undefined ? bundled[field] : null;
            }

            if (!dryRun) {
                await collection.updateOne(
                    { _id: doc._id },
                    { $set: setPayload, $unset: unsetPayload }
                );
            }

            migrated++;
        } catch (err) {
            const action = onError ? await onError(doc._id, err) : 'abort';
            if (action === 'abort') {
                await cursor.close();
                throw err;
            }
            errors++;
        }

        if (onProgress) onProgress(1);
    }

    return { migrated, skipped, errors };
}

module.exports = { migrateFromMongooseEncryption, preflight, discoverCtFields };
