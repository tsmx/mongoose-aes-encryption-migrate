'use strict';

const crypto = require('crypto');
const { encrypt } = require('mongoose-aes-encryption');

// mongoose-field-encryption wire format (string fields):
//   "<16-byte-salt-hex>:<ciphertext-hex>"
//   Algorithm: AES-256-CBC
//   Key: SHA-256(secret).slice(0, 32 bytes)
//
// Non-string fields are stored in a marker field:
//   __enc_<fieldname>_d  — encrypted JSON.stringify of the original value
//   <fieldname>          — set to undefined in the document
//
// Encryption marker:
//   __enc_<fieldname>: true  — field is encrypted
//   __enc_<fieldname>: false — field is NOT encrypted (skip)

/**
 * Derive the 32-byte AES key from the secret string the same way
 * mongoose-field-encryption does internally:
 *   SHA-256(secret) → take first 32 chars of the hex digest (= 32-byte key material)
 */
function deriveKey(secret) {
    return crypto.createHash('sha256').update(secret).digest('hex').substring(0, 32);
}

/**
 * Decrypt a single field value stored by mongoose-field-encryption.
 * format: "<salt-hex>:<ciphertext-hex>"
 *
 * @param {string} encryptedValue
 * @param {string} derivedKey  — 32-char hex string (output of deriveKey)
 * @returns {string}           — plaintext string
 */
function decryptMfeField(encryptedValue, derivedKey) {
    const [saltHex, ciphertextHex] = encryptedValue.split(':');
    if (!saltHex || !ciphertextHex) {
        throw new Error(
            `mongoose-aes-encryption-migrate: unexpected mongoose-field-encryption value format: "${encryptedValue}"`
        );
    }
    const salt = Buffer.from(saltHex, 'hex');
    const ciphertext = Buffer.from(ciphertextHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', derivedKey, salt);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

/**
 * Return the marker field name for a given field.
 */
function markerField(field) {
    return `__enc_${field}`;
}

/**
 * Return the non-string data field name for a given field.
 */
function dataField(field) {
    return `__enc_${field}_d`;
}

/**
 * Preflight check for mongoose-field-encryption mode.
 *
 * Validates that for each field, the document either has the field itself
 * or the __enc_<field>_d marker. Returns missing fields.
 */
function preflight(sampleDoc, fields) {
    if (!sampleDoc) return [];
    return fields.filter((f) => {
        const hasField = sampleDoc[f] !== undefined;
        const hasMarker = sampleDoc[markerField(f)] !== undefined;
        const hasDataField = sampleDoc[dataField(f)] !== undefined;
        return !hasField && !hasMarker && !hasDataField;
    });
}

/**
 * Migrate a single collection from mongoose-field-encryption → mongoose-aes-encryption.
 *
 * Options:
 *   collection  — MongoDB native Collection object
 *   fields      — string[]  field names to migrate
 *   secret      — string    the secret used with mongoose-field-encryption
 *   key         — string    64-char hex target key for mongoose-aes-encryption
 *   algorithm   — string    default 'aes-256-gcm'
 *   batchSize   — number    default 100
 *   dryRun      — boolean   default false
 *   onProgress  — function(delta: number)
 *   onError     — async function(docId, err) → 'skip'|'abort'
 *
 * Returns { migrated, skipped, errors }
 */
async function migrateFromMongooseFieldEncryption({
    collection,
    fields,
    secret,
    key,
    algorithm = 'aes-256-gcm',
    batchSize = 100,
    dryRun = false,
    onProgress,
    onError
}) {
    const derivedKey = deriveKey(secret);
    let migrated = 0;
    let skipped = 0;
    let errors = 0;

    const cursor = collection.find({}, { batchSize });

    for await (const doc of cursor) {
        const setPayload = {};
        const unsetPayload = {};
        let docNeedsUpdate = false;

        for (const field of fields) {
            const marker = markerField(field);
            const dField = dataField(field);

            // If marker is explicitly false or missing entirely, field is not encrypted — skip
            if (!doc[marker]) {
                continue;
            }

            let plaintextString;

            // Non-string fields: value stored in __enc_<field>_d, original field is undefined
            if (doc[dField] !== undefined) {
                plaintextString = decryptMfeField(doc[dField], derivedKey);
                // plaintextString is a JSON-stringified value — keep as string for re-encryption
                // (mongoose-aes-encryption will store it as a string; the user's app is responsible
                // for JSON.parse on read, same as before — or they were using a String field type)
            } else if (doc[field] !== undefined && doc[field] !== null) {
                plaintextString = decryptMfeField(String(doc[field]), derivedKey);
            } else {
                // Marker is true but no value — treat as null, pass through
                setPayload[field] = null;
                unsetPayload[marker] = '';
                docNeedsUpdate = true;
                continue;
            }

            setPayload[field] = encrypt(plaintextString, { key, algorithm, passNull: true });
            unsetPayload[marker] = '';
            if (doc[dField] !== undefined) {
                unsetPayload[dField] = '';
            }
            docNeedsUpdate = true;
        }

        if (!docNeedsUpdate) {
            skipped++;
            if (onProgress) onProgress(1);
            continue;
        }

        if (!dryRun) {
            try {
                await collection.updateOne(
                    { _id: doc._id },
                    { $set: setPayload, $unset: unsetPayload }
                );
                migrated++;
            } catch (err) {
                const action = onError ? await onError(doc._id, err) : 'abort';
                if (action === 'abort') {
                    await cursor.close();
                    throw err;
                }
                errors++;
            }
        } else {
            migrated++;
        }

        if (onProgress) onProgress(1);
    }

    return { migrated, skipped, errors };
}

module.exports = { migrateFromMongooseFieldEncryption, preflight, deriveKey, decryptMfeField };
