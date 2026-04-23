'use strict';

const { encrypt } = require('mongoose-aes-encryption');
const { isAlreadyEncrypted } = require('./detect');

/**
 * Resolve a (possibly dot-notation) field path on a plain object.
 * Returns undefined if any segment is missing.
 */
function getField(doc, path) {
    return path.split('.').reduce((obj, seg) => (obj != null ? obj[seg] : undefined), doc);
}

/**
 * Preflight check for plaintext mode.
 *
 * Validates that every field in `fields` actually exists on the sample document.
 * Returns an array of missing field names (empty = all good).
 */
function preflight(sampleDoc, fields) {
    if (!sampleDoc) return [];
    return fields.filter((f) => getField(sampleDoc, f) === undefined);
}

/**
 * Migrate a single collection from plaintext → AES-encrypted.
 *
 * Options:
 *   collection  — MongoDB native Collection object
 *   fields      — string[]  field paths to encrypt
 *   key         — string    64-char hex target key
 *   algorithm   — string    default 'aes-256-gcm'
 *   batchSize   — number    default 100
 *   dryRun      — boolean   default false
 *   onProgress  — function(delta: number)  called after each document
 *   onError     — async function(docId, err) → 'skip'|'abort'
 *                 For the programmatic API this should throw; for the CLI it
 *                 should prompt the user.
 *
 * Returns { migrated, skipped, errors }
 */
async function migratePlaintext({ collection, fields, key, algorithm = 'aes-256-gcm', batchSize = 100, dryRun = false, onProgress, onError }) {
    let migrated = 0;
    let skipped = 0;
    let errors = 0;

    const cursor = collection.find({}, { batchSize });

    for await (const doc of cursor) {
        const setPayload = {};
        let docNeedsUpdate = false;

        for (const field of fields) {
            const value = getField(doc, field);

            // null/undefined — leave as-is
            if (value == null) continue;

            if (isAlreadyEncrypted(value, key)) {
                // field already encrypted, nothing to do
                continue;
            }

            const plaintext = String(value);
            const ciphertext = encrypt(plaintext, { key, algorithm, passNull: true });
            setPayload[field] = ciphertext;
            docNeedsUpdate = true;
        }

        if (!docNeedsUpdate) {
            skipped++;
            if (onProgress) onProgress(1);
            continue;
        }

        if (!dryRun) {
            try {
                await collection.updateOne({ _id: doc._id }, { $set: setPayload });
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

module.exports = { migratePlaintext, preflight };
