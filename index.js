'use strict';

const { connect, countDocuments, sampleDocument } = require('./lib/mongo');
const { migratePlaintext, preflight: plaintextPreflight } = require('./lib/plaintext');
const { migrateFromMongooseEncryption, preflight: mePreflight } = require('./lib/mongoose-encryption');
const { migrateFromMongooseFieldEncryption, preflight: mfePreflight } = require('./lib/mongoose-field-encryption');

/**
 * Programmatic API — plaintext → @tsmx/mongoose-aes-encryption
 *
 * @param {object} opts
 * @param {string}   opts.uri           MongoDB connection string (must include db name)
 * @param {string}   opts.collection    Collection name
 * @param {string[]} opts.fields        Field paths to encrypt
 * @param {string}   opts.key           64-char hex key
 * @param {string}   [opts.algorithm]   'aes-256-gcm' (default) | 'aes-256-cbc'
 * @param {number}   [opts.batchSize]   Documents per batch (default 100)
 * @param {boolean}  [opts.dryRun]      When true, no writes are made
 * @returns {Promise<{ migrated: number, skipped: number, errors: number }>}
 */
async function plaintextToEncrypted(opts) {
    const {
        uri,
        collection: collectionName,
        fields,
        key,
        algorithm = 'aes-256-gcm',
        batchSize = 100,
        dryRun = false
    } = opts;

    if (!uri) throw new Error('mongoose-aes-encryption-migrate: opts.uri is required');
    if (!collectionName) throw new Error('mongoose-aes-encryption-migrate: opts.collection is required');
    if (!fields || fields.length === 0) throw new Error('mongoose-aes-encryption-migrate: opts.fields must be a non-empty array');
    if (!key) throw new Error('mongoose-aes-encryption-migrate: opts.key is required');

    const { client, collection } = await connect(uri, collectionName);

    try {
        const sample = await sampleDocument(collection);
        const missing = plaintextPreflight(sample, fields);
        if (missing.length > 0) {
            throw new Error(
                `mongoose-aes-encryption-migrate: the following fields were not found in the sample document: ${missing.join(', ')}`
            );
        }

        // In programmatic mode, errors always throw (no interactive prompt)
        const onError = async (_id, err) => { throw err; };

        return await migratePlaintext({ collection, fields, key, algorithm, batchSize, dryRun, onError });
    } finally {
        await client.close();
    }
}

/**
 * Programmatic API — mongoose-encryption → @tsmx/mongoose-aes-encryption
 *
 * @param {object} opts
 * @param {string}   opts.uri              MongoDB connection string (must include db name)
 * @param {string}   opts.collection       Collection name
 * @param {string[]} opts.fields           Fields from _ct to re-encrypt with the new plugin
 * @param {string[]} [opts.plaintextFields] Fields from _ct to restore as plaintext
 * @param {string}   opts.key              64-char hex target key
 * @param {string}   opts.sourceKey        base64-encoded 32-byte mongoose-encryption encryptionKey
 * @param {string}   [opts.algorithm]      'aes-256-gcm' (default) | 'aes-256-cbc'
 * @param {number}   [opts.batchSize]      Documents per batch (default 100)
 * @param {boolean}  [opts.dryRun]         When true, no writes are made
 * @returns {Promise<{ migrated: number, skipped: number, errors: number }>}
 */
async function mongooseEncryptionToEncrypted(opts) {
    const {
        uri,
        collection: collectionName,
        fields,
        plaintextFields = [],
        key,
        sourceKey,
        algorithm = 'aes-256-gcm',
        batchSize = 100,
        dryRun = false
    } = opts;

    if (!uri) throw new Error('mongoose-aes-encryption-migrate: opts.uri is required');
    if (!collectionName) throw new Error('mongoose-aes-encryption-migrate: opts.collection is required');
    if (!fields || fields.length === 0) throw new Error('mongoose-aes-encryption-migrate: opts.fields must be a non-empty array');
    if (!key) throw new Error('mongoose-aes-encryption-migrate: opts.key is required');
    if (!sourceKey) throw new Error('mongoose-aes-encryption-migrate: opts.sourceKey is required (base64 mongoose-encryption encryptionKey)');

    const { client, collection } = await connect(uri, collectionName);

    try {
        const sample = await sampleDocument(collection);
        const { discoveredFields, unaccountedFields } = mePreflight(sample, fields, plaintextFields, sourceKey);

        if (unaccountedFields.length > 0) {
            throw new Error(
                `mongoose-aes-encryption-migrate: the following fields found in _ct are not accounted for: ${unaccountedFields.join(', ')}. ` +
                'Add them to opts.fields (re-encrypt) or opts.plaintextFields (restore as plaintext).'
            );
        }

        if (discoveredFields.length === 0 && sample && !sample._ct) {
            // Collection has no _ct — nothing to migrate
            return { migrated: 0, skipped: 0, errors: 0 };
        }

        // In programmatic mode, errors always throw
        const onError = async (_id, err) => { throw err; };

        return await migrateFromMongooseEncryption({
            collection, fields, plaintextFields, key, sourceKeyBase64: sourceKey,
            algorithm, batchSize, dryRun, onError
        });
    } finally {
        await client.close();
    }
}

/**
 * Programmatic API — mongoose-field-encryption → mongoose-aes-encryption
 *
 * @param {object} opts
 * @param {string}   opts.uri           MongoDB connection string (must include db name)
 * @param {string}   opts.collection    Collection name
 * @param {string[]} opts.fields        Field names to migrate
 * @param {string}   opts.secret        The secret string used with mongoose-field-encryption
 * @param {string}   opts.key           64-char hex target key
 * @param {string}   [opts.algorithm]   'aes-256-gcm' (default) | 'aes-256-cbc'
 * @param {number}   [opts.batchSize]   Documents per batch (default 100)
 * @param {boolean}  [opts.dryRun]      When true, no writes are made
 * @returns {Promise<{ migrated: number, skipped: number, errors: number }>}
 */
async function mongooseFieldEncryptionToEncrypted(opts) {
    const {
        uri,
        collection: collectionName,
        fields,
        secret,
        key,
        algorithm = 'aes-256-gcm',
        batchSize = 100,
        dryRun = false
    } = opts;

    if (!uri) throw new Error('mongoose-aes-encryption-migrate: opts.uri is required');
    if (!collectionName) throw new Error('mongoose-aes-encryption-migrate: opts.collection is required');
    if (!fields || fields.length === 0) throw new Error('mongoose-aes-encryption-migrate: opts.fields must be a non-empty array');
    if (!secret) throw new Error('mongoose-aes-encryption-migrate: opts.secret is required (the secret used with mongoose-field-encryption)');
    if (!key) throw new Error('mongoose-aes-encryption-migrate: opts.key is required');

    const { client, collection } = await connect(uri, collectionName);

    try {
        const sample = await sampleDocument(collection);
        const missing = mfePreflight(sample, fields);
        if (missing.length > 0) {
            throw new Error(
                `mongoose-aes-encryption-migrate: the following fields were not found in the sample document: ${missing.join(', ')}`
            );
        }

        // In programmatic mode, errors always throw
        const onError = async (_id, err) => { throw err; };

        return await migrateFromMongooseFieldEncryption({
            collection, fields, secret, key, algorithm, batchSize, dryRun, onError
        });
    } finally {
        await client.close();
    }
}

module.exports = { plaintextToEncrypted, mongooseEncryptionToEncrypted, mongooseFieldEncryptionToEncrypted };
