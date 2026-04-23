'use strict';

const mongoose = require('mongoose');
const mongooseEncryption = require('mongoose-encryption');
const { fieldEncryption } = require('mongoose-field-encryption');
const {
    TARGET_KEY,
    SOURCE_ENC_KEY,
    SOURCE_SIG_KEY,
    SOURCE_SECRET,
    startDb,
    stopDb,
} = require('./helpers');
const {
    plaintextToEncrypted,
    mongooseEncryptionToEncrypted,
    mongooseFieldEncryptionToEncrypted,
} = require('../index');

let mongoServer, uri;
let sourceConn;
let PlainModel, MEModel, MFEModel;

beforeAll(async () => {
    ({ mongoServer, uri } = await startDb());
    sourceConn = await mongoose.createConnection(uri).asPromise();

    // Plain model for plaintext tests
    PlainModel = sourceConn.model('plain_users', new mongoose.Schema({ name: String }, { strict: false }), 'plain_users');

    // mongoose-encryption model
    const meSchema = new mongoose.Schema({ name: String }, { strict: false });
    meSchema.plugin(mongooseEncryption, {
        encryptionKey: SOURCE_ENC_KEY,
        signingKey: SOURCE_SIG_KEY,
        encryptedFields: ['name'],
    });
    MEModel = sourceConn.model('me_users', meSchema, 'me_users');

    // mongoose-field-encryption model
    const mfeSchema = new mongoose.Schema({ name: String }, { strict: false });
    mfeSchema.plugin(fieldEncryption, { fields: ['name'], secret: SOURCE_SECRET });
    MFEModel = sourceConn.model('mfe_users', mfeSchema, 'mfe_users');
});

afterAll(async () => {
    await sourceConn.close();
    await stopDb(mongoServer);
});

// ---------------------------------------------------------------------------
// plaintextToEncrypted — input validation
// ---------------------------------------------------------------------------

describe('plaintextToEncrypted input validation', () => {
    test('throws when uri is missing', async () => {
        await expect(plaintextToEncrypted({ collection: 'c', fields: ['name'], key: TARGET_KEY }))
            .rejects.toThrow('opts.uri is required');
    });

    test('throws when collection is missing', async () => {
        await expect(plaintextToEncrypted({ uri, fields: ['name'], key: TARGET_KEY }))
            .rejects.toThrow('opts.collection is required');
    });

    test('throws when fields is empty', async () => {
        await expect(plaintextToEncrypted({ uri, collection: 'c', fields: [], key: TARGET_KEY }))
            .rejects.toThrow('opts.fields must be a non-empty array');
    });

    test('throws when key is missing', async () => {
        await expect(plaintextToEncrypted({ uri, collection: 'c', fields: ['name'] }))
            .rejects.toThrow('opts.key is required');
    });

    test('throws on preflight failure — field missing from sample doc', async () => {
        await PlainModel.create({ name: 'Alice' });
        await expect(
            plaintextToEncrypted({ uri, collection: 'plain_users', fields: ['nonexistent'], key: TARGET_KEY })
        ).rejects.toThrow('nonexistent');
        await PlainModel.deleteMany({});
    });
});

// ---------------------------------------------------------------------------
// mongooseEncryptionToEncrypted — input validation
// ---------------------------------------------------------------------------

describe('mongooseEncryptionToEncrypted input validation', () => {
    test('throws when uri is missing', async () => {
        await expect(mongooseEncryptionToEncrypted({ collection: 'c', fields: ['name'], key: TARGET_KEY, sourceKey: SOURCE_ENC_KEY }))
            .rejects.toThrow('opts.uri is required');
    });

    test('throws when collection is missing', async () => {
        await expect(mongooseEncryptionToEncrypted({ uri, fields: ['name'], key: TARGET_KEY, sourceKey: SOURCE_ENC_KEY }))
            .rejects.toThrow('opts.collection is required');
    });

    test('throws when fields is empty', async () => {
        await expect(mongooseEncryptionToEncrypted({ uri, collection: 'c', fields: [], key: TARGET_KEY, sourceKey: SOURCE_ENC_KEY }))
            .rejects.toThrow('opts.fields must be a non-empty array');
    });

    test('throws when key is missing', async () => {
        await expect(mongooseEncryptionToEncrypted({ uri, collection: 'c', fields: ['name'], sourceKey: SOURCE_ENC_KEY }))
            .rejects.toThrow('opts.key is required');
    });

    test('throws when sourceKey is missing', async () => {
        await expect(mongooseEncryptionToEncrypted({ uri, collection: 'c', fields: ['name'], key: TARGET_KEY }))
            .rejects.toThrow('opts.sourceKey is required');
    });

    test('throws on preflight failure — unaccounted field in _ct', async () => {
        // Save a doc that encrypts 'name' into _ct, then ask to migrate only 'other'
        await MEModel.create({ name: 'Alice' });
        await expect(
            mongooseEncryptionToEncrypted({ uri, collection: 'me_users', fields: ['other'], key: TARGET_KEY, sourceKey: SOURCE_ENC_KEY })
        ).rejects.toThrow('not accounted for');
        await MEModel.deleteMany({});
    });
});

// ---------------------------------------------------------------------------
// mongooseFieldEncryptionToEncrypted — input validation
// ---------------------------------------------------------------------------

describe('mongooseFieldEncryptionToEncrypted input validation', () => {
    test('throws when uri is missing', async () => {
        await expect(mongooseFieldEncryptionToEncrypted({ collection: 'c', fields: ['name'], secret: SOURCE_SECRET, key: TARGET_KEY }))
            .rejects.toThrow('opts.uri is required');
    });

    test('throws when collection is missing', async () => {
        await expect(mongooseFieldEncryptionToEncrypted({ uri, fields: ['name'], secret: SOURCE_SECRET, key: TARGET_KEY }))
            .rejects.toThrow('opts.collection is required');
    });

    test('throws when fields is empty', async () => {
        await expect(mongooseFieldEncryptionToEncrypted({ uri, collection: 'c', fields: [], secret: SOURCE_SECRET, key: TARGET_KEY }))
            .rejects.toThrow('opts.fields must be a non-empty array');
    });

    test('throws when secret is missing', async () => {
        await expect(mongooseFieldEncryptionToEncrypted({ uri, collection: 'c', fields: ['name'], key: TARGET_KEY }))
            .rejects.toThrow('opts.secret is required');
    });

    test('throws when key is missing', async () => {
        await expect(mongooseFieldEncryptionToEncrypted({ uri, collection: 'c', fields: ['name'], secret: SOURCE_SECRET }))
            .rejects.toThrow('opts.key is required');
    });

    test('throws on preflight failure — field missing from sample doc', async () => {
        await MFEModel.create({ name: 'Alice' });
        await expect(
            mongooseFieldEncryptionToEncrypted({ uri, collection: 'mfe_users', fields: ['nonexistent'], secret: SOURCE_SECRET, key: TARGET_KEY })
        ).rejects.toThrow('nonexistent');
        await MFEModel.deleteMany({});
    });
});
