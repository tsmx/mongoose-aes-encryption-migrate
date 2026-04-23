'use strict';

const mongoose = require('mongoose');
const mongooseEncryption = require('mongoose-encryption');
const {
    TARGET_KEY,
    SOURCE_ENC_KEY,
    SOURCE_SIG_KEY,
    startDb,
    stopDb,
    getNativeCollection,
    getEncryptedMongooseModel,
} = require('./helpers');
const { mongooseEncryptionToEncrypted } = require('../index');
const { migrateFromMongooseEncryption } = require('../lib/mongoose-encryption');

const COLLECTION = 'users';

let mongoServer, uri;
let sourceConn, SourceModel;

beforeAll(async () => {
    ({ mongoServer, uri } = await startDb());

    // Mongoose model with mongoose-encryption plugin for inserting source docs
    sourceConn = await mongoose.createConnection(uri).asPromise();
    const schema = new mongoose.Schema({ name: String }, { strict: false });
    schema.plugin(mongooseEncryption, {
        encryptionKey: SOURCE_ENC_KEY,
        signingKey: SOURCE_SIG_KEY,
        encryptedFields: ['name'],
    });
    SourceModel = sourceConn.model(COLLECTION, schema, COLLECTION);
});

afterAll(async () => {
    await sourceConn.close();
    await stopDb(mongoServer);
});

afterEach(async () => {
    await SourceModel.deleteMany({});
});

test('migrates all mongoose-encryption documents', async () => {
    await SourceModel.create([{ name: 'Alice' }, { name: 'Bob' }, { name: 'Carol' }]);

    const result = await mongooseEncryptionToEncrypted({
        uri,
        collection: COLLECTION,
        fields: ['name'],
        key: TARGET_KEY,
        sourceKey: SOURCE_ENC_KEY,
    });

    expect(result).toEqual({ migrated: 3, skipped: 0, errors: 0 });
});

test('migrated values are readable via mongoose-aes-encryption', async () => {
    await SourceModel.create([{ name: 'Alice' }, { name: 'Bob' }]);

    await mongooseEncryptionToEncrypted({
        uri,
        collection: COLLECTION,
        fields: ['name'],
        key: TARGET_KEY,
        sourceKey: SOURCE_ENC_KEY,
    });

    const { conn, Model } = await getEncryptedMongooseModel(uri, COLLECTION, TARGET_KEY);
    const docs = await Model.find().sort({ _id: 1 });
    expect(docs.map((d) => d.name).sort()).toEqual(['Alice', 'Bob']);
    await conn.close();
});

test('_ct and _ac fields are removed after migration', async () => {
    await SourceModel.create([{ name: 'Alice' }]);

    await mongooseEncryptionToEncrypted({
        uri,
        collection: COLLECTION,
        fields: ['name'],
        key: TARGET_KEY,
        sourceKey: SOURCE_ENC_KEY,
    });

    const { client, collection } = await getNativeCollection(uri, COLLECTION);
    const doc = await collection.findOne({});
    expect(doc._ct).toBeUndefined();
    expect(doc._ac).toBeUndefined();
    await client.close();
});

test('is idempotent — second run skips already-migrated documents', async () => {
    await SourceModel.create([{ name: 'Alice' }, { name: 'Bob' }]);

    await mongooseEncryptionToEncrypted({
        uri,
        collection: COLLECTION,
        fields: ['name'],
        key: TARGET_KEY,
        sourceKey: SOURCE_ENC_KEY,
    });

    const result = await mongooseEncryptionToEncrypted({
        uri,
        collection: COLLECTION,
        fields: ['name'],
        key: TARGET_KEY,
        sourceKey: SOURCE_ENC_KEY,
    });

    // After a full migration, no documents have _ct remaining.
    // index.js detects this via the sample doc and returns early with zeros —
    // the collection is fully migrated, so there is nothing left to process.
    expect(result).toEqual({ migrated: 0, skipped: 0, errors: 0 });
});

test('dryRun does not modify documents', async () => {
    await SourceModel.create([{ name: 'Alice' }]);

    await mongooseEncryptionToEncrypted({
        uri,
        collection: COLLECTION,
        fields: ['name'],
        key: TARGET_KEY,
        sourceKey: SOURCE_ENC_KEY,
        dryRun: true,
    });

    // _ct should still be present — doc was not actually migrated
    const { client, collection } = await getNativeCollection(uri, COLLECTION);
    const doc = await collection.findOne({});
    expect(doc._ct).toBeDefined();
    await client.close();
});

test('plaintextFields — field is restored as plaintext, not re-encrypted', async () => {
    // Save a doc that has both 'name' (to re-encrypt) and 'role' (to restore as plaintext)
    // We need a schema that encrypts both fields
    const schema2 = new mongoose.Schema({ name: String, role: String }, { strict: false });
    schema2.plugin(mongooseEncryption, {
        encryptionKey: SOURCE_ENC_KEY,
        signingKey: SOURCE_SIG_KEY,
        encryptedFields: ['name', 'role'],
    });
    const MultiModel = sourceConn.model('multi_users', schema2, 'multi_users');
    await MultiModel.create({ name: 'Alice', role: 'admin' });

    await mongooseEncryptionToEncrypted({
        uri,
        collection: 'multi_users',
        fields: ['name'],
        plaintextFields: ['role'],
        key: TARGET_KEY,
        sourceKey: SOURCE_ENC_KEY,
    });

    const { client, collection } = await getNativeCollection(uri, 'multi_users');
    const doc = await collection.findOne({});
    // 'role' should be plaintext
    expect(doc.role).toBe('admin');
    // 'name' should be an AES ciphertext (pipe-delimited hex)
    expect(typeof doc.name).toBe('string');
    expect(doc.name).toMatch(/^[0-9a-f]+\|[0-9a-f]+\|[0-9a-f]+$/);
    await collection.drop();
    await client.close();
});

test('onProgress is called for each document including skipped', async () => {
    // Insert 2 docs with _ct, 1 already migrated (no _ct)
    await SourceModel.create([{ name: 'Alice' }, { name: 'Bob' }]);
    // Manually migrate one doc so it has no _ct
    await mongooseEncryptionToEncrypted({ uri, collection: COLLECTION, fields: ['name'], key: TARGET_KEY, sourceKey: SOURCE_ENC_KEY, dryRun: false });
    // Re-insert one unmigrated doc
    await SourceModel.create({ name: 'Carol' });

    const { client, collection } = await getNativeCollection(uri, COLLECTION);
    let progressCount = 0;
    await migrateFromMongooseEncryption({
        collection,
        fields: ['name'],
        key: TARGET_KEY,
        sourceKeyBase64: SOURCE_ENC_KEY,
        onProgress: () => { progressCount++; },
        onError: async (_id, err) => { throw err; },
    });
    // Alice and Bob are already migrated (skipped), Carol has _ct (migrated)
    expect(progressCount).toBe(3);
    await client.close();
});

test('wrong sourceKey length throws during migration', async () => {
    await SourceModel.create({ name: 'Alice' });
    const { client, collection } = await getNativeCollection(uri, COLLECTION);
    // A base64 string that decodes to the wrong number of bytes
    const badKey = Buffer.alloc(16, 0x01).toString('base64'); // 16 bytes, not 32
    await expect(
        migrateFromMongooseEncryption({
            collection,
            fields: ['name'],
            key: TARGET_KEY,
            sourceKeyBase64: badKey,
            onError: async (_id, err) => { throw err; },
        })
    ).rejects.toThrow('32-byte');
    await client.close();
});

test('null value inside _ct is set to null in migrated doc', async () => {
    // mongoose-encryption stores null field values inside _ct as JSON null
    const schema2 = new mongoose.Schema({ name: String }, { strict: false });
    schema2.plugin(mongooseEncryption, {
        encryptionKey: SOURCE_ENC_KEY,
        signingKey: SOURCE_SIG_KEY,
        encryptedFields: ['name'],
    });
    const NullModel = sourceConn.model('null_users', schema2, 'null_users');
    await NullModel.create({ name: null });

    await mongooseEncryptionToEncrypted({
        uri,
        collection: 'null_users',
        fields: ['name'],
        key: TARGET_KEY,
        sourceKey: SOURCE_ENC_KEY,
    });

    const { client, collection } = await getNativeCollection(uri, 'null_users');
    const doc = await collection.findOne({});
    expect(doc.name).toBeNull();
    expect(doc._ct).toBeUndefined();
    await collection.drop();
    await client.close();
});

test('onError returning skip counts error and continues', async () => {
    await SourceModel.create([{ name: 'Alice' }, { name: 'Bob' }]);

    const { client, collection } = await getNativeCollection(uri, COLLECTION);
    const mockCollection = {
        find: (...args) => collection.find(...args),
        updateOne: jest.fn().mockRejectedValueOnce(new Error('simulated write failure')),
    };

    const result = await migrateFromMongooseEncryption({
        collection: mockCollection,
        fields: ['name'],
        key: TARGET_KEY,
        sourceKeyBase64: SOURCE_ENC_KEY,
        onError: async () => 'skip',
    });

    // One error (skipped), one migrated successfully
    expect(result.errors).toBe(1);
    expect(result.migrated).toBe(1);
    await client.close();
});

test('onError returning abort rethrows and stops migration', async () => {
    await SourceModel.create([{ name: 'Alice' }, { name: 'Bob' }]);

    const { client, collection } = await getNativeCollection(uri, COLLECTION);
    const mockCollection = {
        find: (...args) => collection.find(...args),
        updateOne: jest.fn().mockRejectedValueOnce(new Error('simulated write failure')),
    };

    await expect(
        migrateFromMongooseEncryption({
            collection: mockCollection,
            fields: ['name'],
            key: TARGET_KEY,
            sourceKeyBase64: SOURCE_ENC_KEY,
            onError: async () => 'abort',
        })
    ).rejects.toThrow('simulated write failure');
    await client.close();
});
