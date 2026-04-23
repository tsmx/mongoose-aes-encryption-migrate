'use strict';

const mongoose = require('mongoose');
const { fieldEncryption } = require('mongoose-field-encryption');
const {
    TARGET_KEY,
    SOURCE_SECRET,
    startDb,
    stopDb,
    getNativeCollection,
    getEncryptedMongooseModel,
} = require('./helpers');
const { mongooseFieldEncryptionToEncrypted } = require('../index');
const { migrateFromMongooseFieldEncryption, decryptMfeField, deriveKey } = require('../lib/mongoose-field-encryption');

const COLLECTION = 'users';

let mongoServer, uri;
let sourceConn, SourceModel;

beforeAll(async () => {
    ({ mongoServer, uri } = await startDb());

    // Mongoose model with mongoose-field-encryption plugin for inserting source docs
    sourceConn = await mongoose.createConnection(uri).asPromise();
    const schema = new mongoose.Schema({ name: String }, { strict: false });
    schema.plugin(fieldEncryption, {
        fields: ['name'],
        secret: SOURCE_SECRET,
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

test('migrates all mongoose-field-encryption documents', async () => {
    await SourceModel.create([{ name: 'Alice' }, { name: 'Bob' }, { name: 'Carol' }]);

    const result = await mongooseFieldEncryptionToEncrypted({
        uri,
        collection: COLLECTION,
        fields: ['name'],
        secret: SOURCE_SECRET,
        key: TARGET_KEY,
    });

    expect(result).toEqual({ migrated: 3, skipped: 0, errors: 0 });
});

test('migrated values are readable via mongoose-aes-encryption', async () => {
    await SourceModel.create([{ name: 'Alice' }, { name: 'Bob' }]);

    await mongooseFieldEncryptionToEncrypted({
        uri,
        collection: COLLECTION,
        fields: ['name'],
        secret: SOURCE_SECRET,
        key: TARGET_KEY,
    });

    const { conn, Model } = await getEncryptedMongooseModel(uri, COLLECTION, TARGET_KEY);
    const docs = await Model.find().sort({ _id: 1 });
    expect(docs.map((d) => d.name).sort()).toEqual(['Alice', 'Bob']);
    await conn.close();
});

test('__enc_* marker fields are removed after migration', async () => {
    await SourceModel.create([{ name: 'Alice' }]);

    await mongooseFieldEncryptionToEncrypted({
        uri,
        collection: COLLECTION,
        fields: ['name'],
        secret: SOURCE_SECRET,
        key: TARGET_KEY,
    });

    const { client, collection } = await getNativeCollection(uri, COLLECTION);
    const doc = await collection.findOne({});
    expect(doc.__enc_name).toBeUndefined();
    await client.close();
});

test('is idempotent — second run skips already-migrated documents', async () => {
    await SourceModel.create([{ name: 'Alice' }, { name: 'Bob' }]);

    await mongooseFieldEncryptionToEncrypted({
        uri,
        collection: COLLECTION,
        fields: ['name'],
        secret: SOURCE_SECRET,
        key: TARGET_KEY,
    });

    const result = await mongooseFieldEncryptionToEncrypted({
        uri,
        collection: COLLECTION,
        fields: ['name'],
        secret: SOURCE_SECRET,
        key: TARGET_KEY,
    });

    expect(result).toEqual({ migrated: 0, skipped: 2, errors: 0 });
});

test('dryRun does not modify documents', async () => {
    await SourceModel.create([{ name: 'Alice' }]);

    await mongooseFieldEncryptionToEncrypted({
        uri,
        collection: COLLECTION,
        fields: ['name'],
        secret: SOURCE_SECRET,
        key: TARGET_KEY,
        dryRun: true,
    });

    // __enc_name should still be present — doc was not actually migrated
    const { client, collection } = await getNativeCollection(uri, COLLECTION);
    const doc = await collection.findOne({});
    expect(doc.__enc_name).toBe(true);
    await client.close();
});

test('decryptMfeField throws on malformed value (missing colon separator)', () => {
    const derivedKey = deriveKey(SOURCE_SECRET);
    expect(() => decryptMfeField('notvalidformat', derivedKey)).toThrow(
        'unexpected mongoose-field-encryption value format'
    );
});

test('onProgress is called for each document including skipped', async () => {
    await SourceModel.create([{ name: 'Alice' }, { name: 'Bob' }]);
    // Migrate so Alice and Bob have no __enc_name (skipped on next run)
    await mongooseFieldEncryptionToEncrypted({ uri, collection: COLLECTION, fields: ['name'], secret: SOURCE_SECRET, key: TARGET_KEY });
    // Insert a new unmigrated doc
    await SourceModel.create({ name: 'Carol' });

    const { client, collection } = await getNativeCollection(uri, COLLECTION);
    let progressCount = 0;
    await migrateFromMongooseFieldEncryption({
        collection,
        fields: ['name'],
        secret: SOURCE_SECRET,
        key: TARGET_KEY,
        onProgress: () => { progressCount++; },
        onError: async (_id, err) => { throw err; },
    });
    // Alice and Bob skipped, Carol migrated
    expect(progressCount).toBe(3);
    await client.close();
});

test('marker true but field value absent — field set to null in migrated doc', async () => {
    // Insert a raw doc where __enc_name is true but 'name' is absent
    const { client, collection } = await getNativeCollection(uri, COLLECTION);
    await collection.insertOne({ __enc_name: true });

    await mongooseFieldEncryptionToEncrypted({
        uri,
        collection: COLLECTION,
        fields: ['name'],
        secret: SOURCE_SECRET,
        key: TARGET_KEY,
    });

    const doc = await collection.findOne({ __enc_name: { $exists: false } });
    expect(doc.name).toBeNull();
    expect(doc.__enc_name).toBeUndefined();
    await client.close();
});

test('non-string field stored in __enc_<field>_d is migrated correctly', async () => {
    // Use a schema with a Number field so mongoose-field-encryption uses the _d path
    const schema2 = new mongoose.Schema({ score: Number }, { strict: false });
    schema2.plugin(fieldEncryption, { fields: ['score'], secret: SOURCE_SECRET });
    const NumModel = sourceConn.model('num_users', schema2, 'num_users');
    await NumModel.create({ score: 42 });

    await mongooseFieldEncryptionToEncrypted({
        uri,
        collection: 'num_users',
        fields: ['score'],
        secret: SOURCE_SECRET,
        key: TARGET_KEY,
    });

    const { client, collection } = await getNativeCollection(uri, 'num_users');
    const doc = await collection.findOne({});
    // __enc_score and __enc_score_d should be removed
    expect(doc.__enc_score).toBeUndefined();
    expect(doc.__enc_score_d).toBeUndefined();
    // score should now be an AES ciphertext
    expect(typeof doc.score).toBe('string');
    expect(doc.score).toMatch(/^[0-9a-f]+\|[0-9a-f]+\|[0-9a-f]+$/);
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

    const result = await migrateFromMongooseFieldEncryption({
        collection: mockCollection,
        fields: ['name'],
        secret: SOURCE_SECRET,
        key: TARGET_KEY,
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
        migrateFromMongooseFieldEncryption({
            collection: mockCollection,
            fields: ['name'],
            secret: SOURCE_SECRET,
            key: TARGET_KEY,
            onError: async () => 'abort',
        })
    ).rejects.toThrow('simulated write failure');
    await client.close();
});
