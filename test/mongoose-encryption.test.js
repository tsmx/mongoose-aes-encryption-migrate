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
