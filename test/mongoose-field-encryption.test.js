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
