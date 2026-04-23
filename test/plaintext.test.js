'use strict';

const mongoose = require('mongoose');
const {
    TARGET_KEY,
    startDb,
    stopDb,
    getNativeCollection,
    getEncryptedMongooseModel,
} = require('./helpers');
const { plaintextToEncrypted } = require('../index');

const COLLECTION = 'users';

let mongoServer, uri;
let sourceConn, SourceModel;
let nativeClient;

beforeAll(async () => {
    ({ mongoServer, uri } = await startDb());

    // Plain Mongoose model — no encryption plugin — for inserting source docs
    sourceConn = await mongoose.createConnection(uri).asPromise();
    const schema = new mongoose.Schema({ name: String }, { strict: false });
    SourceModel = sourceConn.model(COLLECTION, schema, COLLECTION);
});

afterAll(async () => {
    await sourceConn.close();
    if (nativeClient) await nativeClient.close();
    await stopDb(mongoServer);
});

afterEach(async () => {
    await SourceModel.deleteMany({});
});

test('migrates all plaintext documents', async () => {
    await SourceModel.create([{ name: 'Alice' }, { name: 'Bob' }, { name: 'Carol' }]);

    const result = await plaintextToEncrypted({ uri, collection: COLLECTION, fields: ['name'], key: TARGET_KEY });

    expect(result).toEqual({ migrated: 3, skipped: 0, errors: 0 });
});

test('migrated values are readable via mongoose-aes-encryption', async () => {
    await SourceModel.create([{ name: 'Alice' }, { name: 'Bob' }]);
    await plaintextToEncrypted({ uri, collection: COLLECTION, fields: ['name'], key: TARGET_KEY });

    const { conn, Model } = await getEncryptedMongooseModel(uri, COLLECTION, TARGET_KEY);
    const docs = await Model.find().sort({ _id: 1 });
    expect(docs.map((d) => d.name).sort()).toEqual(['Alice', 'Bob']);
    await conn.close();
});

test('is idempotent — second run skips already-encrypted documents', async () => {
    await SourceModel.create([{ name: 'Alice' }, { name: 'Bob' }]);
    await plaintextToEncrypted({ uri, collection: COLLECTION, fields: ['name'], key: TARGET_KEY });

    const result = await plaintextToEncrypted({ uri, collection: COLLECTION, fields: ['name'], key: TARGET_KEY });

    expect(result).toEqual({ migrated: 0, skipped: 2, errors: 0 });
});

test('dryRun does not modify documents', async () => {
    await SourceModel.create([{ name: 'Alice' }]);
    await plaintextToEncrypted({ uri, collection: COLLECTION, fields: ['name'], key: TARGET_KEY, dryRun: true });

    // Value should still be plaintext
    const doc = await SourceModel.findOne();
    expect(doc.name).toBe('Alice');
});

test('handles documents with null field gracefully', async () => {
    await SourceModel.create([{ name: null }, { name: 'Bob' }]);

    const result = await plaintextToEncrypted({ uri, collection: COLLECTION, fields: ['name'], key: TARGET_KEY });

    // null is skipped (not encrypted), Bob is migrated
    expect(result.errors).toBe(0);
    expect(result.migrated + result.skipped).toBe(2);
});
