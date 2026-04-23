'use strict';

const { MongoClient } = require('mongodb');
const { startDb, stopDb } = require('./helpers');
const { connect, countDocuments, sampleDocument } = require('../lib/mongo');

let mongoServer, uri;

beforeAll(async () => {
    ({ mongoServer, uri } = await startDb());
});

afterAll(async () => {
    await stopDb(mongoServer);
});

test('connect() throws when URI has no database name', async () => {
    // Strip the db name from the URI to get a bare host URI
    const bareUri = uri.replace(/\/testdb$/, '/');
    await expect(connect(bareUri, 'users')).rejects.toThrow(
        'could not determine database name from URI'
    );
});

test('connect() returns client and collection for valid URI', async () => {
    const { client, collection } = await connect(uri, 'users');
    expect(client).toBeDefined();
    expect(collection).toBeDefined();
    expect(collection.collectionName).toBe('users');
    await client.close();
});

test('countDocuments() returns 0 for empty collection', async () => {
    const client = new MongoClient(uri);
    await client.connect();
    const collection = client.db().collection('empty_col');
    const count = await countDocuments(collection);
    expect(count).toBe(0);
    await client.close();
});

test('countDocuments() returns correct count for non-empty collection', async () => {
    const client = new MongoClient(uri);
    await client.connect();
    const collection = client.db().collection('count_col');
    await collection.insertMany([{ x: 1 }, { x: 2 }, { x: 3 }]);
    const count = await countDocuments(collection);
    expect(count).toBe(3);
    await collection.drop();
    await client.close();
});

test('sampleDocument() returns null for empty collection', async () => {
    const client = new MongoClient(uri);
    await client.connect();
    const collection = client.db().collection('empty_sample');
    const doc = await sampleDocument(collection);
    expect(doc).toBeNull();
    await client.close();
});

test('sampleDocument() returns a document for non-empty collection', async () => {
    const client = new MongoClient(uri);
    await client.connect();
    const collection = client.db().collection('sample_col');
    await collection.insertOne({ name: 'test' });
    const doc = await sampleDocument(collection);
    expect(doc).not.toBeNull();
    expect(doc.name).toBe('test');
    await collection.drop();
    await client.close();
});
