'use strict';

const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');
const { MongoClient } = require('mongodb');
const createAESPlugin = require('mongoose-aes-encryption');

// Fixed 64-char hex key used as the migration target key across all test suites
const TARGET_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

// Fixed source keys for mongoose-encryption (base64-encoded 32-byte and 64-byte keys)
const SOURCE_ENC_KEY = Buffer.alloc(32, 0x01).toString('base64');
const SOURCE_SIG_KEY = Buffer.alloc(64, 0x02).toString('base64');

// Fixed secret string for mongoose-field-encryption
const SOURCE_SECRET = 'test-secret-for-mfe';

/**
 * Start an in-memory MongoDB instance.
 * @returns {Promise<{ mongoServer: MongoMemoryServer, uri: string }>}
 */
async function startDb() {
    const mongoServer = await MongoMemoryServer.create();
    const uri = mongoServer.getUri('testdb');
    return { mongoServer, uri };
}

/**
 * Stop the in-memory MongoDB instance.
 * @param {MongoMemoryServer} mongoServer
 */
async function stopDb(mongoServer) {
    await mongoServer.stop();
}

/**
 * Get a native MongoDB collection.
 * @param {string} uri
 * @param {string} collectionName
 * @returns {Promise<{ client: MongoClient, collection: import('mongodb').Collection }>}
 */
async function getNativeCollection(uri, collectionName) {
    const client = new MongoClient(uri);
    await client.connect();
    const db = client.db();
    const collection = db.collection(collectionName);
    return { client, collection };
}

/**
 * Create a Mongoose connection + model that reads fields via mongoose-aes-encryption.
 * Used to verify migrated documents.
 *
 * @param {string} uri
 * @param {string} collectionName
 * @param {string} key  64-char hex target key
 * @returns {Promise<{ conn: mongoose.Connection, Model: mongoose.Model }>}
 */
async function getEncryptedMongooseModel(uri, collectionName, key) {
    const conn = await mongoose.createConnection(uri).asPromise();
    const schema = new mongoose.Schema({ name: { type: String, encrypted: true } }, { strict: false });
    schema.plugin(createAESPlugin({ key }));
    const Model = conn.model(collectionName, schema, collectionName);
    return { conn, Model };
}

module.exports = {
    TARGET_KEY,
    SOURCE_ENC_KEY,
    SOURCE_SIG_KEY,
    SOURCE_SECRET,
    startDb,
    stopDb,
    getNativeCollection,
    getEncryptedMongooseModel,
};
