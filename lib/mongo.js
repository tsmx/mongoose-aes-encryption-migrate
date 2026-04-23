'use strict';

const { MongoClient } = require('mongodb');

/**
 * Connect to MongoDB and return { client, db, collection }.
 * The caller is responsible for calling client.close().
 */
async function connect(uri, collectionName) {
    const client = new MongoClient(uri);
    await client.connect();
    const dbName = new URL(uri).pathname.replace(/^\//, '');
    if (!dbName) {
        throw new Error('mongoose-aes-encryption-migrate: could not determine database name from URI. Include the database name in the URI path (e.g. mongodb://host/mydb).');
    }
    const db = client.db(dbName);
    const collection = db.collection(collectionName);
    return { client, db, collection };
}

/**
 * Return the total number of documents in the collection.
 */
async function countDocuments(collection) {
    return collection.countDocuments();
}

/**
 * Return a single sample document (the first one found).
 */
async function sampleDocument(collection) {
    return collection.findOne({});
}

module.exports = { connect, countDocuments, sampleDocument };
