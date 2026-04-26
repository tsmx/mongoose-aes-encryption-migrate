#!/usr/bin/env node
'use strict';

/**
 * verify.js — read all three migrated test collections using Mongoose +
 * mongoose-aes-encryption and print a summary per collection.
 *
 * Run AFTER migrating the collections created by seed.js:
 *   node scripts/verify.js --key <64-char-hex>
 *
 * The --key value must match the --key passed to the migration tool.
 */

const mongoose = require('mongoose');
const AesEncryption = require('mongoose-aes-encryption');

// ─── CLI arg parsing ──────────────────────────────────────────────────────────

const args = process.argv.slice(2);
const keyFlagIndex = args.indexOf('--key');
if (keyFlagIndex === -1 || !args[keyFlagIndex + 1]) {
    console.error('Error: --key <64-char-hex> is required.');
    console.error('  Example: node scripts/verify.js --key 603deb10...');
    process.exit(1);
}
const KEY_HEX = args[keyFlagIndex + 1];
if (!/^[0-9a-fA-F]{64}$/.test(KEY_HEX)) {
    console.error('Error: --key must be exactly 64 hexadecimal characters (32 bytes).');
    process.exit(1);
}

const MONGO_URI = 'mongodb://localhost:27017/encryptiontest';
const ENCRYPTED_FIELDS = ['firstName', 'lastName', 'email', 'age'];
const PREVIEW_COUNT = 5;

const COLLECTIONS = [
    'mg-field-enc-test',
    'mg-enc-test',
    'mg-plaintext-test'
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function buildModel(conn, collectionName) {
    const schema = new mongoose.Schema({
        firstName: String,
        lastName: String,
        email: String,
        age: Number
    });

    schema.plugin(AesEncryption({
        fields: ENCRYPTED_FIELDS,
        key: KEY_HEX
    }));

    // Model names must be unique per connection — use the collection name
    return conn.model(collectionName, schema, collectionName);
}

function formatDoc(doc, index) {
    return `  #${index + 1} { firstName: '${doc.firstName}', lastName: '${doc.lastName}', email: '${doc.email}', age: ${doc.age} }`;
}

// ─── Per-collection verification ─────────────────────────────────────────────

async function verifyCollection(collectionName) {
    console.log(`=== ${collectionName} ===`);

    const conn = await mongoose.createConnection(MONGO_URI).asPromise();

    try {
        const Model = buildModel(conn, collectionName);

        const total = await Model.countDocuments();
        console.log(`Total documents: ${total}`);

        if (total === 0) {
            console.log('  (no documents found — collection is empty or does not exist)\n');
            return;
        }

        const docs = await Model.find({}).limit(PREVIEW_COUNT).lean();
        console.log(`First ${Math.min(PREVIEW_COUNT, total)}:`);
        docs.forEach((doc, i) => console.log(formatDoc(doc, i)));
        console.log();
    } finally {
        await conn.close();
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

(async () => {
    console.log(`Using key: ${KEY_HEX}\n`);
    try {
        for (const col of COLLECTIONS) {
            await verifyCollection(col);
        }
        console.log('Verification complete.');
    } catch (err) {
        console.error('Verification failed:', err.message);
        process.exit(1);
    }
})();
