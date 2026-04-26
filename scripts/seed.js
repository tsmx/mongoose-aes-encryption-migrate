#!/usr/bin/env node
'use strict';

/**
 * seed.js — populate local MongoDB with three test collections for manual
 * migration testing.
 *
 * Collections created in database "encryptiontest" on localhost:27017:
 *   mg-field-enc-test   — encrypted with mongoose-field-encryption
 *   mg-enc-test         — encrypted with mongoose-encryption
 *   mg-plaintext-test   — plain unencrypted documents
 *
 * Run: node scripts/seed.js
 * Requires: devDependencies installed (mongoose, mongoose-encryption,
 *           mongoose-field-encryption)
 */

const mongoose = require('mongoose');
const { fieldEncryption } = require('mongoose-field-encryption');
const mongooseEncryption = require('mongoose-encryption');

// ─── Hardcoded keys ──────────────────────────────────────────────────────────

// mongoose-field-encryption: arbitrary secret string (plugin derives AES key
// internally via SHA-256)
const MFE_SECRET = 'mfe-secret-seed-key-32bytes!!!!!';

// mongoose-encryption: 32-byte AES-256 key + 64-byte HMAC-SHA-512 signing key
const ME_ENCRYPTION_KEY = Buffer.from(
    '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
    'hex'
); // 32 bytes
const ME_SIGNING_KEY = Buffer.from(
    'b0f3b28bf8b0b4b2b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcc' +
    'cdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebec',
    'hex'
); // 64 bytes

const MONGO_URI = 'mongodb://localhost:27017/encryptiontest';
const NUM_DOCS = 1000;

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeDocs(n) {
    const docs = [];
    for (let i = 1; i <= n; i++) {
        docs.push({
            firstName: `User${i}`,
            lastName: `Last${i}`,
            email: `user${i}@example.com`,
            age: (i % 80) + 18
        });
    }
    return docs;
}

async function dropCollection(db, name) {
    try {
        await db.dropCollection(name);
    } catch (err) {
        // ns not found — collection didn't exist yet, that's fine
        if (!err.message.includes('ns not found') && err.codeName !== 'NamespaceNotFound') {
            throw err;
        }
    }
}

// ─── Phase 1: mongoose-field-encryption ──────────────────────────────────────

async function seedFieldEncryption() {
    console.log('=== Phase 1: mongoose-field-encryption → mg-field-enc-test ===');
    console.log(`Secret (--secret): ${MFE_SECRET}`);

    const conn = await mongoose.createConnection(MONGO_URI).asPromise();

    await dropCollection(conn.db, 'mg-field-enc-test');

    const schema = new mongoose.Schema({
        firstName: String,
        lastName: String,
        email: String,
        age: Number
    });

    schema.plugin(fieldEncryption, {
        fields: ['firstName', 'lastName', 'email', 'age'],
        secret: MFE_SECRET,
        saltGenerator: (secret) => secret.substring(0, 16)
    });

    const Model = conn.model('MgFieldEncTest', schema, 'mg-field-enc-test');

    const docs = makeDocs(NUM_DOCS);
    await Model.insertMany(docs);

    console.log(`Inserted ${NUM_DOCS} documents.\n`);
    await conn.close();
}

// ─── Phase 2: mongoose-encryption ────────────────────────────────────────────

async function seedMongooseEncryption() {
    console.log('=== Phase 2: mongoose-encryption → mg-enc-test ===');
    console.log(`Encryption key (--source-key, base64): ${ME_ENCRYPTION_KEY.toString('base64')}`);
    console.log(`Signing key (base64):                  ${ME_SIGNING_KEY.toString('base64')}`);

    const conn = await mongoose.createConnection(MONGO_URI).asPromise();

    await dropCollection(conn.db, 'mg-enc-test');

    const schema = new mongoose.Schema({
        firstName: String,
        lastName: String,
        email: String,
        age: Number
    });

    schema.plugin(mongooseEncryption, {
        encryptionKey: ME_ENCRYPTION_KEY,
        signingKey: ME_SIGNING_KEY,
        encryptedFields: ['firstName', 'lastName', 'email', 'age']
    });

    const Model = conn.model('MgEncTest', schema, 'mg-enc-test');

    const docs = makeDocs(NUM_DOCS);

    // mongoose-encryption only hooks pre('save'), not pre('insertMany').
    // Use chunked parallel saves to trigger encryption middleware correctly.
    const CHUNK = 50;
    for (let i = 0; i < docs.length; i += CHUNK) {
        await Promise.all(docs.slice(i, i + CHUNK).map((d) => new Model(d).save()));
    }

    console.log(`Inserted ${NUM_DOCS} documents.\n`);
    await conn.close();
}

// ─── Phase 3: plaintext ───────────────────────────────────────────────────────

async function seedPlaintext() {
    console.log('=== Phase 3: plaintext → mg-plaintext-test ===');

    const conn = await mongoose.createConnection(MONGO_URI).asPromise();

    await dropCollection(conn.db, 'mg-plaintext-test');

    const schema = new mongoose.Schema({
        firstName: String,
        lastName: String,
        email: String,
        age: Number
    });

    const Model = conn.model('MgPlaintextTest', schema, 'mg-plaintext-test');

    const docs = makeDocs(NUM_DOCS);
    await Model.insertMany(docs);

    console.log(`Inserted ${NUM_DOCS} documents.\n`);
    await conn.close();
}

// ─── Main ─────────────────────────────────────────────────────────────────────

(async () => {
    try {
        await seedFieldEncryption();
        await seedMongooseEncryption();
        await seedPlaintext();
        console.log('All collections seeded successfully.');
    } catch (err) {
        console.error('Seed failed:', err.message);
        process.exit(1);
    }
})();
