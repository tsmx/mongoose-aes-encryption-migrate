#!/usr/bin/env node
'use strict';

const { program } = require('commander');
const cliProgress = require('cli-progress');
const inquirer = require('inquirer');
const prompt = inquirer.createPromptModule();

const { connect, countDocuments, sampleDocument } = require('../lib/mongo');
const { migratePlaintext, preflight: plaintextPreflight } = require('../lib/plaintext');
const { migrateFromMongooseEncryption, preflight: mePreflight } = require('../lib/mongoose-encryption');
const { migrateFromMongooseFieldEncryption, preflight: mfePreflight } = require('../lib/mongoose-field-encryption');

// ─── helpers ────────────────────────────────────────────────────────────────

function parseList(val) {
    return val.split(',').map((s) => s.trim()).filter(Boolean);
}

function fatal(msg) {
    console.error(`\nError: ${msg}`);
    process.exit(1);
}

function printSummary(result, dryRun) {
    const tag = dryRun ? ' (dry-run — no writes made)' : '';
    console.log(`\nDone.${tag}`);
    console.log(`  Migrated : ${result.migrated}`);
    console.log(`  Skipped  : ${result.skipped}`);
    console.log(`  Errors   : ${result.errors}`);
}

// ─── CLI definition ─────────────────────────────────────────────────────────

program
    .name('mongoose-aes-encryption-migrate')
    .description('Migrate existing MongoDB collections for use with mongoose-aes-encryption')
    .requiredOption('--uri <uri>', 'MongoDB connection string including database name (e.g. mongodb://localhost:27017/mydb)')
    .requiredOption('--collection <name>', 'Collection to migrate')
    .requiredOption('--mode <mode>', 'Migration mode: plaintext | mongoose-encryption | mongoose-field-encryption')
    .requiredOption('--key <hex>', '64-character hex target encryption key')
    .requiredOption('--fields <fields>', 'Comma-separated list of field paths to encrypt/migrate')
    .option('--plaintext-fields <fields>', 'Comma-separated fields from _ct to restore as plaintext (mongoose-encryption mode only)', '')
    .option('--source-key <base64>', 'base64 encryptionKey used with mongoose-encryption (mongoose-encryption mode only)')
    .option('--secret <string>', 'Secret string used with mongoose-field-encryption (mongoose-field-encryption mode only)')
    .option('--algorithm <algo>', 'Target algorithm: aes-256-gcm (default) | aes-256-cbc', 'aes-256-gcm')
    .option('--batch-size <n>', 'Documents per batch', (v) => parseInt(v, 10), 100)
    .option('--dry-run', 'Probe and report without writing any changes', false);

program.parse(process.argv);
const opts = program.opts();

// ─── main ────────────────────────────────────────────────────────────────────

(async () => {
    const mode = opts.mode;
    if (mode !== 'plaintext' && mode !== 'mongoose-encryption' && mode !== 'mongoose-field-encryption') {
        fatal(`Unknown mode "${mode}". Must be "plaintext", "mongoose-encryption", or "mongoose-field-encryption".`);
    }

    const fields = parseList(opts.fields);
    if (fields.length === 0) fatal('--fields must list at least one field.');

    const plaintextFields = opts.plaintextFields ? parseList(opts.plaintextFields) : [];

    if (mode === 'mongoose-encryption' && !opts.sourceKey) {
        fatal('--source-key is required for mode "mongoose-encryption".');
    }

    if (mode === 'mongoose-field-encryption' && !opts.secret) {
        fatal('--secret is required for mode "mongoose-field-encryption".');
    }

    // ── connect ──────────────────────────────────────────────────────────────
    console.log(`\nConnecting to ${opts.uri} ...`);
    let client, collection;
    try {
        ({ client, collection } = await connect(opts.uri, opts.collection));
    } catch (err) {
        fatal(`Could not connect to MongoDB: ${err.message}`);
    }

    try {
        const total = await countDocuments(collection);
        const sample = await sampleDocument(collection);

        console.log(`Collection "${opts.collection}": ${total} document(s) found.`);

        // ── mode-specific preflight ───────────────────────────────────────────
        if (mode === 'plaintext') {
            const missing = plaintextPreflight(sample, fields);
            if (missing.length > 0) {
                fatal(
                    `The following fields were not found in the sample document: ${missing.join(', ')}.\n` +
                    'Check your --fields argument.'
                );
            }
            console.log(`\nPre-flight OK. Fields to encrypt: ${fields.join(', ')}`);

        } else if (mode === 'mongoose-encryption') {
            // mongoose-encryption mode
            let discoveredFields, unaccountedFields;
            try {
                ({ discoveredFields, unaccountedFields } = mePreflight(sample, fields, plaintextFields, opts.sourceKey));
            } catch (err) {
                fatal(`Pre-flight failed: ${err.message}`);
            }

            if (!sample || !sample._ct) {
                console.log('\nNo documents with _ct found. Nothing to migrate.');
                await client.close();
                return;
            }

            if (unaccountedFields.length > 0) {
                console.error('\nPre-flight FAILED.');
                console.error(`The following fields were found inside _ct but are not accounted for:\n  ${unaccountedFields.join(', ')}\n`);
                console.error('Decide what to do with each field:');
                console.error(`  --fields ${[...fields, ...unaccountedFields].join(',')}               (re-encrypt them with the new plugin)`);
                console.error(`  --plaintext-fields ${[...plaintextFields, ...unaccountedFields].join(',')}   (restore them as unencrypted plaintext)\n`);
                await client.close();
                process.exit(1);
            }

            console.log('\nPre-flight OK. Fields found in _ct:');
            for (const f of discoveredFields) {
                const tag = fields.includes(f) ? '→ re-encrypt' : '→ restore as plaintext';
                console.log(`  ${f}  ${tag}`);
            }

        } else {
            // mongoose-field-encryption mode
            const missing = mfePreflight(sample, fields);
            if (missing.length > 0) {
                fatal(
                    `The following fields were not found in the sample document: ${missing.join(', ')}.\n` +
                    'Check your --fields argument.'
                );
            }
            console.log(`\nPre-flight OK. Fields to migrate: ${fields.join(', ')}`);
        }

        // ── confirmation ─────────────────────────────────────────────────────
        if (!opts.dryRun) {
            const { confirmed } = await prompt([{
                type: 'confirm',
                name: 'confirmed',
                message: `Proceed with migration${total > 0 ? ` of ${total} document(s)` : ''}? This will modify the database.`,
                default: false
            }]);
            if (!confirmed) {
                console.log('Aborted.');
                await client.close();
                return;
            }
        } else {
            console.log('\nDry-run mode — no writes will be made.');
        }

        // ── progress bar ──────────────────────────────────────────────────────
        const bar = new cliProgress.SingleBar({
            format: ' {bar} {percentage}% | {value}/{total} docs | skipped: {skipped} | errors: {errors} | ETA: {eta}s',
            barCompleteChar: '\u2588',
            barIncompleteChar: '\u2591',
            hideCursor: true
        });

        bar.start(total || 1, 0, { skipped: 0, errors: 0 });
        let runningSkipped = 0;
        let runningErrors = 0;

        const onProgress = () => {
            bar.increment(1, { skipped: runningSkipped, errors: runningErrors });
        };

        // Interactive error handler — pauses the progress bar and asks the user.
        const onError = async (docId, err) => {
            bar.stop();
            console.error(`\n  Error processing document _id=${docId}: ${err.message}`);
            const { action } = await prompt([{
                type: 'list',
                name: 'action',
                message: 'What do you want to do?',
                choices: [
                    { value: 'skip', name: 'Skip this document and continue' },
                    { value: 'abort', name: 'Abort the migration' }
                ]
            }]);
            if (action === 'skip') {
                runningErrors++;
                bar.start(total || 1, bar.value, { skipped: runningSkipped, errors: runningErrors });
                return 'skip';
            }
            return 'abort';
        };

        // ── run migration ─────────────────────────────────────────────────────
        let result;
        try {
            if (mode === 'plaintext') {
                result = await migratePlaintext({
                    collection,
                    fields,
                    key: opts.key,
                    algorithm: opts.algorithm,
                    batchSize: opts.batchSize,
                    dryRun: opts.dryRun,
                    onProgress,
                    onError
                });
            } else if (mode === 'mongoose-encryption') {
                result = await migrateFromMongooseEncryption({
                    collection,
                    fields,
                    plaintextFields,
                    key: opts.key,
                    sourceKeyBase64: opts.sourceKey,
                    algorithm: opts.algorithm,
                    batchSize: opts.batchSize,
                    dryRun: opts.dryRun,
                    onProgress,
                    onError
                });
            } else {
                result = await migrateFromMongooseFieldEncryption({
                    collection,
                    fields,
                    secret: opts.secret,
                    key: opts.key,
                    algorithm: opts.algorithm,
                    batchSize: opts.batchSize,
                    dryRun: opts.dryRun,
                    onProgress,
                    onError
                });
            }
        } catch (err) {
            bar.stop();
            fatal(`Migration aborted: ${err.message}`);
        }

        runningSkipped = result.skipped;
        runningErrors = result.errors;
        bar.update(total || 1, { skipped: runningSkipped, errors: runningErrors });
        bar.stop();

        printSummary(result, opts.dryRun);

    } finally {
        await client.close();
    }
})();
