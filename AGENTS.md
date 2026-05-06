# AGENTS.md

**Updated:** 2026-05-06 | **Commit:** 751e83e | **Branch:** master

## Overview

Plain CommonJS JavaScript Node.js library + CLI. No TypeScript, no build step. Migrates MongoDB collections to `mongoose-aes-encryption` format from three source modes: plaintext, `mongoose-encryption`, and `mongoose-field-encryption`.

## Structure

```
mongoose-aes-encryption-migrate/
├── index.js           ← programmatic API entry point
├── bin/migrate.js     ← CLI entry point (commander + inquirer)
├── lib/               ← migration logic (5 modules)
├── test/              ← Jest tests (7 files, 58 tests)
└── scripts/           ← local dev helpers (not published)
```

## Where to Look

| Task | Location |
|------|----------|
| Add/change CLI flag | `bin/migrate.js` (commander option + pass-through to index.js) |
| Add/change migration logic | `lib/plaintext.js`, `lib/mongoose-encryption.js`, or `lib/mongoose-field-encryption.js` |
| Change encryption detection | `lib/detect.js` → `isAlreadyEncrypted()` |
| Change MongoDB connection | `lib/mongo.js` → `connect()` |
| Add programmatic API function | `index.js` (add fn + export) |
| Shared test setup/keys | `test/helpers.js` |
| Local DB seeding | `scripts/seed.js` |

## Code Map

| Symbol | File | Role |
|--------|------|------|
| `plaintextToEncrypted` | `index.js` | API: plaintext → encrypted |
| `mongooseEncryptionToEncrypted` | `index.js` | API: mongoose-encryption → encrypted |
| `mongooseFieldEncryptionToEncrypted` | `index.js` | API: mongoose-field-encryption → encrypted |
| `isAlreadyEncrypted(value, key)` | `lib/detect.js` | Skip-check heuristic (decrypt probe) |
| `connect(uri, collectionName)` | `lib/mongo.js` | Native driver connect → `{ client, collection }` |
| `sampleDocument(collection)` | `lib/mongo.js` | First-doc sample for preflight |
| `migratePlaintext` | `lib/plaintext.js` | Core batch loop for plaintext mode |
| `migrateFromMongooseEncryption` | `lib/mongoose-encryption.js` | Decrypt `_ct`, re-encrypt per-field |
| `migrateFromMongooseFieldEncryption` | `lib/mongoose-field-encryption.js` | Decrypt `<salt>:<ct>` fields, re-encrypt |

## Key Dependencies

| Package | Role |
|---------|------|
| `mongodb` ^6 | Native driver (NOT Mongoose) for all DB ops |
| `mongoose-aes-encryption` | Target encrypt/decrypt wire format |
| `commander` | CLI option parsing |
| `inquirer` | Interactive confirmation + error prompts |
| `cli-progress` | Progress bar during migration |

## Commands

```bash
npm test                # jest --testEnvironment node
npm run test-coverage   # jest --testEnvironment node --coverage
```

No `build`, `lint`, `format`, or `typecheck` scripts exist — don't add them unless explicitly requested.

Run a single test file or pattern:
```bash
npx jest --testEnvironment node path/to/test.js
npx jest --testEnvironment node -t "test name pattern"
```

Always pass `--testEnvironment node` when invoking Jest directly.

## Package structure

- Programmatic API exports: `plaintextToEncrypted`, `mongooseEncryptionToEncrypted`, `mongooseFieldEncryptionToEncrypted` — all return `Promise<{ migrated, skipped, errors }>`.
- CLI binary name matches the package name. Users invoke it with `npx mongoose-aes-encryption-migrate [options]`.
- `scripts/` is excluded from npm publish (`.npmignore`) but tracked in git.
- Published files: `index.js`, `bin/`, `lib/` only (`test/`, `scripts/` excluded).

## Testing

- Tests use `mongodb-memory-server` — no real MongoDB needed.
- Shared setup lives in `test/helpers.js`: `startDb()`, `stopDb()`, `getNativeCollection()`, `getEncryptedMongooseModel()`, and hardcoded test keys (`TARGET_KEY`, `SOURCE_ENC_KEY`, `SOURCE_SIG_KEY`, `SOURCE_SECRET`).
- CI runs Node 20, 22, 24 in parallel (`.github/workflows/git-build.yml`) and reports coverage to Coveralls.

## Critical quirks

- **Native `mongodb` driver, not Mongoose.** `lib/mongo.js` uses the MongoDB native driver directly. The source plugins (`mongoose-encryption`, `mongoose-field-encryption`) are devDependencies used only in tests — the migration lib re-implements their decryption using raw `crypto`.
- **`--fields` CLI flag is comma-separated; programmatic API takes `string[]`.** Don't pass a comma string to the API.
- **Programmatic `onError` always throws; CLI `onError` prompts interactively.** Test the library path for unit tests.
- **Double-encryption risk.** If `isAlreadyEncrypted()` is called with the wrong key, an already-encrypted field will be treated as plaintext and re-encrypted. Key must be consistent across runs.
- **`mongoose-encryption` requires chunked `.save()` not `insertMany()` in seed.** `insertMany` bypasses `pre('save')` middleware which is the only hook `mongoose-encryption` registers — documents land unencrypted. `mongoose-field-encryption` is fine with `insertMany` (has a `pre('insertMany')` hook).
- **`mongoose-aes-encryption` plugin is a factory.** Call it as `schema.plugin(AesEncryption({ key, fields }))` — not `schema.plugin(AesEncryption, { ... })`.
- **Non-string fields from `mongoose-field-encryption`** (numbers, booleans, dates) are stored as JSON strings after migration. Mongoose auto-casts on read if the schema type is correct; raw driver access requires manual casting.
- **No dotenv/config file support.** Keys and secrets are passed via CLI flags or programmatic options only.
- **Node >=18 required.**
