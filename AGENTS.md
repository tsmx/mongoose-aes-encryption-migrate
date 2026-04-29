# AGENTS.md

## Overview

Plain CommonJS JavaScript Node.js library + CLI. No TypeScript, no build step. Migrates MongoDB collections to `mongoose-aes-encryption` format from three source modes: plaintext, `mongoose-encryption`, and `mongoose-field-encryption`.

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

```
index.js           ← programmatic API ("main")
bin/migrate.js     ← CLI binary ("mongoose-aes-encryption-migrate")
lib/
  detect.js                        ← isAlreadyEncrypted() heuristic
  mongo.js                         ← connect/count/sample via native mongodb driver
  plaintext.js
  mongoose-encryption.js
  mongoose-field-encryption.js
test/
  helpers.js                       ← shared startDb/stopDb (mongodb-memory-server), keys, model factories
  *.test.js                        ← 58 tests across 6 suites, all using in-memory MongoDB
scripts/
  seed.js                          ← populates local encryptiontest DB with 1000-doc test collections
  verify.js                        ← reads migrated collections via mongoose-aes-encryption
  migrate-local.sh                 ← generates a key with openssl and runs npx migration against local DB
```

- Programmatic API exports: `plaintextToEncrypted`, `mongooseEncryptionToEncrypted`, `mongooseFieldEncryptionToEncrypted` — all return `Promise<{ migrated, skipped, errors }>`.
- CLI binary name matches the package name. Users invoke it with `npx mongoose-aes-encryption-migrate [options]`.
- `scripts/` is excluded from npm publish (`.npmignore`) but tracked in git.

## Testing

- Tests use `mongodb-memory-server` — no real MongoDB needed.
- Shared setup lives in `test/helpers.js`: `startDb()`, `stopDb()`, `getNativeCollection()`, `getEncryptedMongooseModel()`, and hardcoded test keys (`TARGET_KEY`, `SOURCE_ENC_KEY`, `SOURCE_SIG_KEY`, `SOURCE_SECRET`).
- CI runs Node 18, 20, 22 in parallel (`.github/workflows/git-build.yml`) and reports coverage to Coveralls.

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
