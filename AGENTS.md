# AGENTS.md

## Overview

Plain CommonJS JavaScript Node.js library + CLI. No TypeScript, no build step. Migrates MongoDB collections to `@tsmx/mongoose-aes-encryption` format from three source modes: plaintext, `mongoose-encryption`, and `mongoose-field-encryption`.

## Commands

```bash
npm test                # jest --testEnvironment node (no tests exist yet)
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
bin/migrate.js     ← CLI binary (registered as "mongoose-aes-migration")
lib/
  detect.js                          ← isAlreadyEncrypted() heuristic
  mongo.js                           ← connect/count/sample via native mongodb driver
  plaintext.js
  mongoose-encryption.js
  mongoose-field-encryption.js
```

- Programmatic API exports: `plaintextToEncrypted`, `mongooseEncryptionToEncrypted`, `mongooseFieldEncryptionToEncrypted` — all return `Promise<{ migrated, skipped, errors }>`.
- CLI binary name is `mongoose-aes-migration`, not `mongoose-aes-encryption-migrate`.

## Critical quirks

- **Local peer dep.** `mongoose-aes-encryption` is resolved from `file:../mongoose-aes-encryption` (a sibling directory). `npm install` will fail in a fresh checkout unless that sibling package exists at that relative path.
- **No tests exist yet.** `npm test` exits 0 but runs nothing. New tests go in `test/` or root with `.test.js` suffix.
- **Native `mongodb` driver, not Mongoose.** `lib/mongo.js` uses the MongoDB native driver directly. Mongoose is only a peer dep for the consumer app.
- **`--fields` CLI flag is comma-separated; programmatic API takes `string[]`.** Don't pass a comma string to the API.
- **Programmatic `onError` always throws; CLI `onError` prompts interactively.** Test the library path for unit tests.
- **Double-encryption risk.** If `isAlreadyEncrypted()` is called with the wrong key, an already-encrypted field will be treated as plaintext and re-encrypted. Key must be consistent across runs.
- **Node >=18 required.**
- **No dotenv/config file support.** Keys and secrets are passed via CLI flags or programmatic options only.
