# mongoose-aes-encryption-migrate

CLI migration tool for [mongoose-aes-encryption](https://github.com/tsmx/mongoose-aes-encryption) for existing databases in plaintext or using other Mongoose encryption plugins.

Supports migration for the following paths:

| Mode | Source plugin | Source encryption |
|---|---|---|
| `plaintext` | No encryption — plain text fields | none |
| `mongoose-encryption` | [mongoose-encryption](https://github.com/joegoldbeck/mongoose-encryption) | AES-CBC |
| `mongoose-field-encryption` | [mongoose-field-encryption](https://github.com/wheresvic/mongoose-field-encryption) | AES-CBC |

> **Always back up your database before running a migration.**

---

## Installation

```bash
npm install -g mongoose-aes-encryption-migrate
# peer dependencies
npm install mongoose-aes-encryption mongoose
```

Or use without installing via `npx`:

```bash
npx mongoose-aes-encryption-migrate --help
```

---

## CLI usage

### Mode 1 — Plain-text to encrypted

Use this when you have added `encrypted: true` to fields in an existing Mongoose schema and need to encrypt all existing documents that still hold plain-text values.

```bash
mongoose-aes-encryption-migrate \
  --uri         mongodb://localhost:27017/mydb \
  --collection  users \
  --mode        plaintext \
  --key         9af7d400be4705147dc724db25bfd2513aa11d6013d7bf7bdb2bfe050593bd0f \
  --fields      name,email,salary
```

The tool is **idempotent** — documents whose fields are already encrypted are detected and skipped automatically. Safe to re-run.

---

### Mode 2 — From mongoose-encryption

Use this when migrating from [mongoose-encryption](https://github.com/joegoldbeck/mongoose-encryption), which stores all encrypted fields bundled together in a single `_ct` Binary field per document.

```bash
mongoose-aes-encryption-migrate \
  --uri           mongodb://localhost:27017/mydb \
  --collection    users \
  --mode          mongoose-encryption \
  --key           9af7d400be4705147dc724db25bfd2513aa11d6013d7bf7bdb2bfe050593bd0f \
  --source-key    <base64-encoded encryptionKey from mongoose-encryption> \
  --fields        name,email \
  --plaintext-fields salary
```

**Important:** `mongoose-encryption` bundles multiple fields into a single `_ct` blob. Every field found inside that blob must be explicitly accounted for:

- `--fields` — fields to re-encrypt individually with `mongoose-aes-encryption`
- `--plaintext-fields` — fields to restore as unencrypted plaintext

If any field inside `_ct` is not covered by either flag, the tool **aborts at pre-flight** and lists the unaccounted fields along with suggested corrected commands. No data is lost or changed.

After migration, `_ct` and `_ac` are removed from every document.

---

### Mode 3 — From mongoose-field-encryption

Use this when migrating from [mongoose-field-encryption](https://github.com/wheresvic/mongoose-field-encryption), which stores each field as a per-field AES-256-CBC string in the format `<salt-hex>:<ciphertext-hex>` alongside `__enc_<field>` boolean marker fields.

```bash
mongoose-aes-encryption-migrate \
  --uri         mongodb://localhost:27017/mydb \
  --collection  users \
  --mode        mongoose-field-encryption \
  --key         9af7d400be4705147dc724db25bfd2513aa11d6013d7bf7bdb2bfe050593bd0f \
  --secret      "the secret string used with mongoose-field-encryption" \
  --fields      name,email,salary
```

After migration, the `__enc_<field>` boolean markers and any `__enc_<field>_d` data fields (used for non-string types) are removed from every document.

Documents where the `__enc_<field>` marker is `false` or absent are skipped (field is already plaintext).

---

## All options

| Option | Required | Default | Description |
|---|---|---|---|
| `--uri` | yes | — | MongoDB connection string, must include database name |
| `--collection` | yes | — | Collection name to migrate |
| `--mode` | yes | — | `plaintext`, `mongoose-encryption`, or `mongoose-field-encryption` |
| `--key` | yes | — | 64-character hex target encryption key |
| `--fields` | yes | — | Comma-separated field paths to encrypt |
| `--plaintext-fields` | mode 2 only | — | Comma-separated fields from `_ct` to restore as plaintext |
| `--source-key` | mode 2 only | — | base64 `encryptionKey` used with `mongoose-encryption` |
| `--secret` | mode 3 only | — | Secret string used with `mongoose-field-encryption` |
| `--algorithm` | no | `aes-256-gcm` | Target algorithm: `aes-256-gcm` or `aes-256-cbc` |
| `--batch-size` | no | `100` | Number of documents to process per batch |
| `--dry-run` | no | `false` | Probe and report without writing any changes |

---

## Dry-run mode

Add `--dry-run` to any command to see what would happen without touching the database:

```bash
mongoose-aes-encryption-migrate \
  --uri mongodb://localhost:27017/mydb \
  --collection users \
  --mode plaintext \
  --key  9af7d400be4705147dc724db25bfd2513aa11d6013d7bf7bdb2bfe050593bd0f \
  --fields name,email \
  --dry-run
```

---

## Error handling

If a document fails to update (e.g. due to a write conflict), the tool pauses and asks:

```
  Error processing document _id=64a3f...: <error message>
? What do you want to do?
  > Skip this document and continue
    Abort the migration
```

Skipped document IDs are reported in the final summary. You can re-run the tool afterward — already-migrated documents are skipped automatically.

---

## Programmatic API

For use in custom migration scripts or CI pipelines. Errors throw immediately (no interactive prompts).

```js
const {
    plaintextToEncrypted,
    mongooseEncryptionToEncrypted,
    mongooseFieldEncryptionToEncrypted
} = require('mongoose-aes-encryption-migrate');

// Mode 1 — plain text
const result = await plaintextToEncrypted({
    uri:        'mongodb://localhost:27017/mydb',
    collection: 'users',
    fields:     ['name', 'email', 'salary'],
    key:        '9af7d400be4705147dc724db25bfd2513aa11d6013d7bf7bdb2bfe050593bd0f',
    algorithm:  'aes-256-gcm',   // optional, default
    batchSize:  100,              // optional, default
    dryRun:     false             // optional, default
});
// result: { migrated: 998, skipped: 2, errors: 0 }

// Mode 2 — mongoose-encryption
const result = await mongooseEncryptionToEncrypted({
    uri:             'mongodb://localhost:27017/mydb',
    collection:      'users',
    fields:          ['name', 'email'],
    plaintextFields: ['salary'],
    key:             '9af7d400be4705147dc724db25bfd2513aa11d6013d7bf7bdb2bfe050593bd0f',
    sourceKey:       '<base64 encryptionKey>',
    dryRun:          false
});

// Mode 3 — mongoose-field-encryption
const result = await mongooseFieldEncryptionToEncrypted({
    uri:        'mongodb://localhost:27017/mydb',
    collection: 'users',
    fields:     ['name', 'email', 'salary'],
    secret:     'the secret string used with mongoose-field-encryption',
    key:        '9af7d400be4705147dc724db25bfd2513aa11d6013d7bf7bdb2bfe050593bd0f',
    dryRun:     false
});
```

All functions return `Promise<{ migrated: number, skipped: number, errors: number }>`.

---

## How each source plugin is migrated

### mongoose-encryption

`mongoose-encryption` stores all encrypted fields together in a single `_ct` BSON Binary field:

```
_ct layout:  [ version (1 byte) | IV (16 bytes) | AES-256-CBC ciphertext ]
             ciphertext decrypts to: JSON.stringify({ name: "Joe", email: "...", salary: 50000 })
```

The migration tool:
1. Decrypts `_ct` using the AES-256-CBC `encryptionKey` provided as `--source-key` (base64)
2. Re-encrypts each field in `--fields` individually using `mongoose-aes-encryption`'s wire format
3. Restores fields in `--plaintext-fields` as unencrypted values
4. Writes `$set` of all new field values and `$unset` of `_ct` and `_ac` in a single atomic update per document

Documents without a `_ct` field are skipped (already migrated or never encrypted).

### mongoose-field-encryption

`mongoose-field-encryption` stores each encrypted field in-place as:

```
<16-byte-salt-hex>:<ciphertext-hex>
```

Using AES-256-CBC with a key derived from the user's secret via `SHA-256(secret).slice(0, 32 bytes)`. A boolean marker `__enc_<fieldname>: true` marks encrypted fields. Non-string types are additionally stored in a `__enc_<fieldname>_d` field with the original field set to `undefined`.

The migration tool:
1. Checks the `__enc_<field>` marker — if `false` or absent, the field is plaintext and skipped
2. Derives the AES key from the `--secret` using the same SHA-256 method
3. Decrypts each field value (or `__enc_<field>_d` for non-string types)
4. Re-encrypts with `mongoose-aes-encryption`'s wire format
5. Writes `$set` of new ciphertext values and `$unset` of all `__enc_*` marker and data fields

---

## License

MIT
