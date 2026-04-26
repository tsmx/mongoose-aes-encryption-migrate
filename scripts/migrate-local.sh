#!/usr/bin/env bash
set -euo pipefail

# migrate-local.sh — generate a fresh AES-256 key and migrate all three local
# test collections created by seed.js to mongoose-aes-encryption format.
#
# Run from the repo root:
#   bash scripts/migrate-local.sh
#
# Requires: openssl, npx, a running MongoDB on localhost:27017

MONGO_URI="mongodb://localhost:27017/encryptiontest"

# ── Source credentials (must match seed.js) ───────────────────────────────────
MFE_SECRET="mfe-secret-seed-key-32bytes!!!!!"
ME_SOURCE_KEY_B64="YD3rEBXKcb4rc67whX13gR81LAc7YQjXLZgQowkU3/Q="

# ── Generate target key ───────────────────────────────────────────────────────
TARGET_KEY=$(openssl rand -hex 32)
echo "============================================================"
echo " Generated target key (save this for verify.js --key):"
echo " $TARGET_KEY"
echo "============================================================"
echo ""

# ── Helper ────────────────────────────────────────────────────────────────────
migrate() {
    local label="$1"
    shift
    echo "--- $label ---"
    npx --yes mongoose-aes-encryption-migrate \
        --uri "$MONGO_URI" \
        --key "$TARGET_KEY" \
        "$@"
    echo ""
}

# ── Phase 1: mg-field-enc-test ────────────────────────────────────────────────
migrate "mg-field-enc-test (mongoose-field-encryption)" \
    --collection "mg-field-enc-test" \
    --mode "mongoose-field-encryption" \
    --fields "firstName,lastName,email,age" \
    --secret "$MFE_SECRET"

# ── Phase 2: mg-enc-test ──────────────────────────────────────────────────────
migrate "mg-enc-test (mongoose-encryption)" \
    --collection "mg-enc-test" \
    --mode "mongoose-encryption" \
    --fields "firstName,lastName,email,age" \
    --source-key "$ME_SOURCE_KEY_B64"

# ── Phase 3: mg-plaintext-test ────────────────────────────────────────────────
migrate "mg-plaintext-test (plaintext)" \
    --collection "mg-plaintext-test" \
    --mode "plaintext" \
    --fields "firstName,lastName,email,age"

echo "============================================================"
echo " All migrations complete."
echo " Run verify.js with:"
echo "   node scripts/verify.js --key $TARGET_KEY"
echo "============================================================"
