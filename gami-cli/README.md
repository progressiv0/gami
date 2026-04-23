# gami-cli

Command-line interface for creating and verifying GAMI Proof Records (GPRs).

---

## Installation

### Build from source

```bash
# From the repo root (gami/)
make build
# Binary: bin/gami-cli
```

### Install to $GOPATH/bin

```bash
go install github.com/progressiv0/gami/gami-cli@latest
```

---

## Commands

### keygen — Generate a key pair

```bash
gami-cli keygen --domain example.org --output ./keys
# Writes:
#   keys/ed25519.priv   private key (keep secret)
#   keys/ed25519.pub    public key
#   keys/did.json       DID document template
```

Publish `keys/did.json` at `https://example.org/.well-known/did.json`.

---

### anchor — Hash, sign, and timestamp a file

```bash
gami-cli anchor \
  --file     photo.tif \
  --key      ./keys/ed25519.priv \
  --key-id   "did:web:example.org#key-1" \
  --institution "Example Archive" \
  --output   proof.gpr.json
```

Bitcoin confirmation takes ~1 hour. With optional metadata:

```bash
gami-cli anchor \
  --file photo.tif \
  --key ./keys/ed25519.priv \
  --key-id "did:web:example.org#key-1" \
  --institution "Example Archive" \
  --metadata '{"title":"Photo 451","collection":"DM"}' \
  --output proof.gpr.json
```

Embed the public key for offline verification (no DID:web lookup required):

```bash
gami-cli anchor \
  --file photo.tif \
  --key ./keys/ed25519.priv \
  --pub-key ./keys/ed25519.pub \
  --key-id "did:web:example.org#key-1" \
  --institution "Example Archive" \
  --output proof.gpr.json
```

If you already have a SHA-256 hash (e.g. from Archivematica):

```bash
gami-cli anchor \
  --hash sha256:3a7f91c2e8... \
  --key ./keys/ed25519.priv \
  --key-id "did:web:example.org#key-1" \
  --institution "Example Archive"
```

---

### upgrade — Embed the confirmed Bitcoin proof

After ~1 hour Bitcoin confirmation is available. Embed it into the GPR:

```bash
gami-cli upgrade --gpr proof.gpr.json
```

Write to a separate file instead of overwriting:

```bash
gami-cli upgrade --gpr proof.gpr.json --output proof-final.gpr.json
```

---

### verify — Verify a file against its GPR

```bash
gami-cli verify --file photo.tif --gpr proof.gpr.json
```

Output:

```
=== GAMI Verification Result ===
Institution : Example Archive
GPR ID      : urn:uuid:a1b2c3d4-...
Anchored at : 2026-09-15T14:22:00Z

  [PASS] File hash match
  [PASS] Institutional signature (Ed25519)
  [PASS] OTS timestamp (Bitcoin)

RESULT: VERIFIED  [Tier 1 — cryptographic proof]
```

As JSON:

```bash
gami-cli verify --file photo.tif --gpr proof.gpr.json --json
```

Verify via server (only the hash is sent — file stays local):

```bash
gami-cli verify --file photo.tif --server https://example.org/gami
```

---

### batch — Anchor multiple files

From a directory:

```bash
gami-cli batch \
  --adapter filesystem \
  --path /mnt/archive/collection \
  --key ./keys/ed25519.priv \
  --key-id "did:web:example.org#key-1" \
  --institution "Example Archive" \
  --output ./gprs
```

From a CSV manifest (columns: `path`, `hash`, `title`, `collection`):

```bash
gami-cli batch \
  --adapter csv \
  --manifest collection.csv \
  --key ./keys/ed25519.priv \
  --key-id "did:web:example.org#key-1" \
  --institution "Example Archive" \
  --output ./gprs
```

Resume an interrupted batch:

```bash
gami-cli batch ... --resume
```

---

### export — Download a GPR from an index server

```bash
# By file hash
gami-cli export \
  --hash sha256:3a7f91... \
  --server https://example.org/gami \
  --output proof.gpr.json

# By GPR ID with full provenance chain
gami-cli export \
  --id urn:uuid:a1b2c3... \
  --server https://example.org/gami \
  --chain
```

---

## Local Testing

The `test/` directory at the repo root contains a pre-signed GPR and sample file.

```bash
make build

bin/gami-cli verify --file test/testfile.txt --gpr test/testfile.gpr.json
```

Expected output:

```
  [PASS] File hash match
  [PASS] Institutional signature (Ed25519)
  [FAIL] OTS timestamp (Bitcoin)   ← anchored with --no-ots; run upgrade to fix
```
