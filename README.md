# GAMI — Global Authentic Memory Initiative

Core library and CLI for creating and verifying cryptographic proofs of existence
for digital archival materials.

Each proof (GPR — GAMI Proof Record) ties a file to:
- A **SHA-256 hash** (file identity)
- An **Ed25519 institutional signature** (attribution)
- A **Bitcoin blockchain timestamp** via OpenTimestamps (existence proof)

See the [Technical Application Document](https://github.com/progressiv0/gami) for full
architecture and use-case documentation.

---

## Requirements

- [Go 1.22+](https://go.dev/dl/)

No other runtime dependencies. All cryptographic primitives use the Go standard library.

---

## Installation

### From source

```bash
git clone git@github.com:progressiv0/gami.git
cd gami
go mod download
make build
# binary is at bin/gami
```

### Install to $GOPATH/bin

```bash
go install github.com/progressiv0/gami/cli@latest
```

### Cross-compile for all platforms

```bash
make cross
# Produces bin/gami-linux-amd64, bin/gami-darwin-arm64, bin/gami-windows-amd64.exe
```

---

## Quick Start

### 1. Generate a key pair

```bash
gami keygen --domain example.org --output ./keys

# Writes:
#   keys/ed25519.priv   private key (keep secret)
#   keys/ed25519.pub    public key
#   keys/did.json       DID document template
```

Publish `keys/did.json` at `https://example.org/.well-known/did.json`.

---

### 2. Anchor a file

```bash
gami anchor \
  --file     /path/to/archive/photo.tif \
  --key      ./keys/ed25519.priv \
  --key-id   "did:web:example.org#key-1" \
  --institution "Example Archive" \
  --output   proof.gpr.json
```

The GPR is written to `proof.gpr.json`. Bitcoin confirmation takes ~1 hour.

With optional metadata:

```bash
gami anchor \
  --file photo.tif \
  --key ./keys/ed25519.priv \
  --key-id "did:web:example.org#key-1" \
  --institution "Example Archive" \
  --metadata '{"title":"Photo 451","collection":"DM","classificationCode":"DM/2024/00451"}' \
  --output proof.gpr.json
```

If you already have a SHA-256 hash (e.g. from Archivematica), skip the file read:

```bash
gami anchor \
  --hash sha256:3a7f91c2e8... \
  --key ./keys/ed25519.priv \
  --key-id "did:web:example.org#key-1" \
  --institution "Example Archive"
```

---

### 3. Verify a file (offline / direct mode)

No server required. Verifies hash match, Ed25519 signature, and OTS proof locally.

```bash
gami verify --file photo.tif --gpr proof.gpr.json
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
gami verify --file photo.tif --gpr proof.gpr.json --json
```

---

### 4. Verify via server (lookup mode)

The file hash is computed locally and only the hash is sent to the server.

```bash
gami verify --file photo.tif --server https://authenticmemory.org
```

---

### 5. Batch anchoring

**From a directory:**

```bash
gami batch \
  --adapter filesystem \
  --path /mnt/archive/collection \
  --key ./keys/ed25519.priv \
  --key-id "did:web:example.org#key-1" \
  --institution "Example Archive" \
  --output ./gprs
```

**From a CSV manifest** (columns: `path`, `hash`, `title`, `collection`):

```bash
gami batch \
  --adapter csv \
  --manifest collection.csv \
  --key ./keys/ed25519.priv \
  --key-id "did:web:example.org#key-1" \
  --institution "Example Archive" \
  --output ./gprs
```

**Resume an interrupted batch:**

```bash
gami batch ... --resume
```

---

### 6. Export a GPR from the index

```bash
# By file hash
gami export \
  --hash sha256:3a7f91... \
  --server https://authenticmemory.org \
  --output proof.gpr.json

# By GPR ID with full provenance chain
gami export \
  --id urn:uuid:a1b2c3... \
  --server https://authenticmemory.org \
  --chain
```

---

## Project Structure

```
gami/
├── core/               Shared library — no HTTP, no UI, independently auditable
│   ├── hash/           SHA-256 file fingerprinting
│   ├── gpr/            GPR construction, JCS canonicalisation (RFC 8785)
│   ├── signing/        Ed25519 key generation, signing, verification
│   ├── ots/            OpenTimestamps calendar client
│   ├── did/            DID:web resolution with archive fallback
│   ├── verify/         Stateless verification engine (hash · sig · OTS)
│   └── batch/          Filesystem and CSV adapters, progress tracking
│
└── cli/                Command-line interface (uses core/ only)
    └── commands/
        ├── anchor      Hash → GPR → sign → OTS submit
        ├── verify      Offline or server-lookup verification
        ├── batch       Multi-file anchoring with resume support
        ├── keygen      Ed25519 key pair + DID document template
        └── export      Download GPR(s) from an index server
```

---

## Development

```bash
make test    # run all tests
make lint    # go vet
make tidy    # go mod tidy + verify
make build   # compile to bin/gami
make cross   # compile for Linux, macOS (amd64+arm64), Windows
```

---

## Standards

| Standard | Role |
|---|---|
| SHA-256 (FIPS 180-4) | File fingerprinting |
| Ed25519 (RFC 8032) | Institutional signing |
| OpenTimestamps | Bitcoin-anchored existence proofs |
| JCS / RFC 8785 | Deterministic JSON canonicalisation |
| DID:web (W3C) | Institutional key management |

---

## License

MIT
