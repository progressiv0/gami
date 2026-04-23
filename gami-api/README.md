# gami-api

HTTP REST API server exposing GAMI proof operations. The server holds the institution's
private key — clients never send key material over the wire.

---

## Build & Run

```bash
# From the repo root (gami/)
make build
# Binary: bin/gami-api

# Run
GAMI_KEY_ID="did:web:example.org#key-1" \
GAMI_PRIVATE_KEY="<hex>" \
GAMI_PUBLIC_KEY="<hex>" \
bin/gami-api
# Listening on :8080
```

---

## Configuration

All configuration is via environment variables.

| Variable           | Required | Default | Description |
|--------------------|----------|---------|-------------|
| `PORT`             | No       | `8080`  | TCP port to listen on |
| `GAMI_KEY_ID`      | For signing | —  | DID key reference, e.g. `did:web:example.org#key-1` |
| `GAMI_PRIVATE_KEY` | For signing | —  | Hex-encoded Ed25519 private key |
| `GAMI_PUBLIC_KEY`  | No       | —       | Hex-encoded Ed25519 public key — embedded in GPRs for offline verification |

Signing endpoints (`/v1/anchor`, `/v1/sign`) return `503` if `GAMI_KEY_ID` or
`GAMI_PRIVATE_KEY` are not set. All other endpoints work without key material.

---

## Endpoints

### POST /v1/anchor

Hash → GPR → sign → OTS submit in one call. Requires key configuration.

```json
{
  "file_hash":  "sha256:<64 hex chars>",
  "filename":   "photo.tif",
  "metadata":   { "title": "Photo 451", "collection": "DM" },
  "parent_id":  null,
  "submit_ots": true
}
```

Response:

```json
{
  "gpr":      { ... },
  "calendar": "https://alice.btc.calendar.opentimestamps.org",
  "ots_error": null
}
```

---

### POST /v1/sign

Sign an existing unsigned GPR with the server's key. Requires key configuration.

```json
{
  "gpr": { ... }
}
```

Response: the signed GPR object.

---

### POST /v1/stamp

Compute `document_hash` and optionally submit to OTS. No key material required.

```json
{
  "gpr":        { ... },
  "submit_ots": true
}
```

Response:

```json
{
  "gpr":      { ... },
  "calendar": "https://alice.btc.calendar.opentimestamps.org"
}
```

---

### POST /v1/upgrade

Fetch the completed Bitcoin proof from OTS calendars and embed it in the GPR.

```json
{
  "gpr": { ... }
}
```

Response:

```json
{
  "gpr":       { ... },
  "confirmed": true,
  "calendar":  "https://alice.btc.calendar.opentimestamps.org"
}
```

---

### POST /v1/verify

Stateless verification — no key material required. Four modes:

**Full GPR verification:**

```json
{
  "file_hash": "sha256:...",
  "gpr":       { ... }
}
```

**Full GPR verification with public key override:**

```json
{
  "file_hash":      "sha256:...",
  "gpr":            { ... },
  "public_key_hex": "<hex>"
}
```

**OTS-only from raw tree bytes:**

```json
{
  "file_hash": "sha256:...",
  "ots_data":  "<base64>"
}
```

**OTS-only from exported `.ots` file:**

```json
{
  "ots_file":  "<base64>",
  "canonical": "<text content of .canonical file>"
}
```

Response (all modes):

```json
{
  "hash_ok":      true,
  "signature_ok": true,
  "ots_ok":       true,
  "institution":  "Example Archive",
  "anchored_at":  "2026-09-15T14:22:00Z"
}
```
