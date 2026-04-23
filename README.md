# GAMI — Global Authentic Memory Initiative

Core library, CLI, and REST API for creating and verifying cryptographic proofs of existence
for digital archival materials.

Each proof (GPR — GAMI Proof Record) ties a file to:
- A **SHA-256 hash** (file identity)
- An **Ed25519 institutional signature** (attribution)
- A **Bitcoin blockchain timestamp** via OpenTimestamps (existence proof)

See the [Technical Application Document](https://github.com/progressiv0/gami) for full
architecture and use-case documentation.

---

## Repository Structure

```
gami/
├── gami-core/          Shared library — hash, signing, OTS, verification
├── gami-cli/           Command-line interface  → README
├── gami-api/           HTTP REST API server    → README
├── go-opentimestamps/  Submodule — local OpenTimestamps dependency
├── go.sh               Run go commands across all modules
└── Makefile
```

- [gami-cli/README.md](gami-cli/README.md) — CLI installation, all commands, and examples
- [gami-api/README.md](gami-api/README.md) — API server configuration and endpoint reference

---

## Getting Started

### Clone

```bash
git clone --recurse-submodules git@github.com:progressiv0/gami.git
cd gami
```

> If you already cloned without submodules: `git submodule update --init`

### Build

```bash
make build
# Produces:
#   bin/gami-cli
#   bin/gami-api
```

### Cross-compile

```bash
make cross
# Produces bin/gami-cli-linux-amd64, bin/gami-api-darwin-arm64, etc.
```

---

## Development

### Multi-module helper — go.sh

`go.sh` runs any `go` command across all three modules (`gami-core`, `gami-cli`, `gami-api`)
in order, stopping on the first failure.

```bash
./go.sh mod tidy       # tidy all modules
./go.sh build ./...    # build all modules
./go.sh test ./...     # test all modules
```

### Makefile targets

| Target       | Description                                  |
|--------------|----------------------------------------------|
| `make build` | Compile CLI and API for current OS/arch      |
| `make test`  | Run all tests across all three modules       |
| `make lint`  | Run `go vet` across all three modules        |
| `make tidy`  | `go mod tidy && go mod verify` on all modules|
| `make cross` | Cross-compile for Linux, macOS, Windows      |
| `make clean` | Remove `bin/`                                |

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
