// Package verify implements the stateless GPR verification engine. §5.7, §4.4
package verify

import (
	"bytes"
	gosha256 "crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"authenticmemory.org/gami-core/did"
	"authenticmemory.org/gami-core/gpr"
	"authenticmemory.org/gami-core/hash"
	"authenticmemory.org/gami-core/signing"
	"github.com/progressiv0/go-opentimestamps/core"
)

// otsFileMagic is the 31-byte header that starts every DetachedTimestampFile (.ots).
var otsFileMagic = []byte("\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94")

// Checks holds the per-check results.
type Checks struct {
	FileHashMatch      bool   `json:"file_hash_match"`
	CanonicalChecked   bool   `json:"canonical_checked,omitempty"` // set only in ots_file mode
	SignatureValid     bool   `json:"signature_valid"`
	SignatureKeyStatus string `json:"signature_key_status,omitempty"`
	OTSVerified        bool   `json:"ots_verified"`
}

// Result holds the outcome of a GPR verification. §4.4
type Result struct {
	Valid bool   `json:"valid"`
	Mode  string `json:"mode"` // "full" | "ots_only"

	GPRID string `json:"gpr_id,omitempty"`
	KeyID string `json:"key_id,omitempty"`

	Checks Checks `json:"checks"`

	AnchoredAt   string `json:"anchored_at,omitempty"`
	BitcoinBlock int64  `json:"bitcoin_block,omitempty"`

	Errors map[string]string `json:"errors,omitempty"`
}

// Overall returns true only if all applicable checks pass. §4.4
func (r *Result) Overall() bool {
	if r.Mode == "ots_only" {
		return r.Checks.OTSVerified
	}
	return r.Checks.FileHashMatch && r.Checks.SignatureValid && r.Checks.OTSVerified
}

// Options controls optional overrides for verification.
type Options struct {
	// PublicKeyHex overrides DID resolution and the embedded key for signature verification.
	// If empty, normal key resolution (DID → embedded) is used.
	PublicKeyHex string
}

// Engine runs verification checks. §5.7
type Engine struct {
	DIDResolver *did.Resolver
}

// New returns an Engine with a default DID resolver.
func New() *Engine {
	return &Engine{DIDResolver: did.New()}
}

// Verify runs all three checks against a GPR and a pre-computed file hash. §5.7
// Equivalent to VerifyWithOptions with empty Options.
func (e *Engine) Verify(fileHash string, g *gpr.GPR) *Result {
	return e.VerifyWithOptions(fileHash, g, Options{})
}

// VerifyWithOptions runs full verification with optional key override.
func (e *Engine) VerifyWithOptions(fileHash string, g *gpr.GPR, opts Options) *Result {
	result := &Result{
		Mode:       "full",
		KeyID:      g.Proof.KeyID,
		GPRID:      g.ID,
		AnchoredAt: g.Proof.Created,
		Errors:     make(map[string]string),
	}

	// Step 1 — Hash match §4.4
	result.Checks.FileHashMatch = fileHash == g.Subject.FileHash
	if !result.Checks.FileHashMatch {
		result.Errors["hash"] = fmt.Sprintf(
			"file hash %q does not match GPR hash %q", fileHash, g.Subject.FileHash,
		)
	}

	// Step 2 — Signature verification §4.4
	e.checkSignature(g, result, opts.PublicKeyHex)

	// Step 3 — OTS timestamp verification §4.4
	e.checkTimestamp(g, result)

	result.Valid = result.Overall()
	return result
}

// VerifyFile hashes the file at filePath and verifies it against a GPR. §UC-05
func (e *Engine) VerifyFile(filePath string, g *gpr.GPR) (*Result, error) {
	fileHash, err := hash.File(filePath)
	if err != nil {
		return nil, fmt.Errorf("hash file: %w", err)
	}
	return e.Verify(fileHash, g), nil
}

// VerifyOTS parses a raw OTS binary proof (base64-encoded) and reports its attestation status.
// fileHash is optional; if provided it is used as the tree root for parsing (enabling hash-chain
// consistency checking). If absent a zero-byte root is used — tree structure is still validated.
func (e *Engine) VerifyOTS(fileHash string, otsDataBase64 string) *Result {
	result := &Result{
		Mode:   "ots_only",
		Errors: make(map[string]string),
	}

	otsBytes, err := base64.StdEncoding.DecodeString(otsDataBase64)
	if err != nil {
		result.Errors["ots"] = fmt.Sprintf("invalid base64: %v", err)
		return result
	}

	var hashBytes []byte
	if fileHash != "" {
		trimmed := strings.TrimPrefix(fileHash, "sha256:")
		hashBytes, err = hex.DecodeString(trimmed)
		if err != nil || len(hashBytes) != 32 {
			result.Errors["ots"] = fmt.Sprintf("invalid file hash: %v", err)
			return result
		}
	} else {
		hashBytes = make([]byte, 32)
	}

	ctx := core.NewBytesDeserializationContext(otsBytes)
	ts, err := core.DeserializeTimestamp(ctx, hashBytes, 256)
	if err != nil {
		result.Errors["ots"] = fmt.Sprintf("parse OTS data: %v", err)
		return result
	}

	bitcoinBlock, hasPending := walkAttestations(ts)
	switch {
	case bitcoinBlock > 0:
		result.Checks.OTSVerified = true
		result.BitcoinBlock = bitcoinBlock
	case hasPending:
		result.Errors["ots"] = "OTS proof is pending Bitcoin confirmation"
	default:
		result.Errors["ots"] = "no recognised attestation found in OTS data"
	}

	result.Valid = result.Overall()
	return result
}

// VerifyOTSFile parses a standard .ots DetachedTimestampFile (base64-encoded) and checks
// its attestation status — equivalent to `ots verify --no-bitcoin`.
//
// If canonicalContent is non-nil its SHA-256 is compared against the file digest
// embedded in the .ots header, populating Checks.FileHashMatch accordingly.
//
// Format: HEADER_MAGIC(31) | version(1) | SHA256-op-tag=0x08(1) | digest(32) | timestamp-tree
func (e *Engine) VerifyOTSFile(otsFileBase64 string, canonicalContent []byte) *Result {
	result := &Result{
		Mode:   "ots_only",
		Errors: make(map[string]string),
	}

	otsBytes, err := base64.StdEncoding.DecodeString(otsFileBase64)
	if err != nil {
		result.Errors["ots"] = fmt.Sprintf("invalid base64: %v", err)
		return result
	}

	const minLen = 31 + 1 + 1 + 32 // magic + version + hash-op + digest
	if len(otsBytes) < minLen {
		result.Errors["ots"] = "file too short to be a valid .ots file"
		return result
	}
	if !bytes.Equal(otsBytes[:len(otsFileMagic)], otsFileMagic) {
		result.Errors["ots"] = "not a valid .ots file — magic bytes mismatch"
		return result
	}

	pos := len(otsFileMagic)
	version := otsBytes[pos]
	pos++
	if version != 0x01 {
		result.Errors["ots"] = fmt.Sprintf("unsupported .ots version %d", version)
		return result
	}

	hashOp := otsBytes[pos]
	pos++
	if hashOp != 0x08 {
		result.Errors["ots"] = fmt.Sprintf("unsupported hash algorithm in .ots file (tag 0x%02x, only SHA-256/0x08 supported)", hashOp)
		return result
	}

	fileDigest := otsBytes[pos : pos+32]
	pos += 32

	// Optional: verify canonical content hash matches the embedded file digest.
	if len(canonicalContent) > 0 {
		result.Checks.CanonicalChecked = true
		h := gosha256.Sum256(canonicalContent)
		result.Checks.FileHashMatch = bytes.Equal(h[:], fileDigest)
		if !result.Checks.FileHashMatch {
			result.Errors["canonical"] = fmt.Sprintf(
				"canonical file SHA-256 %x does not match digest in .ots file %x",
				h[:], fileDigest,
			)
		}
	}

	// Parse and walk the timestamp tree.
	ctx := core.NewBytesDeserializationContext(otsBytes[pos:])
	ts, err := core.DeserializeTimestamp(ctx, fileDigest, 256)
	if err != nil {
		result.Errors["ots"] = fmt.Sprintf("parse OTS tree: %v", err)
		result.Valid = result.Overall()
		return result
	}

	bitcoinBlock, hasPending := walkAttestations(ts)
	switch {
	case bitcoinBlock > 0:
		result.Checks.OTSVerified = true
		result.BitcoinBlock = bitcoinBlock
	case hasPending:
		result.Errors["ots"] = "OTS proof is pending Bitcoin confirmation"
	default:
		result.Errors["ots"] = "no recognised attestation found in OTS data"
	}

	result.Valid = result.Overall()
	return result
}

// walkAttestations recursively walks a timestamp tree and returns the lowest
// Bitcoin block height found and whether any PendingAttestation was seen.
func walkAttestations(ts *core.Timestamp) (bitcoinBlock int64, hasPending bool) {
	for _, att := range ts.Attestations {
		switch a := att.(type) {
		case *core.BitcoinBlockHeaderAttestation:
			h := int64(a.Height)
			if bitcoinBlock == 0 || h < bitcoinBlock {
				bitcoinBlock = h
			}
		case *core.PendingAttestation:
			hasPending = true
		}
	}
	for _, entry := range ts.Ops.Entries() {
		b, p := walkAttestations(entry.Stamp)
		if b > 0 && (bitcoinBlock == 0 || b < bitcoinBlock) {
			bitcoinBlock = b
		}
		if p {
			hasPending = true
		}
	}
	return
}

func (e *Engine) checkSignature(g *gpr.GPR, result *Result, keyOverride string) {
	if g.Proof.Signature == "" {
		result.Checks.SignatureValid = false
		result.Checks.SignatureKeyStatus = "unknown"
		result.Errors["signature"] = "no signature present in GPR"
		return
	}

	var pubKeyHex string
	if keyOverride != "" {
		pubKeyHex = keyOverride
		result.Checks.SignatureKeyStatus = "overridden"
	} else {
		resolved, err := e.DIDResolver.Resolve(g.Proof.KeyID)
		if err == nil {
			if resolved.FromArchive {
				result.Checks.SignatureKeyStatus = "archived"
			} else {
				result.Checks.SignatureKeyStatus = "valid"
			}
			pubKeyHex, err = did.PublicKeyHex(resolved.Document, g.Proof.KeyID)
			if err != nil {
				result.Checks.SignatureValid = false
				result.Errors["signature"] = fmt.Sprintf("key not found in DID document: %v", err)
				return
			}
		} else if g.Proof.PublicKeyHex != "" {
			pubKeyHex = g.Proof.PublicKeyHex
			result.Checks.SignatureKeyStatus = "embedded"
		} else {
			result.Checks.SignatureValid = false
			result.Checks.SignatureKeyStatus = "unknown"
			result.Errors["signature"] = fmt.Sprintf("DID resolution failed and no embedded key: %v", err)
			return
		}
	}

	pubKey, err := signing.ParsePublicKey(pubKeyHex)
	if err != nil {
		result.Checks.SignatureValid = false
		result.Errors["signature"] = fmt.Sprintf("invalid public key: %v", err)
		return
	}

	canonical, err := g.CanonicaliseForSigning()
	if err != nil {
		result.Checks.SignatureValid = false
		result.Errors["signature"] = fmt.Sprintf("canonicalise for signing: %v", err)
		return
	}

	if err := signing.Verify(canonical, g.Proof.Signature, pubKey); err != nil {
		result.Checks.SignatureValid = false
		result.Errors["signature"] = err.Error()
		return
	}

	result.Checks.SignatureValid = true
}

func (e *Engine) checkTimestamp(g *gpr.GPR, result *Result) {
	if g.Proof.Timestamp == nil || g.Proof.Timestamp.OTSData == "" {
		result.Checks.OTSVerified = false
		result.Errors["timestamp"] = "no OTS proof present — run 'gami stamp' then 'gami upgrade'"
		return
	}

	otsBytes, err := base64.StdEncoding.DecodeString(g.Proof.Timestamp.OTSData)
	if err != nil {
		result.Checks.OTSVerified = false
		result.Errors["timestamp"] = fmt.Sprintf("invalid OTS data encoding: %v", err)
		return
	}

	docHashHex := strings.TrimPrefix(g.Proof.Timestamp.DocumentHash, "sha256:")
	docHashBytes, err := hex.DecodeString(docHashHex)
	if err != nil || len(docHashBytes) != 32 {
		result.Checks.OTSVerified = false
		result.Errors["timestamp"] = "invalid document_hash in GPR timestamp"
		return
	}

	ctx := core.NewBytesDeserializationContext(otsBytes)
	ts, err := core.DeserializeTimestamp(ctx, docHashBytes, 256)
	if err != nil {
		result.Checks.OTSVerified = false
		result.Errors["timestamp"] = fmt.Sprintf("parse OTS data: %v", err)
		return
	}

	bitcoinBlock, hasPending := walkAttestations(ts)
	switch {
	case bitcoinBlock > 0:
		result.Checks.OTSVerified = true
		result.BitcoinBlock = bitcoinBlock
	case hasPending:
		result.Checks.OTSVerified = false
		result.Errors["timestamp"] = "OTS proof is pending Bitcoin confirmation — try 'gami upgrade'"
	default:
		result.Checks.OTSVerified = false
		result.Errors["timestamp"] = "OTS data present but no valid attestation found"
	}
}
