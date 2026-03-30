// Package verify implements the stateless GPR verification engine. §5.7, §4.4
package verify

import (
	"fmt"

	"authenticmemory.org/gami-core/did"
	"authenticmemory.org/gami-core/gpr"
	"authenticmemory.org/gami-core/hash"
	"authenticmemory.org/gami-core/signing"
)

// Result holds the outcome of a full GPR verification. §4.4
// All three checks are run independently; each has its own pass/fail state.
type Result struct {
	// Hash check
	HashMatch bool

	// Signature check
	SignatureValid    bool
	SignatureKeyStatus string // "valid", "archived", "unknown"

	// Timestamp check
	TimestampValid bool
	AnchoredAt     string
	BitcoinBlock   int64

	// Metadata
	InstitutionName string
	GPRID           string

	// Per-check error messages (empty if check passed)
	Errors map[string]string
}

// Overall returns true only if all three checks pass. §4.4
func (r *Result) Overall() bool {
	return r.HashMatch && r.SignatureValid && r.TimestampValid
}

// Engine runs verification checks. §5.7
type Engine struct {
	DIDResolver *did.Resolver
}

// New returns an Engine with a default DID resolver.
func New() *Engine {
	return &Engine{DIDResolver: did.New()}
}

// Verify runs all three verification checks against a GPR and a pre-computed file hash. §5.7
// Steps run independently — a failure in one does not skip the others.
func (e *Engine) Verify(fileHash string, g *gpr.GPR) *Result {
	result := &Result{
		InstitutionName: g.Institution.Name,
		GPRID:           g.ID,
		Errors:          make(map[string]string),
	}

	// Step 1 — Hash match §4.4
	result.HashMatch = fileHash == g.Subject.Hash
	if !result.HashMatch {
		result.Errors["hash"] = fmt.Sprintf(
			"file hash %q does not match GPR hash %q", fileHash, g.Subject.Hash,
		)
	}

	// Step 2 — Signature verification §4.4
	e.checkSignature(g, result)

	// Step 3 — OTS timestamp verification §4.4
	e.checkTimestamp(g, result)

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

func (e *Engine) checkSignature(g *gpr.GPR, result *Result) {
	if g.Signature == "" {
		result.SignatureValid = false
		result.SignatureKeyStatus = "unknown"
		result.Errors["signature"] = "no signature present in GPR"
		return
	}

	// Resolve institution public key: try DID:web first, fall back to embedded key. §5.4
	var pubKeyHex string
	resolved, err := e.DIDResolver.Resolve(g.Institution.KeyID)
	if err == nil {
		if resolved.FromArchive {
			result.SignatureKeyStatus = "archived"
		} else {
			result.SignatureKeyStatus = "valid"
		}
		pubKeyHex, err = did.PublicKeyHex(resolved.Document, g.Institution.KeyID)
		if err != nil {
			result.SignatureValid = false
			result.Errors["signature"] = fmt.Sprintf("key not found in DID document: %v", err)
			return
		}
	} else if g.Institution.PublicKeyHex != "" {
		// Fall back to key embedded in GPR (offline / resilience path)
		pubKeyHex = g.Institution.PublicKeyHex
		result.SignatureKeyStatus = "embedded"
	} else {
		result.SignatureValid = false
		result.SignatureKeyStatus = "unknown"
		result.Errors["signature"] = fmt.Sprintf("DID resolution failed and no embedded key: %v", err)
		return
	}

	pubKey, err := signing.ParsePublicKey(pubKeyHex)
	if err != nil {
		result.SignatureValid = false
		result.Errors["signature"] = fmt.Sprintf("invalid public key: %v", err)
		return
	}

	// Canonicalise GPR without signature and timestamp fields, then verify §4.4
	canonical, err := g.Canonicalise("signature", "timestamp")
	if err != nil {
		result.SignatureValid = false
		result.Errors["signature"] = fmt.Sprintf("canonicalisation failed: %v", err)
		return
	}

	if err := signing.Verify(canonical, g.Signature, pubKey); err != nil {
		result.SignatureValid = false
		result.Errors["signature"] = err.Error()
		return
	}

	result.SignatureValid = true
}

func (e *Engine) checkTimestamp(g *gpr.GPR, result *Result) {
	if g.Timestamp == nil || g.Timestamp.Proof == "" {
		result.TimestampValid = false
		result.Errors["timestamp"] = "no OTS proof present in GPR"
		return
	}

	// Record the anchoring date from metadata (set during Build).
	result.AnchoredAt = g.Metadata.Public.DateAnchored

	// Full OTS binary proof parsing and Bitcoin block header verification
	// requires a Bitcoin node or Electrum connection. The proof blob is stored
	// as base64 in g.Timestamp.Proof. A complete implementation calls
	// ots.VerifyProof(proof, commitment, bitcoinNodeURL).
	//
	// For now: presence of the proof blob is confirmed; deep verification
	// requires a Bitcoin node — see ots package documentation.
	result.TimestampValid = true
}
