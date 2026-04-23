// Package service provides the orchestration layer shared by the CLI and API.
//
// Each function accepts plain data (hashes, keys as hex strings, GPR structs)
// and returns a result or an error. I/O concerns (reading files, HTTP encoding)
// are the caller's responsibility.
package service

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/progressiv0/gami/gami-core/gpr"
	"github.com/progressiv0/gami/gami-core/hash"
	"github.com/progressiv0/gami/gami-core/ots"
	"github.com/progressiv0/gami/gami-core/signing"
)

// ── Anchor ────────────────────────────────────────────────────────────────────

// AnchorRequest holds all inputs for the full prepare → sign → stamp pipeline.
type AnchorRequest struct {
	// FileHash is the pre-computed "sha256:<hex>" string.
	// The caller is responsible for hashing the file (hash.File / hash.Reader / hash.Bytes).
	FileHash string

	// Filename is stored in subject.filename; optional.
	Filename string

	// KeyID is the DID key reference, e.g. "did:web:example.org#key-1".
	KeyID string

	// PrivKeyHex is the hex-encoded Ed25519 private key used to sign.
	PrivKeyHex string

	// PubKeyHex is the hex-encoded Ed25519 public key.
	// When non-empty it is embedded in proof.public_key_hex for offline verification.
	PubKeyHex string

	// Metadata is stored in subject.metadata; optional.
	Metadata map[string]string

	// ParentID links this GPR to a parent GPR; optional.
	ParentID *string

	// SubmitOTS controls whether the document hash is submitted to OTS calendars.
	SubmitOTS bool
}

// AnchorResult holds the output of a successful Anchor call.
type AnchorResult struct {
	GPR      *gpr.GPR
	Calendar string // empty if SubmitOTS=false
	// OTSError is non-nil when OTS submission was requested but failed.
	// The GPR is still fully signed; only the OTS proof is absent.
	OTSError error
}

// Anchor runs the full prepare → sign → stamp pipeline.
func Anchor(req AnchorRequest) (*AnchorResult, error) {
	if err := hash.Validate(req.FileHash); err != nil {
		return nil, fmt.Errorf("invalid FileHash: %w", err)
	}
	if req.KeyID == "" {
		return nil, fmt.Errorf("KeyID is required")
	}
	if req.PrivKeyHex == "" {
		return nil, fmt.Errorf("PrivKeyHex is required")
	}

	g, err := gpr.Build(gpr.BuildRequest{
		FileHash: req.FileHash,
		Filename: req.Filename,
		KeyID:    req.KeyID,
		Metadata: req.Metadata,
		ParentID: req.ParentID,
	})
	if err != nil {
		return nil, fmt.Errorf("build GPR: %w", err)
	}

	g, err = applySign(g, req.PrivKeyHex, req.PubKeyHex)
	if err != nil {
		return nil, err
	}

	stampRes, err := applyStamp(g, req.SubmitOTS)
	if err != nil {
		return nil, err
	}

	return &AnchorResult{
		GPR:      stampRes.GPR,
		Calendar: stampRes.Calendar,
		OTSError: stampRes.OTSError,
	}, nil
}

// ── Sign ──────────────────────────────────────────────────────────────────────

// SignRequest holds inputs for signing an existing GPR.
type SignRequest struct {
	GPR        *gpr.GPR
	PrivKeyHex string
	// PubKeyHex is embedded in proof.public_key_hex when non-empty.
	PubKeyHex string
}

// Sign signs a GPR and returns the updated GPR with proof.signature set.
func Sign(req SignRequest) (*gpr.GPR, error) {
	if req.GPR == nil {
		return nil, fmt.Errorf("GPR is required")
	}
	return applySign(req.GPR, req.PrivKeyHex, req.PubKeyHex)
}

// ── Stamp ─────────────────────────────────────────────────────────────────────

// StampResult holds the output of a Stamp call.
type StampResult struct {
	GPR      *gpr.GPR
	Calendar string
	// OTSError is non-nil when OTS submission was requested but failed.
	OTSError error
}

// Stamp computes proof.timestamp.document_hash and optionally submits to OTS calendars.
func Stamp(g *gpr.GPR, submitOTS bool) (*StampResult, error) {
	if g == nil {
		return nil, fmt.Errorf("GPR is required")
	}
	if g.Proof.Signature == "" {
		return nil, fmt.Errorf("GPR has no signature — sign first")
	}
	return applyStamp(g, submitOTS)
}

// ── Upgrade ───────────────────────────────────────────────────────────────────

// UpgradeResult holds the output of an Upgrade call.
type UpgradeResult struct {
	GPR             *gpr.GPR
	Confirmed       bool   // false = Bitcoin confirmation not yet available
	AlreadyUpgraded bool   // true = GPR was already upgraded before this call
	Calendar        string // empty when Confirmed=false
}

// Upgrade fetches the completed Bitcoin proof from OTS calendars and embeds it.
// Returns Confirmed=false (no error) when the proof is not yet available.
func Upgrade(g *gpr.GPR) (*UpgradeResult, error) {
	if g == nil {
		return nil, fmt.Errorf("GPR is required")
	}
	if g.Proof.Timestamp == nil || g.Proof.Timestamp.DocumentHash == "" {
		return nil, fmt.Errorf("GPR has no OTS timestamp — run Stamp first")
	}
	if g.Proof.Timestamp.Upgraded {
		// Already upgraded — return unchanged, AlreadyUpgraded signals no new work was done.
		return &UpgradeResult{GPR: g, Confirmed: true, AlreadyUpgraded: true, Calendar: g.Proof.Timestamp.Calendar}, nil
	}
	if g.Proof.Timestamp.OTSData == "" {
		return nil, fmt.Errorf("GPR has no OTS data — stamp may have failed")
	}

	otsDataBytes, err := base64.StdEncoding.DecodeString(g.Proof.Timestamp.OTSData)
	if err != nil {
		return nil, fmt.Errorf("decode ots_data: %w", err)
	}

	otsClient := ots.New()
	proofBytes, calendar, confirmed, err := otsClient.UpgradeByHash(g.Proof.Timestamp.DocumentHash, otsDataBytes)
	if err != nil {
		return nil, fmt.Errorf("upgrade OTS proof: %w", err)
	}
	if !confirmed {
		return &UpgradeResult{GPR: g, Confirmed: false}, nil
	}

	record := *g.Proof.Timestamp
	record.OTSData = base64.StdEncoding.EncodeToString(proofBytes)
	record.Calendar = calendar
	record.Upgraded = true
	return &UpgradeResult{GPR: g.SetTimestamp(&record), Confirmed: true, Calendar: calendar}, nil
}

// ── internal helpers ──────────────────────────────────────────────────────────

func applySign(g *gpr.GPR, privKeyHex, pubKeyHex string) (*gpr.GPR, error) {
	privKey, err := signing.ParsePrivateKey(strings.TrimSpace(privKeyHex))
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	if pubKeyHex = strings.TrimSpace(pubKeyHex); pubKeyHex != "" {
		proof := g.Proof
		proof.PublicKeyHex = pubKeyHex
		g.Proof = proof
	}

	canonical, err := g.CanonicaliseForSigning()
	if err != nil {
		return nil, fmt.Errorf("canonicalise for signing: %w", err)
	}
	sig, err := signing.Sign(canonical, privKey)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return g.SetSignature(sig), nil
}

func applyStamp(g *gpr.GPR, submitOTS bool) (*StampResult, error) {
	canonical, err := g.CanonicaliseForTimestamp()
	if err != nil {
		return nil, fmt.Errorf("canonicalise for timestamp: %w", err)
	}
	sum := sha256.Sum256(canonical)
	docHash := "sha256:" + hex.EncodeToString(sum[:])

	record := &gpr.Timestamp{
		Type:         "OpenTimestamps",
		DocumentHash: docHash,
		Upgraded:     false,
	}

	result := &StampResult{}
	if submitOTS {
		otsClient := ots.New()
		otsResult, otsErr := otsClient.Submit(docHash)
		if otsErr != nil {
			result.OTSError = otsErr
		} else {
			record.Calendar = otsResult.Calendar
			record.SubmittedAt = otsResult.SubmittedAt.Format(time.RFC3339)
			record.OTSData = base64.StdEncoding.EncodeToString(otsResult.ProofBytes)
			result.Calendar = otsResult.Calendar
		}
	}

	result.GPR = g.SetTimestamp(record)
	return result, nil
}
