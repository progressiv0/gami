// Package gpr provides GAMI Proof Record construction and validation. §3.1, §5.2
package gpr

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const (
	ContextURL = "https://authenticmemory.org/schema/v1"
	TypeName   = "gami-proof"
	SchemaV1   = "v1"
)

// GPR is a GAMI Proof Record — the self-contained unit of evidence. §3.1
type GPR struct {
	Context string  `json:"@context"`
	Type    string  `json:"type"`
	Schema  string  `json:"schema"`
	ID      string  `json:"id"`
	Subject Subject `json:"subject"`
	Proof   Proof   `json:"proof"`
	Parent  *string `json:"parent"`
}

// Subject holds the file hash and metadata for the anchored content.
type Subject struct {
	Filename string            `json:"filename,omitempty"`
	FileHash string            `json:"file_hash"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Proof holds all cryptographic evidence: signer identity, signature, and optional timestamp.
type Proof struct {
	Created      string     `json:"created"`
	KeyID        string     `json:"key_id"`
	PublicKeyHex string     `json:"public_key_hex,omitempty"` // embedded for offline/resilience verification
	Signature    string     `json:"signature,omitempty"`
	Timestamp    *Timestamp `json:"timestamp,omitempty"`
}

// Timestamp holds the OpenTimestamps proof for the signed document. §5.3
type Timestamp struct {
	Type         string `json:"type"`
	DocumentHash string `json:"document_hash"` // SHA-256 of JCS(document including proof.signature)
	Calendar     string `json:"calendar,omitempty"`
	SubmittedAt  string `json:"submitted_at,omitempty"`
	OTSData      string `json:"ots_data,omitempty"` // base64-encoded raw .ots binary
	Upgraded     bool   `json:"upgraded"`           // true once Bitcoin confirmation received
}

// BuildRequest holds all inputs needed to construct a new GPR.
type BuildRequest struct {
	FileHash     string
	Filename     string
	KeyID        string
	PublicKeyHex string            // optional: embed public key for offline verification
	Metadata     map[string]string // open key/value metadata
	ParentID     *string
}

// Build constructs a new unsigned GPR. §5.2
//
// The GPR has no signature and no timestamp; run 'gami sign' then 'gami stamp'.
// Signing target: JCS(document with proof.signature and proof.timestamp absent).
// Timestamp target: JCS(document with proof.signature present, proof.timestamp absent).
func Build(req BuildRequest) (*GPR, error) {
	if req.FileHash == "" {
		return nil, fmt.Errorf("file hash is required")
	}
	if req.KeyID == "" {
		return nil, fmt.Errorf("key ID is required")
	}

	meta := make(map[string]string, len(req.Metadata))
	for k, v := range req.Metadata {
		meta[k] = v
	}

	return &GPR{
		Context: ContextURL,
		Type:    TypeName,
		Schema:  SchemaV1,
		ID:      "urn:uuid:" + uuid.New().String(),
		Subject: Subject{
			Filename: req.Filename,
			FileHash: req.FileHash,
			Metadata: meta,
		},
		Proof: Proof{
			Created:      time.Now().UTC().Format(time.RFC3339),
			KeyID:        req.KeyID,
			PublicKeyHex: req.PublicKeyHex,
		},
		Parent: req.ParentID,
	}, nil
}

// SetSignature returns a copy of the GPR with proof.signature set. §5.2
func (g *GPR) SetSignature(sig string) *GPR {
	c := *g
	c.Proof.Signature = sig
	return &c
}

// SetTimestamp returns a copy of the GPR with proof.timestamp set. §5.3
func (g *GPR) SetTimestamp(ts *Timestamp) *GPR {
	c := *g
	c.Proof.Timestamp = ts
	return &c
}

// WithParent returns a copy of the GPR linked to a parent GPR ID. §UC-06
func (g *GPR) WithParent(parentID string) *GPR {
	c := *g
	c.Parent = &parentID
	return &c
}

// Validate checks that all required fields are present and valid.
func Validate(g *GPR) error {
	if g.ID == "" {
		return fmt.Errorf("missing id")
	}
	if g.Subject.FileHash == "" {
		return fmt.Errorf("missing subject.file_hash")
	}
	if g.Proof.KeyID == "" {
		return fmt.Errorf("missing proof.key_id")
	}
	if g.Proof.Signature == "" {
		return fmt.Errorf("missing proof.signature")
	}
	return nil
}

// ToJSON marshals the GPR to indented JSON.
func (g *GPR) ToJSON() ([]byte, error) {
	return json.MarshalIndent(g, "", "  ")
}

// FromJSON parses a GPR from JSON bytes.
func FromJSON(data []byte) (*GPR, error) {
	var g GPR
	if err := json.Unmarshal(data, &g); err != nil {
		return nil, fmt.Errorf("parse GPR: %w", err)
	}
	return &g, nil
}
