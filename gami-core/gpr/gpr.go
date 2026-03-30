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
	Context          string      `json:"@context"`
	Type             string      `json:"type"`
	Schema           string      `json:"schema"`
	ID               string      `json:"id"`
	Subject          Subject     `json:"subject"`
	Institution      Institution `json:"institution"`
	Metadata         Metadata    `json:"metadata"`
	Parent           *string     `json:"parent"`
	Canonicalization string      `json:"canonicalization"`
	Signature        string      `json:"signature,omitempty"`
	Timestamp        *Timestamp  `json:"timestamp,omitempty"`
}

// Subject identifies the file being anchored.
type Subject struct {
	Hash     string `json:"hash"`
	Filename string `json:"filename,omitempty"`
}

// Institution identifies the signing institution and its key.
type Institution struct {
	Name         string `json:"name"`
	KeyID        string `json:"key_id"`
	PublicKeyHex string `json:"public_key_hex,omitempty"` // embedded for offline/resilience verification
}

// Metadata holds public and optionally a private metadata hash.
type Metadata struct {
	Public      PublicMetadata `json:"public"`
	PrivateHash string         `json:"private_hash,omitempty"`
}

// PublicMetadata contains descriptive fields recorded at anchoring time.
type PublicMetadata struct {
	Title              string            `json:"title,omitempty"`
	Collection         string            `json:"collection,omitempty"`
	ClassificationCode string            `json:"classificationCode,omitempty"`
	DateAnchored       string            `json:"dateAnchored,omitempty"`
	Extra              map[string]string `json:"extra,omitempty"`
}

// Timestamp holds the OTS proof and anchoring method.
type Timestamp struct {
	Method string `json:"method"`
	Proof  string `json:"proof,omitempty"`
}

// BuildRequest holds all inputs needed to construct a new GPR.
type BuildRequest struct {
	FileHash        string
	Filename        string
	InstitutionName string
	KeyID           string
	PublicKeyHex    string // optional: embed public key for offline verification
	Metadata        PublicMetadata
	PrivateHash     string
	ParentID        *string
}

// Build constructs a new unsigned GPR without a timestamp proof. §5.2
func Build(req BuildRequest) (*GPR, error) {
	if req.FileHash == "" {
		return nil, fmt.Errorf("file hash is required")
	}
	if req.InstitutionName == "" {
		return nil, fmt.Errorf("institution name is required")
	}
	if req.KeyID == "" {
		return nil, fmt.Errorf("key ID is required")
	}

	req.Metadata.DateAnchored = time.Now().UTC().Format(time.RFC3339)

	return &GPR{
		Context: ContextURL,
		Type:    TypeName,
		Schema:  SchemaV1,
		ID:      "urn:uuid:" + uuid.New().String(),
		Subject: Subject{
			Hash:     req.FileHash,
			Filename: req.Filename,
		},
		Institution: Institution{
			Name:         req.InstitutionName,
			KeyID:        req.KeyID,
			PublicKeyHex: req.PublicKeyHex,
		},
		Metadata: Metadata{
			Public:      req.Metadata,
			PrivateHash: req.PrivateHash,
		},
		Parent:           req.ParentID,
		Canonicalization: "JCS",
	}, nil
}

// SetSignature returns a copy of the GPR with the signature field set. §5.2
func (g *GPR) SetSignature(sig string) *GPR {
	c := *g
	c.Signature = sig
	return &c
}

// SetTimestampProof returns a copy of the GPR with the OTS proof inserted. §5.3
func (g *GPR) SetTimestampProof(proof string) *GPR {
	c := *g
	c.Timestamp = &Timestamp{Method: "opentimestamps", Proof: proof}
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
	if g.Subject.Hash == "" {
		return fmt.Errorf("missing subject.hash")
	}
	if g.Institution.Name == "" {
		return fmt.Errorf("missing institution.name")
	}
	if g.Institution.KeyID == "" {
		return fmt.Errorf("missing institution.key_id")
	}
	if g.Signature == "" {
		return fmt.Errorf("missing signature")
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
