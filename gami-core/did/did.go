// Package did provides DID:web document resolution and key extraction. §5.4
package did

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Document represents a DID:web document. §5.4
type Document struct {
	Context            any                  `json:"@context"`
	ID                 string               `json:"id"`
	VerificationMethod []VerificationMethod `json:"verificationMethod"`
	Authentication     []any                `json:"authentication,omitempty"`
}

// VerificationMethod represents a key entry in a DID document.
type VerificationMethod struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	Controller         string `json:"controller"`
	PublicKeyHex       string `json:"publicKeyHex,omitempty"`
	PublicKeyMultibase string `json:"publicKeyMultibase,omitempty"`
}

// ResolveResult holds a resolved DID document and whether it came from the archive.
type ResolveResult struct {
	Document    *Document
	FromArchive bool // true if live resolution failed and archive was used §5.4
}

// Resolver fetches and parses DID:web documents. §5.4
type Resolver struct {
	HTTPClient *http.Client
	// Archive is an optional fallback returning a cached DID document. §5.5
	Archive func(did string) (*Document, error)
}

// New returns a Resolver with a 10-second timeout.
func New() *Resolver {
	return &Resolver{
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// Resolve fetches the DID document for a did:web identifier. §5.4
// Falls back to the Archive function if live resolution fails.
func (r *Resolver) Resolve(didStr string) (*ResolveResult, error) {
	// Strip key fragment for URL construction
	bare := didStr
	if idx := strings.Index(bare, "#"); idx != -1 {
		bare = bare[:idx]
	}

	url, err := toURL(bare)
	if err != nil {
		return nil, err
	}

	doc, err := r.fetch(url)
	if err == nil {
		return &ResolveResult{Document: doc, FromArchive: false}, nil
	}
	liveErr := err

	// Fallback to archive §5.4
	if r.Archive != nil {
		archived, archErr := r.Archive(bare)
		if archErr == nil {
			return &ResolveResult{Document: archived, FromArchive: true}, nil
		}
	}
	return nil, fmt.Errorf("resolve %s: live failed (%v), no usable archive", didStr, liveErr)
}

// PublicKeyHex returns the publicKeyHex for a key ID within a document. §5.4
func PublicKeyHex(doc *Document, keyID string) (string, error) {
	for _, vm := range doc.VerificationMethod {
		if vm.ID == keyID {
			if vm.PublicKeyHex != "" {
				return vm.PublicKeyHex, nil
			}
			return "", fmt.Errorf("key %s has no publicKeyHex", keyID)
		}
	}
	return "", fmt.Errorf("key ID %q not found in DID document", keyID)
}

func (r *Resolver) fetch(url string) (*Document, error) {
	resp, err := r.HTTPClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s returned %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var doc Document
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse DID document: %w", err)
	}
	return &doc, nil
}

// toURL converts a bare did:web identifier to its HTTPS well-known URL.
func toURL(didStr string) (string, error) {
	if !strings.HasPrefix(didStr, "did:web:") {
		return "", fmt.Errorf("not a did:web identifier: %s", didStr)
	}
	host := strings.TrimPrefix(didStr, "did:web:")
	// Colons after the host encode path segments
	host = strings.ReplaceAll(host, ":", "/")
	return "https://" + host + "/.well-known/did.json", nil
}
