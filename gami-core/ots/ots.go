// Package ots provides an OpenTimestamps calendar client. §5.3
package ots

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultCalendars are the public OTS calendar servers operated by the OTS project.
var DefaultCalendars = []string{
	"https://alice.btc.calendar.opentimestamps.org",
	"https://bob.btc.calendar.opentimestamps.org",
	"https://finney.calendar.eternitywall.com",
}

// Client submits hashes to OTS calendar servers and retrieves proofs.
type Client struct {
	Calendars  []string
	HTTPClient *http.Client
}

// New returns a Client with default calendars and a 30-second timeout.
func New() *Client {
	return &Client{
		Calendars:  DefaultCalendars,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// Submit sends a SHA-256 hash to the configured OTS calendar servers.
// Returns a base64-encoded incomplete OTS proof blob on the first success. §5.3
//
// The hash must be a hex string (with or without "sha256:" prefix).
func (c *Client) Submit(hashHex string) (string, error) {
	hashHex = strings.TrimPrefix(hashHex, "sha256:")
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		return "", fmt.Errorf("decode hash: %w", err)
	}
	if len(hashBytes) != 32 {
		return "", fmt.Errorf("expected 32-byte SHA-256 hash, got %d bytes", len(hashBytes))
	}

	var lastErr error
	for _, calendar := range c.Calendars {
		proof, err := c.submitToCalendar(calendar, hashBytes)
		if err != nil {
			lastErr = err
			continue
		}
		return base64.StdEncoding.EncodeToString(proof), nil
	}
	return "", fmt.Errorf("all %d calendars failed; last error: %w", len(c.Calendars), lastErr)
}

func (c *Client) submitToCalendar(calendar string, hashBytes []byte) ([]byte, error) {
	url := strings.TrimRight(calendar, "/") + "/digest"
	resp, err := c.HTTPClient.Post(url, "application/octet-stream", bytes.NewReader(hashBytes))
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("calendar %s returned %d: %s", calendar, resp.StatusCode, string(body))
	}
	return io.ReadAll(resp.Body)
}

// Upgrade attempts to complete an incomplete OTS proof by querying calendar servers
// for a Bitcoin block confirmation. Returns (proof, confirmed, error). §5.3
//
// If not yet confirmed, returns (originalProof, false, nil) — safe to retry later.
func (c *Client) Upgrade(incompleteProofB64 string) (string, bool, error) {
	proofBytes, err := base64.StdEncoding.DecodeString(incompleteProofB64)
	if err != nil {
		return "", false, fmt.Errorf("decode proof: %w", err)
	}

	for _, calendar := range c.Calendars {
		upgraded, confirmed, err := c.upgradeFromCalendar(calendar, proofBytes)
		if err != nil {
			continue
		}
		if confirmed {
			return base64.StdEncoding.EncodeToString(upgraded), true, nil
		}
	}
	// Not yet confirmed in any calendar — safe to return original and retry later
	return incompleteProofB64, false, nil
}

func (c *Client) upgradeFromCalendar(calendar string, proof []byte) ([]byte, bool, error) {
	// The commitment is the first 32 bytes of the proof body (after the OTS magic header).
	// A full implementation parses the OTS binary format; this uses the first 32 bytes
	// as an approximation for the calendar query.
	if len(proof) < 32 {
		return nil, false, fmt.Errorf("proof too short")
	}
	commitment := hex.EncodeToString(proof[:32])
	url := strings.TrimRight(calendar, "/") + "/timestamp/" + commitment

	resp, err := c.HTTPClient.Get(url)
	if err != nil {
		return nil, false, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil // pending confirmation
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("calendar returned %d", resp.StatusCode)
	}

	upgraded, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, err
	}
	return upgraded, true, nil
}
