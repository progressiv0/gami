// Package ots provides an OpenTimestamps calendar client. §5.3
package ots

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/progressiv0/go-opentimestamps/calendar"
	"github.com/progressiv0/go-opentimestamps/core"
)

// DefaultCalendars are the public OTS calendar servers operated by the OTS project.
var DefaultCalendars = []string{
	"https://alice.btc.calendar.opentimestamps.org",
	"https://bob.btc.calendar.opentimestamps.org",
	"https://finney.calendar.eternitywall.com",
}

// SubmitResult holds the raw response from a successful calendar submission.
type SubmitResult struct {
	Calendar    string    // URL of the calendar that responded
	SubmittedAt time.Time // time of submission
	ProofBytes  []byte    // raw binary .ots file content (incomplete, pending Bitcoin confirmation)
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
// Returns a SubmitResult with the raw .ots binary on the first successful calendar. §5.3
//
// The hash must be a hex string (with or without "sha256:" prefix).
func (c *Client) Submit(hashHex string) (*SubmitResult, error) {
	hashHex = strings.TrimPrefix(hashHex, "sha256:")
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		return nil, fmt.Errorf("decode hash: %w", err)
	}
	if len(hashBytes) != 32 {
		return nil, fmt.Errorf("expected 32-byte SHA-256 hash, got %d bytes", len(hashBytes))
	}

	var lastErr error
	for _, calURL := range c.Calendars {
		rc := calendar.NewRemoteCalendar(calURL)
		rc.Client = c.HTTPClient
		ts, err := rc.Submit(hashBytes, 0)
		if err != nil {
			lastErr = err
			continue
		}
		proofBytes, err := serializeTimestamp(ts)
		if err != nil {
			lastErr = err
			continue
		}
		return &SubmitResult{
			Calendar:    calURL,
			SubmittedAt: time.Now().UTC(),
			ProofBytes:  proofBytes,
		}, nil
	}
	return nil, fmt.Errorf("all %d calendars failed; last error: %w", len(c.Calendars), lastErr)
}

// UpgradeByHash queries calendar servers for a completed proof using the stored partial OTS data.
// hashHex is the document hash submitted during stamp (with or without "sha256:" prefix).
// otsDataBytes is the raw bytes of the partial OTS proof returned during Submit.
// Returns (proofBytes, calendar, confirmed, error). §5.3
//
// If not yet confirmed by any calendar, returns (nil, "", false, nil) — safe to retry later.
func (c *Client) UpgradeByHash(hashHex string, otsDataBytes []byte) ([]byte, string, bool, error) {
	hashHex = strings.TrimPrefix(hashHex, "sha256:")
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		return nil, "", false, fmt.Errorf("invalid hash hex: %w", err)
	}

	// Parse the stored partial timestamp. The calendar stores the proof under
	// the aggregation root (commitment), not the document hash, so we must
	// walk the tree to find the pending commitment and query with that.
	ctx := core.NewBytesDeserializationContext(otsDataBytes)
	ts, err := core.DeserializeTimestamp(ctx, hashBytes, 256)
	if err != nil {
		return nil, "", false, fmt.Errorf("parse ots_data: %w", err)
	}

	for _, calURL := range c.Calendars {
		rc := calendar.NewRemoteCalendar(calURL)
		rc.Client = c.HTTPClient
		changed, err := upgradeTimestamp(ts, rc)
		if err != nil || !changed {
			continue
		}
		proofBytes, err := serializeTimestamp(ts)
		if err != nil {
			continue
		}
		return proofBytes, calURL, true, nil
	}

	return nil, "", false, nil // no calendar has confirmed yet
}

// upgradeTimestamp walks ts, finds all PendingAttestation nodes, queries the
// calendar for each, and merges the results in-place.
// Returns true if any new attestation was obtained.
func upgradeTimestamp(ts *core.Timestamp, rc *calendar.RemoteCalendar) (bool, error) {
	changed := false
	var walk func(*core.Timestamp)
	walk = func(t *core.Timestamp) {
		for _, att := range t.Attestations {
			if _, ok := att.(*core.PendingAttestation); ok {
				upgraded, err := rc.GetTimestamp(t.Msg, 0)
				if err == nil {
					if mergeErr := t.Merge(upgraded); mergeErr == nil {
						changed = true
					}
				}
				break
			}
		}
		for _, entry := range t.Ops.Entries() {
			walk(entry.Stamp)
		}
	}
	walk(ts)
	return changed, nil
}

// serializeTimestamp converts a *core.Timestamp to the raw bytes returned by
// the calendar API, for storage in GPR.Proof.Timestamp.OTSData.
func serializeTimestamp(ts *core.Timestamp) ([]byte, error) {
	ctx := core.NewBytesSerializationContext()
	if err := ts.Serialize(ctx); err != nil {
		return nil, fmt.Errorf("serialize timestamp: %w", err)
	}
	return ctx.GetBytes(), nil
}
