// Package config loads server configuration from environment variables.
package config

import (
	"fmt"
	"os"
	"strings"
)

// Config holds the API server configuration.
type Config struct {
	// Port is the TCP port the server listens on (default: "8080").
	Port string

	// KeyID is the DID key reference used when signing, e.g. "did:web:example.org#key-1".
	// Read from GAMI_KEY_ID.
	KeyID string

	// PrivKeyHex is the hex-encoded Ed25519 private key.
	// Read from GAMI_PRIVATE_KEY.
	// Never exposed via the API.
	PrivKeyHex string

	// PubKeyHex is the hex-encoded Ed25519 public key.
	// Read from GAMI_PUBLIC_KEY.
	// When set it is embedded in every GPR for offline verification.
	PubKeyHex string
}

// Load reads configuration from environment variables.
// Returns an error if required variables are missing.
func Load() (*Config, error) {
	cfg := &Config{
		Port:       env("PORT", "8080"),
		KeyID:      os.Getenv("GAMI_KEY_ID"),
		PrivKeyHex: strings.TrimSpace(os.Getenv("GAMI_PRIVATE_KEY")),
		PubKeyHex:  strings.TrimSpace(os.Getenv("GAMI_PUBLIC_KEY")),
	}

	// Private key and key ID are required for any signing operation.
	// Allow the server to start without them; signing endpoints will return 503.
	return cfg, nil
}

// CanSign returns true if the server has key material loaded.
func (c *Config) CanSign() error {
	if c.KeyID == "" {
		return fmt.Errorf("GAMI_KEY_ID is not set")
	}
	if c.PrivKeyHex == "" {
		return fmt.Errorf("GAMI_PRIVATE_KEY is not set")
	}
	return nil
}

func env(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
