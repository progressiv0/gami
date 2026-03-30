// Package signing provides Ed25519 key generation, signing, and verification. §5.2
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

const Prefix = "ed25519:"

// KeyPair holds an Ed25519 public and private key.
type KeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// Generate creates a new Ed25519 key pair. §UC-07
func Generate() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key pair: %w", err)
	}
	return &KeyPair{PublicKey: pub, PrivateKey: priv}, nil
}

// PublicKeyHex returns the hex-encoded public key.
func (kp *KeyPair) PublicKeyHex() string {
	return hex.EncodeToString(kp.PublicKey)
}

// PrivateKeyHex returns the hex-encoded private key.
func (kp *KeyPair) PrivateKeyHex() string {
	return hex.EncodeToString(kp.PrivateKey)
}

// Sign computes an Ed25519 signature over the SHA-256 hash of data.
// Returns a prefixed string: "ed25519:<hex>". §5.2
func Sign(data []byte, privateKey ed25519.PrivateKey) (string, error) {
	hash := sha256.Sum256(data)
	sig := ed25519.Sign(privateKey, hash[:])
	return Prefix + hex.EncodeToString(sig), nil
}

// Verify checks an Ed25519 signature against the SHA-256 hash of data. §5.7
func Verify(data []byte, signature string, publicKey ed25519.PublicKey) error {
	sig, err := DecodeSignature(signature)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(data)
	if !ed25519.Verify(publicKey, hash[:], sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// ParsePublicKey decodes a hex-encoded Ed25519 public key.
func ParsePublicKey(hexKey string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: expected %d bytes, got %d", ed25519.PublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
}

// ParsePrivateKey decodes a hex-encoded Ed25519 private key.
func ParsePrivateKey(hexKey string) (ed25519.PrivateKey, error) {
	hexKey = strings.TrimSpace(hexKey)
	b, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key length: expected %d bytes, got %d", ed25519.PrivateKeySize, len(b))
	}
	return ed25519.PrivateKey(b), nil
}

// DecodeSignature strips the "ed25519:" prefix and decodes the hex signature.
func DecodeSignature(sig string) ([]byte, error) {
	if !strings.HasPrefix(sig, Prefix) {
		return nil, fmt.Errorf("invalid signature prefix: expected %q", Prefix)
	}
	b, err := hex.DecodeString(strings.TrimPrefix(sig, Prefix))
	if err != nil {
		return nil, fmt.Errorf("decode signature hex: %w", err)
	}
	return b, nil
}
