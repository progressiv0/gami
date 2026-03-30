// Package hash provides SHA-256 file fingerprinting. §5.1
package hash

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"
)

const (
	Algorithm = "sha256"
	Prefix    = "sha256:"
)

// File computes the SHA-256 hash of a file at the given path.
// Returns a prefixed hex string: "sha256:<64 hex chars>".
func File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	return Reader(f)
}

// Reader computes the SHA-256 hash of data from an io.Reader.
func Reader(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", fmt.Errorf("hash data: %w", err)
	}
	return Prefix + hex.EncodeToString(h.Sum(nil)), nil
}

// Bytes computes the SHA-256 hash of a byte slice.
func Bytes(data []byte) string {
	h := sha256.Sum256(data)
	return Prefix + hex.EncodeToString(h[:])
}

// Validate checks that a hash string has the correct format.
func Validate(h string) error {
	if len(h) != 71 {
		return fmt.Errorf("invalid hash length: expected 71, got %d", len(h))
	}
	if h[:7] != Prefix {
		return fmt.Errorf("unsupported algorithm prefix in: %s", h[:7])
	}
	if _, err := hex.DecodeString(h[7:]); err != nil {
		return fmt.Errorf("invalid hex: %w", err)
	}
	return nil
}

// Hex strips the "sha256:" prefix and returns the raw hex string.
func Hex(h string) string {
	if len(h) > 7 && h[:7] == Prefix {
		return h[7:]
	}
	return h
}

// FileResult holds the outcome of hashing a single file.
type FileResult struct {
	Path string
	Hash string
	Err  error
}

// Files hashes multiple files concurrently and returns a map of path → hash. §5.1
func Files(paths []string) (map[string]string, error) {
	results := make(chan FileResult, len(paths))
	var wg sync.WaitGroup

	for _, path := range paths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			h, err := File(p)
			results <- FileResult{Path: p, Hash: h, Err: err}
		}(path)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	out := make(map[string]string, len(paths))
	for r := range results {
		if r.Err != nil {
			return nil, fmt.Errorf("hash %s: %w", r.Path, r.Err)
		}
		out[r.Path] = r.Hash
	}
	return out, nil
}
