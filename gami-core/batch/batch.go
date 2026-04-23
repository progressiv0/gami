// Package batch provides adapters for reading file collections and tracking progress. §5.6
package batch

import (
	"crypto/ed25519"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/progressiv0/gami/gami-core/gpr"
	"github.com/progressiv0/gami/gami-core/hash"
	"github.com/progressiv0/gami/gami-core/signing"
)

// Entry is a single file ready for GPR construction.
type Entry struct {
	Path     string
	Hash     string
	Filename string
	Metadata map[string]string
}

// Progress tracks which file hashes have already been anchored. §5.6
type Progress struct {
	Path      string          `json:"-"`
	Processed map[string]bool `json:"processed"`
	UpdatedAt time.Time       `json:"updatedAt"`
}

// LoadProgress loads a progress file from disk.
// If the file does not exist, an empty Progress is returned — not an error.
func LoadProgress(path string) (*Progress, error) {
	p := &Progress{Path: path, Processed: make(map[string]bool)}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return p, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read progress file: %w", err)
	}
	if err := json.Unmarshal(data, p); err != nil {
		return nil, fmt.Errorf("parse progress file: %w", err)
	}
	p.Path = path
	return p, nil
}

// Mark records a file hash as processed and persists the progress file. §5.6
func (p *Progress) Mark(fileHash string) error {
	p.Processed[fileHash] = true
	p.UpdatedAt = time.Now()
	return p.save()
}

// IsDone returns true if the hash has already been processed.
func (p *Progress) IsDone(fileHash string) bool {
	return p.Processed[fileHash]
}

func (p *Progress) save() error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p.Path, data, 0600)
}

// FilesystemAdapter walks a directory tree and returns an Entry for each file. §5.6
// Files whose hash is already in progress are skipped.
func FilesystemAdapter(root string, progress *Progress) ([]Entry, error) {
	var entries []Entry

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		fileHash, err := hash.File(path)
		if err != nil {
			return fmt.Errorf("hash %s: %w", path, err)
		}
		if progress != nil && progress.IsDone(fileHash) {
			return nil
		}

		entries = append(entries, Entry{
			Path:     path,
			Hash:     fileHash,
			Filename: d.Name(),
		})
		return nil
	})

	return entries, err
}

// CSVAdapter reads a manifest CSV with header row. §5.6
// Supported columns: path, hash, title, collection, classificationCode.
// If "hash" is absent or empty, the file at "path" is hashed automatically.
func CSVAdapter(manifestPath string, progress *Progress) ([]Entry, error) {
	f, err := os.Open(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("open manifest: %w", err)
	}
	defer f.Close()

	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return nil, fmt.Errorf("read CSV: %w", err)
	}
	if len(records) < 2 {
		return nil, fmt.Errorf("manifest has no data rows")
	}

	// Build column index from header
	col := make(map[string]int)
	for i, h := range records[0] {
		col[h] = i
	}

	get := func(row []string, name string) string {
		if i, ok := col[name]; ok && i < len(row) {
			return row[i]
		}
		return ""
	}

	var entries []Entry
	for lineNum, row := range records[1:] {
		filePath := get(row, "path")
		fileHash := get(row, "hash")

		if fileHash == "" {
			if filePath == "" {
				return nil, fmt.Errorf("line %d: both path and hash are empty", lineNum+2)
			}
			fileHash, err = hash.File(filePath)
			if err != nil {
				return nil, fmt.Errorf("line %d: hash %s: %w", lineNum+2, filePath, err)
			}
		}

		if progress != nil && progress.IsDone(fileHash) {
			continue
		}

		entries = append(entries, Entry{
			Path:     filePath,
			Hash:     fileHash,
			Filename: filepath.Base(filePath),
			Metadata: map[string]string{
				"title":              get(row, "title"),
				"collection":         get(row, "collection"),
				"classificationCode": get(row, "classificationCode"),
			},
		})
	}
	return entries, nil
}

// BuildAndSign constructs a signed GPR for a batch entry. §UC-03
// The Ed25519 signature covers JCS(document with proof.signature and proof.timestamp absent).
func BuildAndSign(entry Entry, keyID string, privKey ed25519.PrivateKey) (*gpr.GPR, error) {
	g, err := gpr.Build(gpr.BuildRequest{
		FileHash: entry.Hash,
		Filename: entry.Filename,
		KeyID:    keyID,
		Metadata: entry.Metadata,
	})
	if err != nil {
		return nil, fmt.Errorf("build GPR: %w", err)
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
