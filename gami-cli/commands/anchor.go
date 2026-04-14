package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"authenticmemory.org/gami-core/hash"
	"authenticmemory.org/gami-core/service"
)

var anchorCmd = &cobra.Command{
	Use:   "anchor",
	Short: "Prepare, sign, and stamp a file in one step",
	Long: `Combines the prepare → sign → stamp pipeline into a single command.

  1. Hash the file                              (prepare)
  2. Sign the JCS-canonical document (Ed25519)  (sign)
  3. Submit the signed document hash to OTS     (stamp)

Run 'gami upgrade --gpr <output>' after ~1 hour to embed the Bitcoin proof.`,
	RunE: runAnchor,
}

var (
	anchorFile       string
	anchorHashFlag   string
	anchorKeyID      string
	anchorKeyPath    string
	anchorPubKeyPath string
	anchorMetadata   string
	anchorOutput     string
	anchorNoOTS      bool
)

func init() {
	anchorCmd.Flags().StringVar(&anchorFile, "file", "", "Path to the file to anchor")
	anchorCmd.Flags().StringVar(&anchorHashFlag, "hash", "", "Pre-computed SHA-256 hash (skips reading the file)")
	anchorCmd.Flags().StringVar(&anchorKeyID, "key-id", "", "DID key reference (e.g. did:web:example.org#key-1)")
	anchorCmd.Flags().StringVar(&anchorKeyPath, "key", "", "Path to Ed25519 private key file (hex)")
	anchorCmd.Flags().StringVar(&anchorPubKeyPath, "pub-key", "", "Path to Ed25519 public key file — embeds it in the GPR for offline verification")
	anchorCmd.Flags().StringVar(&anchorMetadata, "metadata", "", "Inline JSON metadata or path to a JSON file")
	anchorCmd.Flags().StringVar(&anchorOutput, "output", "", "Write GPR to this file (default: stdout)")
	anchorCmd.Flags().BoolVar(&anchorNoOTS, "no-ots", false, "Skip OTS submission (useful for testing)")

	_ = anchorCmd.MarkFlagRequired("key-id")
	_ = anchorCmd.MarkFlagRequired("key")
}

func runAnchor(cmd *cobra.Command, args []string) error {
	// ── Resolve file hash ─────────────────────────────────────────────────────

	fileHash := anchorHashFlag
	filename := ""

	if fileHash == "" {
		if anchorFile == "" {
			return fmt.Errorf("either --file or --hash is required")
		}
		logf("Hashing %s ...", anchorFile)
		var err error
		fileHash, err = hash.File(anchorFile)
		if err != nil {
			return fmt.Errorf("hash file: %w", err)
		}
		filename = anchorFile
		logf("file_hash: %s", fileHash)
	}

	// ── Load key material ─────────────────────────────────────────────────────

	keyBytes, err := os.ReadFile(anchorKeyPath)
	if err != nil {
		return fmt.Errorf("read key file: %w", err)
	}

	pubKeyHex := ""
	if anchorPubKeyPath != "" {
		pubBytes, err := os.ReadFile(anchorPubKeyPath)
		if err != nil {
			return fmt.Errorf("read pub key file: %w", err)
		}
		pubKeyHex = strings.TrimSpace(string(pubBytes))
	}

	// ── Parse metadata ────────────────────────────────────────────────────────

	meta := map[string]string{}
	if anchorMetadata != "" {
		data := []byte(anchorMetadata)
		if anchorMetadata[0] != '{' {
			data, err = os.ReadFile(anchorMetadata)
			if err != nil {
				return fmt.Errorf("read metadata file: %w", err)
			}
		}
		if err := json.Unmarshal(data, &meta); err != nil {
			return fmt.Errorf("parse metadata: %w", err)
		}
	}

	// ── Run pipeline ──────────────────────────────────────────────────────────

	result, err := service.Anchor(service.AnchorRequest{
		FileHash:   fileHash,
		Filename:   filename,
		KeyID:      anchorKeyID,
		PrivKeyHex: string(keyBytes),
		PubKeyHex:  pubKeyHex,
		Metadata:   meta,
		SubmitOTS:  !anchorNoOTS,
	})
	if err != nil {
		return err
	}

	logf("Signed with key %s", result.GPR.Proof.KeyID)
	if result.GPR.Proof.Timestamp != nil {
		logf("document_hash (JCS): %s", result.GPR.Proof.Timestamp.DocumentHash)
	}
	if result.OTSError != nil {
		logf("Warning: OTS submission failed: %v", result.OTSError)
		logf("GPR is signed but not yet timestamped. Re-run 'gami stamp' to retry.")
	} else if result.Calendar != "" {
		logf("OTS proof submitted via %s (Bitcoin confirmation pending ~1 hour)", result.Calendar)
		logf("Run 'gami upgrade --gpr <output>' after ~1 hour to embed the confirmed proof.")
	}

	// ── Output ────────────────────────────────────────────────────────────────

	out, err := result.GPR.ToJSON()
	if err != nil {
		return fmt.Errorf("marshal GPR: %w", err)
	}

	if anchorOutput != "" {
		if err := os.WriteFile(anchorOutput, out, 0644); err != nil {
			return fmt.Errorf("write GPR: %w", err)
		}
		logf("GPR written to %s", anchorOutput)
	} else {
		fmt.Println(string(out))
	}
	return nil
}
