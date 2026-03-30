package commands

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"authenticmemory.org/gami-core/gpr"
	"authenticmemory.org/gami-core/hash"
	"authenticmemory.org/gami-core/ots"
	"authenticmemory.org/gami-core/signing"
)

var anchorCmd = &cobra.Command{
	Use:   "anchor",
	Short: "Hash a file, build a GPR, sign it, and submit for Bitcoin anchoring",
	Long: `Anchors a file by:
  1. Computing its SHA-256 hash locally (file never leaves this machine)
  2. Building a GAMI Proof Record (GPR)
  3. Signing the GPR with your Ed25519 private key
  4. Submitting the signed GPR hash to OpenTimestamps calendar servers

The resulting GPR is written to --output (or stdout).
Bitcoin confirmation takes ~1 hour. Run 'gami upgrade' on the GPR later
to embed the final OTS proof.`,
	RunE: runAnchor,
}

var (
	anchorFile        string
	anchorHash        string
	anchorKeyPath     string
	anchorPubKeyPath  string
	anchorKeyID       string
	anchorInstitution string
	anchorMetadata    string
	anchorOutput      string
	anchorNoOTS       bool
)

func init() {
	anchorCmd.Flags().StringVar(&anchorFile, "file", "", "Path to the file to anchor")
	anchorCmd.Flags().StringVar(&anchorHash, "hash", "", "Pre-computed SHA-256 hash (skips reading the file)")
	anchorCmd.Flags().StringVar(&anchorKeyPath, "key", "", "Path to Ed25519 private key file (hex)")
	anchorCmd.Flags().StringVar(&anchorPubKeyPath, "pub-key", "", "Path to Ed25519 public key file to embed in GPR (enables offline verification)")
	anchorCmd.Flags().StringVar(&anchorKeyID, "key-id", "", "DID key reference (e.g. did:web:example.org#key-2026)")
	anchorCmd.Flags().StringVar(&anchorInstitution, "institution", "", "Institution name")
	anchorCmd.Flags().StringVar(&anchorMetadata, "metadata", "", "Path to JSON metadata file or inline JSON string")
	anchorCmd.Flags().StringVar(&anchorOutput, "output", "", "Write GPR to this file (default: stdout)")
	anchorCmd.Flags().BoolVar(&anchorNoOTS, "no-ots", false, "Skip OTS submission (useful for testing)")

	_ = anchorCmd.MarkFlagRequired("key")
	_ = anchorCmd.MarkFlagRequired("key-id")
	_ = anchorCmd.MarkFlagRequired("institution")
}

func runAnchor(cmd *cobra.Command, args []string) error {
	// 1. Determine file hash
	fileHash := anchorHash
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
		logf("Hash: %s", fileHash)
	} else {
		if err := hash.Validate(fileHash); err != nil {
			return fmt.Errorf("invalid --hash: %w", err)
		}
	}

	// 2. Load private key
	keyBytes, err := os.ReadFile(anchorKeyPath)
	if err != nil {
		return fmt.Errorf("read key file: %w", err)
	}
	privKey, err := signing.ParsePrivateKey(string(keyBytes))
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}

	// 2b. Load public key for embedding (optional)
	var pubKeyHex string
	if anchorPubKeyPath != "" {
		pubBytes, err := os.ReadFile(anchorPubKeyPath)
		if err != nil {
			return fmt.Errorf("read pub key file: %w", err)
		}
		pubKeyHex = string(pubBytes)
	}

	// 3. Load metadata (optional)
	meta := gpr.PublicMetadata{}
	if anchorMetadata != "" {
		data := []byte(anchorMetadata)
		if anchorMetadata[0] != '{' {
			// treat as file path
			data, err = os.ReadFile(anchorMetadata)
			if err != nil {
				return fmt.Errorf("read metadata file: %w", err)
			}
		}
		if err := json.Unmarshal(data, &meta); err != nil {
			return fmt.Errorf("parse metadata: %w", err)
		}
	}

	// 4. Build GPR
	g, err := gpr.Build(gpr.BuildRequest{
		FileHash:        fileHash,
		Filename:        filename,
		InstitutionName: anchorInstitution,
		KeyID:           anchorKeyID,
		PublicKeyHex:    pubKeyHex,
		Metadata:        meta,
	})
	if err != nil {
		return fmt.Errorf("build GPR: %w", err)
	}

	// 5. Canonicalise and sign
	canonical, err := g.Canonicalise("signature", "timestamp")
	if err != nil {
		return fmt.Errorf("canonicalise GPR: %w", err)
	}
	sig, err := signing.Sign(canonical, privKey)
	if err != nil {
		return fmt.Errorf("sign GPR: %w", err)
	}
	g = g.SetSignature(sig)
	logf("GPR signed with key %s", anchorKeyID)

	// 6. Submit to OpenTimestamps
	if !anchorNoOTS {
		logf("Submitting to OpenTimestamps ...")
		otsClient := ots.New()
		// Hash the signed GPR (without timestamp field) for OTS submission
		canonical2, err := g.Canonicalise("timestamp")
		if err != nil {
			return fmt.Errorf("canonicalise for OTS: %w", err)
		}
		otsHash := hash.Bytes(canonical2)
		proof, err := otsClient.Submit(otsHash)
		if err != nil {
			logf("Warning: OTS submission failed: %v", err)
			logf("GPR is signed but not yet timestamped. Re-run with the saved GPR to retry.")
		} else {
			g = g.SetTimestampProof(proof)
			logf("OTS proof submitted (Bitcoin confirmation pending ~1 hour)")
		}
	}

	// 7. Output
	out, err := g.ToJSON()
	if err != nil {
		return fmt.Errorf("marshal GPR: %w", err)
	}

	if anchorOutput != "" {
		if err := os.WriteFile(anchorOutput, out, 0644); err != nil {
			return fmt.Errorf("write output file: %w", err)
		}
		logf("GPR written to %s", anchorOutput)
	} else {
		fmt.Println(string(out))
	}
	return nil
}

// logf writes a status message to stderr.
func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}
