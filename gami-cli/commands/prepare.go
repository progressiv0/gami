package commands

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/progressiv0/gami/gami-core/gpr"
	"github.com/progressiv0/gami/gami-core/hash"
)

var prepareCmd = &cobra.Command{
	Use:   "prepare",
	Short: "Hash a file and build an unsigned GPR",
	Long: `Part 1 of 3 — builds the GPR structure and computes the file hash:

  1. SHA-256 of the file  → subject.file_hash

The output GPR has no signature and no timestamp.
Next step: gami sign --gpr <output> --key <private-key-file>`,
	RunE: runPrepare,
}

var (
	prepareFile     string
	prepareHash     string
	prepareKeyID    string
	prepareMetadata string
	prepareOutput   string
)

func init() {
	prepareCmd.Flags().StringVar(&prepareFile, "file", "", "Path to the file to anchor")
	prepareCmd.Flags().StringVar(&prepareHash, "hash", "", "Pre-computed SHA-256 hash (skips reading the file)")
	prepareCmd.Flags().StringVar(&prepareKeyID, "key-id", "", "DID key reference (e.g. did:web:example.org#key-1)")
	prepareCmd.Flags().StringVar(&prepareMetadata, "metadata", "", "Inline JSON metadata or path to a JSON file")
	prepareCmd.Flags().StringVar(&prepareOutput, "output", "", "Write GPR to this file (default: stdout)")

	_ = prepareCmd.MarkFlagRequired("key-id")
}

func runPrepare(cmd *cobra.Command, args []string) error {
	// 1. Determine file hash
	fileHash := prepareHash
	filename := ""

	if fileHash == "" {
		if prepareFile == "" {
			return fmt.Errorf("either --file or --hash is required")
		}
		logf("Hashing %s ...", prepareFile)
		var err error
		fileHash, err = hash.File(prepareFile)
		if err != nil {
			return fmt.Errorf("hash file: %w", err)
		}
		filename = prepareFile
		logf("file_hash: %s", fileHash)
	} else {
		if err := hash.Validate(fileHash); err != nil {
			return fmt.Errorf("invalid --hash: %w", err)
		}
	}

	// 2. Load metadata
	meta := map[string]string{}
	if prepareMetadata != "" {
		data := []byte(prepareMetadata)
		if prepareMetadata[0] != '{' {
			var err error
			data, err = os.ReadFile(prepareMetadata)
			if err != nil {
				return fmt.Errorf("read metadata file: %w", err)
			}
		}
		if err := json.Unmarshal(data, &meta); err != nil {
			return fmt.Errorf("parse metadata: %w", err)
		}
	}

	// 3. Build GPR
	g, err := gpr.Build(gpr.BuildRequest{
		FileHash: fileHash,
		Filename: filename,
		KeyID:    prepareKeyID,
		Metadata: meta,
	})
	if err != nil {
		return fmt.Errorf("build GPR: %w", err)
	}

	// 4. Output
	out, err := g.ToJSON()
	if err != nil {
		return fmt.Errorf("marshal GPR: %w", err)
	}

	if prepareOutput != "" {
		if err := os.WriteFile(prepareOutput, out, 0644); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
		logf("GPR written to %s", prepareOutput)
	} else {
		fmt.Println(string(out))
	}
	return nil
}
