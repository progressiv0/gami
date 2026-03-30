package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/progressiv0/gami/core/batch"
	"github.com/progressiv0/gami/core/ots"
	"github.com/progressiv0/gami/core/hash"
	"github.com/progressiv0/gami/core/signing"
)

var batchCmd = &cobra.Command{
	Use:   "batch",
	Short: "Anchor a collection of files from a directory or CSV manifest",
	Long: `Processes multiple files and anchors each with a signed GPR.

Adapters:
  filesystem   Walk a directory tree and hash every file
  csv          Read a manifest CSV (columns: path, hash, title, collection)

GPRs are written to --output as individual JSON files.
Progress is saved to --progress-file; use --resume to continue an interrupted run.`,
	RunE: runBatch,
}

var (
	batchAdapter     string
	batchPath        string
	batchManifest    string
	batchKeyPath     string
	batchKeyID       string
	batchInstitution string
	batchOutput      string
	batchProgressFile string
	batchResume      bool
	batchNoOTS       bool
)

func init() {
	batchCmd.Flags().StringVar(&batchAdapter, "adapter", "filesystem", "Adapter: filesystem, csv")
	batchCmd.Flags().StringVar(&batchPath, "path", "", "Root directory (filesystem adapter)")
	batchCmd.Flags().StringVar(&batchManifest, "manifest", "", "CSV manifest path (csv adapter)")
	batchCmd.Flags().StringVar(&batchKeyPath, "key", "", "Path to Ed25519 private key file")
	batchCmd.Flags().StringVar(&batchKeyID, "key-id", "", "DID key reference")
	batchCmd.Flags().StringVar(&batchInstitution, "institution", "", "Institution name")
	batchCmd.Flags().StringVar(&batchOutput, "output", "./gprs", "Directory to write GPR JSON files")
	batchCmd.Flags().StringVar(&batchProgressFile, "progress-file", ".gami-progress.json", "Progress log file")
	batchCmd.Flags().BoolVar(&batchResume, "resume", false, "Resume from a previous progress log")
	batchCmd.Flags().BoolVar(&batchNoOTS, "no-ots", false, "Skip OTS submission")

	_ = batchCmd.MarkFlagRequired("key")
	_ = batchCmd.MarkFlagRequired("key-id")
	_ = batchCmd.MarkFlagRequired("institution")
}

func runBatch(cmd *cobra.Command, args []string) error {
	// Load private key
	keyBytes, err := os.ReadFile(batchKeyPath)
	if err != nil {
		return fmt.Errorf("read key file: %w", err)
	}
	privKey, err := signing.ParsePrivateKey(string(keyBytes))
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}

	// Load or create progress tracker
	progress, err := batch.LoadProgress(batchProgressFile)
	if err != nil {
		return fmt.Errorf("load progress: %w", err)
	}
	if batchResume {
		logf("Resuming — %d files already processed", len(progress.Processed))
	} else if len(progress.Processed) > 0 && !batchResume {
		logf("Note: progress file exists with %d entries. Use --resume to skip them.", len(progress.Processed))
	}

	// Load entries from the chosen adapter
	var entries []batch.Entry
	switch batchAdapter {
	case "filesystem":
		if batchPath == "" {
			return fmt.Errorf("--path is required for the filesystem adapter")
		}
		logf("Scanning %s ...", batchPath)
		entries, err = batch.FilesystemAdapter(batchPath, progress)
	case "csv":
		if batchManifest == "" {
			return fmt.Errorf("--manifest is required for the csv adapter")
		}
		logf("Reading manifest %s ...", batchManifest)
		entries, err = batch.CSVAdapter(batchManifest, progress)
	default:
		return fmt.Errorf("unknown adapter %q — supported: filesystem, csv", batchAdapter)
	}
	if err != nil {
		return fmt.Errorf("load entries: %w", err)
	}

	logf("%d files to process", len(entries))
	if err := os.MkdirAll(batchOutput, 0755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	otsClient := ots.New()
	ok, failed := 0, 0

	for i, entry := range entries {
		g, err := batch.BuildAndSign(entry, batchInstitution, batchKeyID, privKey)
		if err != nil {
			logf("  [%d/%d] SKIP %s: %v", i+1, len(entries), entry.Filename, err)
			failed++
			continue
		}

		// Submit to OTS
		if !batchNoOTS {
			canonical, _ := g.Canonicalise("timestamp")
			otsHash := hash.Bytes(canonical)
			proof, otsErr := otsClient.Submit(otsHash)
			if otsErr != nil {
				logf("  Warning: OTS failed for %s: %v", entry.Filename, otsErr)
			} else {
				g = g.SetTimestampProof(proof)
			}
		}

		// Write GPR to output directory
		outPath := filepath.Join(batchOutput, sanitise(entry.Hash)+".gpr.json")
		data, err := g.ToJSON()
		if err != nil || os.WriteFile(outPath, data, 0644) != nil {
			logf("  [%d/%d] SKIP %s: failed to write GPR", i+1, len(entries), entry.Filename)
			failed++
			continue
		}

		if err := progress.Mark(entry.Hash); err != nil {
			logf("  Warning: could not update progress log: %v", err)
		}

		ok++
		if ok%100 == 0 || ok == len(entries) {
			logf("  %d / %d processed ...", ok, len(entries))
		}
	}

	fmt.Printf("\nBatch complete: %d anchored, %d failed\n", ok, failed)
	if failed > 0 {
		os.Exit(1)
	}
	return nil
}

// sanitise returns a filesystem-safe version of a hash string.
func sanitise(h string) string {
	if len(h) > 7 && h[:7] == "sha256:" {
		return h[7:]
	}
	return h
}
