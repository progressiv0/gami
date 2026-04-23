package commands

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/progressiv0/gami/gami-core/gpr"
	"github.com/progressiv0/gami/gami-core/service"
)

var stampCmd = &cobra.Command{
	Use:   "stamp",
	Short: "Submit a signed GPR to OpenTimestamps for Bitcoin anchoring",
	Long: `Part 3 of 3 — computes a hash over the signed document and submits it to OTS calendars:

  1. JCS-canonicalise document (proof.signature present, proof.timestamp absent)
  2. SHA-256 of the canonical document  → proof.timestamp.document_hash
  3. Submit hash to OTS calendar        → proof.timestamp.ots_data (raw .ots binary, base64)
  4. Store calendar URL, submission time, and upgrade status

Bitcoin block confirmation takes ~1 hour.
Run 'gami upgrade --gpr <file>' later to embed the confirmed proof.`,
	RunE: runStamp,
}

var (
	stampGPRPath    string
	stampOutputPath string
	stampNoOTS      bool
)

func init() {
	stampCmd.Flags().StringVar(&stampGPRPath, "gpr", "", "Path to the signed GPR file")
	stampCmd.Flags().StringVar(&stampOutputPath, "output", "", "Write stamped GPR to this file (default: overwrite input)")
	stampCmd.Flags().BoolVar(&stampNoOTS, "no-ots", false, "Skip OTS submission (useful for testing)")

	_ = stampCmd.MarkFlagRequired("gpr")
}

func runStamp(cmd *cobra.Command, args []string) error {
	rawGPR, err := os.ReadFile(stampGPRPath)
	if err != nil {
		return fmt.Errorf("read GPR: %w", err)
	}
	g, err := gpr.FromJSON(rawGPR)
	if err != nil {
		return fmt.Errorf("parse GPR: %w", err)
	}

	result, err := service.Stamp(g, !stampNoOTS)
	if err != nil {
		return err
	}

	if result.GPR.Proof.Timestamp != nil {
		logf("document_hash (JCS): %s", result.GPR.Proof.Timestamp.DocumentHash)
	}
	if result.OTSError != nil {
		logf("Warning: OTS submission failed: %v", result.OTSError)
		logf("GPR is signed but not yet timestamped. Re-run 'gami stamp' to retry.")
	} else if result.Calendar != "" {
		logf("OTS proof submitted via %s (Bitcoin confirmation pending ~1 hour)", result.Calendar)
		logf("Run 'gami upgrade --gpr %s' after ~1 hour to embed the confirmed proof.", stampGPRPath)
	}

	out, err := result.GPR.ToJSON()
	if err != nil {
		return fmt.Errorf("marshal GPR: %w", err)
	}

	outPath := stampOutputPath
	if outPath == "" {
		outPath = stampGPRPath
	}
	if err := os.WriteFile(outPath, out, 0644); err != nil {
		return fmt.Errorf("write GPR: %w", err)
	}
	logf("GPR written to %s", outPath)
	return nil
}
