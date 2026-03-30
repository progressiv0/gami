package commands

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"authenticmemory.org/gami-core/gpr"
	"authenticmemory.org/gami-core/ots"
)

var upgradeCmd = &cobra.Command{
	Use:   "upgrade",
	Short: "Fetch a completed OTS proof from calendar servers and embed it in a GPR",
	Long: `Contacts OpenTimestamps calendar servers to retrieve a completed Bitcoin proof
for a previously anchored GPR. Bitcoin block confirmation typically takes ~1 hour.

If the proof is not yet confirmed, the GPR is left unchanged and a message is printed.
Re-run upgrade later until confirmation is received.`,
	RunE: runUpgrade,
}

var (
	upgradeGPRPath    string
	upgradeOutputPath string
)

func init() {
	upgradeCmd.Flags().StringVar(&upgradeGPRPath, "gpr", "", "Path to the GPR file to upgrade")
	upgradeCmd.Flags().StringVar(&upgradeOutputPath, "output", "", "Write upgraded GPR to this file (default: overwrite input)")
	_ = upgradeCmd.MarkFlagRequired("gpr")
}

func runUpgrade(cmd *cobra.Command, args []string) error {
	// 1. Load GPR
	data, err := os.ReadFile(upgradeGPRPath)
	if err != nil {
		return fmt.Errorf("read GPR: %w", err)
	}
	g, err := gpr.FromJSON(data)
	if err != nil {
		return fmt.Errorf("parse GPR: %w", err)
	}

	// 2. Check there is an existing (incomplete) proof to upgrade
	if g.Timestamp == nil || g.Timestamp.Proof == "" {
		return fmt.Errorf("GPR has no OTS proof to upgrade — run 'gami anchor' first")
	}

	// 3. Contact calendar servers
	logf("Contacting OpenTimestamps calendar servers ...")
	otsClient := ots.New()
	upgraded, confirmed, err := otsClient.Upgrade(g.Timestamp.Proof)
	if err != nil {
		return fmt.Errorf("upgrade OTS proof: %w", err)
	}

	if !confirmed {
		logf("Bitcoin confirmation not yet available. Try again in a few minutes.")
		logf("GPR unchanged: %s", upgradeGPRPath)
		return nil
	}

	// 4. Embed completed proof
	g = g.SetTimestampProof(upgraded)
	logf("Bitcoin confirmation received — OTS proof upgraded.")

	// 5. Write output
	out, err := g.ToJSON()
	if err != nil {
		return fmt.Errorf("marshal GPR: %w", err)
	}

	outPath := upgradeOutputPath
	if outPath == "" {
		outPath = upgradeGPRPath // overwrite in place
	}
	if err := os.WriteFile(outPath, out, 0644); err != nil {
		return fmt.Errorf("write GPR: %w", err)
	}
	logf("GPR written to %s", outPath)
	return nil
}
