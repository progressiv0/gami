package commands

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/progressiv0/gami/gami-core/gpr"
	"github.com/progressiv0/gami/gami-core/service"
)

var upgradeCmd = &cobra.Command{
	Use:   "upgrade",
	Short: "Fetch the confirmed Bitcoin OTS proof and embed it in a GPR",
	Long: `Contacts OpenTimestamps calendar servers to retrieve the completed Bitcoin proof
for a previously stamped GPR. Bitcoin block confirmation typically takes ~1 hour.

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
	rawGPR, err := os.ReadFile(upgradeGPRPath)
	if err != nil {
		return fmt.Errorf("read GPR: %w", err)
	}
	g, err := gpr.FromJSON(rawGPR)
	if err != nil {
		return fmt.Errorf("parse GPR: %w", err)
	}

	// Guard: already upgraded before contacting calendars
	if g.Proof.Timestamp != nil && g.Proof.Timestamp.Upgraded {
		logf("OTS proof is already upgraded (Bitcoin confirmation already embedded).")
		return nil
	}

	logf("Contacting OpenTimestamps calendar servers ...")
	result, err := service.Upgrade(g)
	if err != nil {
		return err
	}

	if !result.Confirmed {
		logf("Bitcoin confirmation not yet available. Try again in a few minutes.")
		logf("GPR unchanged: %s", upgradeGPRPath)
		return nil
	}

	logf("Bitcoin confirmation received — OTS proof upgraded via %s", result.Calendar)

	out, err := result.GPR.ToJSON()
	if err != nil {
		return fmt.Errorf("marshal GPR: %w", err)
	}

	outPath := upgradeOutputPath
	if outPath == "" {
		outPath = upgradeGPRPath
	}
	if err := os.WriteFile(outPath, out, 0644); err != nil {
		return fmt.Errorf("write GPR: %w", err)
	}
	logf("GPR written to %s", outPath)
	return nil
}
