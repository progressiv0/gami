package commands

import "github.com/spf13/cobra"

var extractCmd = &cobra.Command{
	Use:   "extract",
	Short: "Extract verifiable artifacts from a GPR",
	Long: `Extract the files needed to verify a GPR outside of gami:

  gami extract ots      — OTS proof binary + canonical document (for opentimestamps.org)
  gami extract signing  — Signing payload + key info (for Ed25519 signature verification)`,
}

func init() {
	extractCmd.AddCommand(extractOTSCmd)
	extractCmd.AddCommand(extractSigningCmd)
}
