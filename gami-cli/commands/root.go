// Package commands defines all GAMI CLI subcommands.
package commands

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "gami",
	Short: "GAMI — Global Authentic Memory Initiative CLI",
	Long: `Create and verify cryptographic proofs of existence for digital archival materials.

Each proof (GPR) ties a file's SHA-256 hash to an institutional Ed25519 signature
and a Bitcoin blockchain timestamp via OpenTimestamps.

Documentation: https://authenticmemory.org/spec`,
}

// logf prints a formatted message to stderr.
func logf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(anchorCmd)
	rootCmd.AddCommand(prepareCmd)
	rootCmd.AddCommand(signCmd)
	rootCmd.AddCommand(stampCmd)
	rootCmd.AddCommand(upgradeCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(batchCmd)
	rootCmd.AddCommand(keygenCmd)
	rootCmd.AddCommand(exportCmd)
	rootCmd.AddCommand(extractCmd)
}
