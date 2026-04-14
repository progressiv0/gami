package commands

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"authenticmemory.org/gami-core/gpr"
	"authenticmemory.org/gami-core/service"
)

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a GPR with an Ed25519 private key",
	Long: `Part 2 of 3 — signs the JCS-canonical document and stores the result in proof.signature:

  canonical = JCS(document with proof.signature and proof.timestamp absent)
  signature = Ed25519Sign(SHA-256(canonical), private_key)

The signature covers the full document: subject, metadata, key identity, and creation time.

Next step: gami stamp --gpr <output>`,
	RunE: runSign,
}

var (
	signGPRPath    string
	signKeyPath    string
	signPubKeyPath string
	signOutputPath string
)

func init() {
	signCmd.Flags().StringVar(&signGPRPath, "gpr", "", "Path to the GPR file to sign")
	signCmd.Flags().StringVar(&signKeyPath, "key", "", "Path to Ed25519 private key file (hex)")
	signCmd.Flags().StringVar(&signPubKeyPath, "pub-key", "", "Path to Ed25519 public key file — embeds it in the GPR for offline verification")
	signCmd.Flags().StringVar(&signOutputPath, "output", "", "Write signed GPR to this file (default: overwrite input)")

	_ = signCmd.MarkFlagRequired("gpr")
	_ = signCmd.MarkFlagRequired("key")
}

func runSign(cmd *cobra.Command, args []string) error {
	rawGPR, err := os.ReadFile(signGPRPath)
	if err != nil {
		return fmt.Errorf("read GPR: %w", err)
	}
	g, err := gpr.FromJSON(rawGPR)
	if err != nil {
		return fmt.Errorf("parse GPR: %w", err)
	}

	keyBytes, err := os.ReadFile(signKeyPath)
	if err != nil {
		return fmt.Errorf("read key file: %w", err)
	}

	pubKeyHex := ""
	if signPubKeyPath != "" {
		pubBytes, err := os.ReadFile(signPubKeyPath)
		if err != nil {
			return fmt.Errorf("read pub key file: %w", err)
		}
		pubKeyHex = strings.TrimSpace(string(pubBytes))
	}

	g, err = service.Sign(service.SignRequest{
		GPR:        g,
		PrivKeyHex: string(keyBytes),
		PubKeyHex:  pubKeyHex,
	})
	if err != nil {
		return err
	}

	logf("Signed with key %s", g.Proof.KeyID)
	sig := g.Proof.Signature
	logf("proof.signature: %s…", sig[:min(len(sig), 40)])

	out, err := g.ToJSON()
	if err != nil {
		return fmt.Errorf("marshal GPR: %w", err)
	}

	outPath := signOutputPath
	if outPath == "" {
		outPath = signGPRPath
	}
	if err := os.WriteFile(outPath, out, 0644); err != nil {
		return fmt.Errorf("write GPR: %w", err)
	}
	logf("GPR written to %s", outPath)
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
