package commands

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/progressiv0/gami/gami-core/gpr"
)

var extractSigningCmd = &cobra.Command{
	Use:   "signing",
	Short: "Extract signing payload and key info for Ed25519 signature verification",
	Long: `Writes the exact bytes that were signed, alongside the public key and signature.

  <name>.signing.json — JCS document without proof.signature and proof.timestamp

The signature scheme is: Ed25519Sign(private_key, SHA-256(<name>.signing.json))
To verify manually:

  # Python (cryptography library):
  python3 -c "
  from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
  import hashlib, binascii, sys
  pub = Ed25519PublicKey.from_public_bytes(binascii.unhexlify('<public_key_hex>'))
  data = open('<name>.signing.json', 'rb').read()
  sig  = binascii.unhexlify('<signature_hex>')
  pub.verify(sig, hashlib.sha256(data).digest())
  print('Signature VALID')
  "`,
	RunE: runExtractSigning,
}

var (
	extractSigningGPRPath string
	extractSigningPrefix  string
)

func init() {
	extractSigningCmd.Flags().StringVar(&extractSigningGPRPath, "gpr", "", "Path to the GPR file")
	extractSigningCmd.Flags().StringVar(&extractSigningPrefix, "output", "", "Output prefix (default: derived from GPR filename)")

	_ = extractSigningCmd.MarkFlagRequired("gpr")
}

func runExtractSigning(cmd *cobra.Command, args []string) error {
	rawGPR, err := os.ReadFile(extractSigningGPRPath)
	if err != nil {
		return fmt.Errorf("read GPR: %w", err)
	}
	g, err := gpr.FromJSON(rawGPR)
	if err != nil {
		return fmt.Errorf("parse GPR: %w", err)
	}
	if g.Proof.Signature == "" {
		return fmt.Errorf("GPR has no signature — run 'gami sign' first")
	}

	prefix := extractSigningPrefix
	if prefix == "" {
		prefix = strings.TrimSuffix(extractSigningGPRPath, ".json")
		prefix = strings.TrimSuffix(prefix, ".gpr")
	}

	// Write JCS canonical document without proof.signature and proof.timestamp —
	// the exact bytes fed into SHA-256 before Ed25519 signing.
	canonical, err := g.CanonicaliseForSigning()
	if err != nil {
		return fmt.Errorf("canonicalise for signing: %w", err)
	}
	signingPath := prefix + ".signing.json"
	if err := os.WriteFile(signingPath, canonical, 0644); err != nil {
		return fmt.Errorf("write signing payload: %w", err)
	}

	// Compute the SHA-256 that Ed25519 actually signs over.
	digest := sha256.Sum256(canonical)
	digestHex := hex.EncodeToString(digest[:])

	// Strip "ed25519:" prefix for display.
	sigHex := strings.TrimPrefix(g.Proof.Signature, "ed25519:")

	// Resolve public key: prefer embedded, fall back to key_id hint.
	pubKeyHex := g.Proof.PublicKeyHex
	pubKeySource := "proof.public_key_hex"
	if pubKeyHex == "" {
		pubKeyHex = "<resolve from " + g.Proof.KeyID + ">"
		pubKeySource = "DID resolution required"
	}

	logf("Signing payload written to %s", signingPath)
	logf("")
	logf("SHA-256 of payload (signed by Ed25519):")
	logf("  %s", digestHex)
	logf("")
	logf("Signature (ed25519, hex):")
	logf("  %s", sigHex)
	logf("")
	logf("Public key (ed25519, hex) — source: %s", pubKeySource)
	logf("  %s", pubKeyHex)
	logf("")
	logf("Verify with Python:")
	logf(`  python3 -c "`)
	logf(`  from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey`)
	logf(`  import hashlib, binascii`)
	logf(`  pub = Ed25519PublicKey.from_public_bytes(binascii.unhexlify('%s'))`, pubKeyHex)
	logf(`  data = open('%s', 'rb').read()`, signingPath)
	logf(`  sig  = binascii.unhexlify('%s')`, sigHex)
	logf(`  pub.verify(sig, hashlib.sha256(data).digest())`)
	logf(`  print('Signature VALID')`)
	logf(`  "`)
	return nil
}
