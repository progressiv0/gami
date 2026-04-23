package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/progressiv0/gami/gami-core/signing"
)

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate an Ed25519 key pair and a DID document template",
	Long: `Generates an Ed25519 key pair for institutional signing and produces
a ready-to-publish DID document template.

Files written to --output:
  ed25519.priv  — private key (hex, keep secret, never share)
  ed25519.pub   — public key (hex)
  did.json      — DID document template to publish at:
                  https://<domain>/.well-known/did.json`,
	RunE: runKeygen,
}

var (
	keygenOutput string
	keygenDomain string
	keygenKeyID  string
)

func init() {
	keygenCmd.Flags().StringVar(&keygenOutput, "output", ".", "Directory to write key files")
	keygenCmd.Flags().StringVar(&keygenDomain, "domain", "", "Institution domain (e.g. example.org)")
	keygenCmd.Flags().StringVar(&keygenKeyID, "key-id", "key-1", "Key identifier suffix used in the DID document")

	_ = keygenCmd.MarkFlagRequired("domain")
}

func runKeygen(cmd *cobra.Command, args []string) error {
	kp, err := signing.Generate()
	if err != nil {
		return fmt.Errorf("generate key pair: %w", err)
	}

	if err := os.MkdirAll(keygenOutput, 0700); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	privPath := filepath.Join(keygenOutput, "ed25519.priv")
	pubPath := filepath.Join(keygenOutput, "ed25519.pub")
	didPath := filepath.Join(keygenOutput, "did.json")

	if err := os.WriteFile(privPath, []byte(kp.PrivateKeyHex()), 0600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := os.WriteFile(pubPath, []byte(kp.PublicKeyHex()), 0644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}

	did := fmt.Sprintf("did:web:%s", keygenDomain)
	keyID := fmt.Sprintf("%s#%s", did, keygenKeyID)

	didDoc := fmt.Sprintf(`{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "%s",
  "verificationMethod": [
    {
      "id": "%s",
      "type": "Ed25519VerificationKey2020",
      "controller": "%s",
      "publicKeyHex": "%s"
    }
  ],
  "authentication": ["%s"]
}
`, did, keyID, did, kp.PublicKeyHex(), keyID)

	if err := os.WriteFile(didPath, []byte(didDoc), 0644); err != nil {
		return fmt.Errorf("write DID document: %w", err)
	}

	fmt.Printf("Key pair generated in %s\n\n", keygenOutput)
	fmt.Printf("  Private key  : %s\n", privPath)
	fmt.Printf("  Public key   : %s\n", pubPath)
	fmt.Printf("  DID document : %s\n\n", didPath)
	fmt.Printf("Next step: publish %s at\n", didPath)
	fmt.Printf("  https://%s/.well-known/did.json\n\n", keygenDomain)
	fmt.Printf("Use --key-id '%s' when running 'gami anchor'.\n", keyID)
	return nil
}
