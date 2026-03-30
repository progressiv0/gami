package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"github.com/progressiv0/gami/core/gpr"
	"github.com/progressiv0/gami/core/hash"
	"github.com/progressiv0/gami/core/verify"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a file against a GPR (offline) or look it up via a server",
	Long: `Two verification modes:

  Offline / direct mode (--gpr):
    Verifies entirely locally. Requires the file and its GPR JSON file.
    No network connection needed (except for DID:web resolution).

  Lookup mode (--server):
    Computes the file hash locally, queries the server for the GPR,
    then runs the same local verification steps.

Exit codes: 0 = verified, 1 = error, 2 = verification failed.`,
	RunE: runVerify,
}

var (
	verifyFile    string
	verifyGPRPath string
	verifyServer  string
	verifyJSON    bool
)

func init() {
	verifyCmd.Flags().StringVar(&verifyFile, "file", "", "Path to the file to verify")
	verifyCmd.Flags().StringVar(&verifyGPRPath, "gpr", "", "Path to GPR JSON file (offline/direct mode)")
	verifyCmd.Flags().StringVar(&verifyServer, "server", "", "GAMI server URL for lookup mode")
	verifyCmd.Flags().BoolVar(&verifyJSON, "json", false, "Output result as JSON")

	_ = verifyCmd.MarkFlagRequired("file")
}

func runVerify(cmd *cobra.Command, args []string) error {
	if verifyGPRPath == "" && verifyServer == "" {
		return fmt.Errorf("either --gpr (offline) or --server (lookup) is required")
	}

	// Hash the file client-side
	logf("Hashing %s ...", verifyFile)
	fileHash, err := hash.File(verifyFile)
	if err != nil {
		return fmt.Errorf("hash file: %w", err)
	}
	logf("Hash: %s", fileHash)

	// Obtain the GPR
	var g *gpr.GPR
	if verifyGPRPath != "" {
		data, err := os.ReadFile(verifyGPRPath)
		if err != nil {
			return fmt.Errorf("read GPR file: %w", err)
		}
		g, err = gpr.FromJSON(data)
		if err != nil {
			return fmt.Errorf("parse GPR: %w", err)
		}
	} else {
		logf("Looking up hash on %s ...", verifyServer)
		g, err = serverLookup(verifyServer, hash.Hex(fileHash))
		if err != nil {
			return err
		}
		if g == nil {
			fmt.Println("NOT FOUND — no proof exists for this file in the index")
			os.Exit(2)
		}
	}

	// Run verification engine
	engine := verify.New()
	result := engine.Verify(fileHash, g)

	if verifyJSON {
		return printResultJSON(result)
	}
	printResult(result)

	if !result.Overall() {
		os.Exit(2)
	}
	return nil
}

func serverLookup(server, hashHex string) (*gpr.GPR, error) {
	url := fmt.Sprintf("%s/v1/gpr/lookup/%s", server, hashHex)
	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("lookup request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // not found
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var envelope struct {
		Found bool            `json:"found"`
		GPR   json.RawMessage `json:"gpr"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("parse server response: %w", err)
	}
	if !envelope.Found {
		return nil, nil
	}
	return gpr.FromJSON(envelope.GPR)
}

func printResult(r *verify.Result) {
	fmt.Println()
	fmt.Println("=== GAMI Verification Result ===")
	fmt.Printf("Institution : %s\n", r.InstitutionName)
	fmt.Printf("GPR ID      : %s\n", r.GPRID)
	fmt.Printf("Anchored at : %s\n", r.AnchoredAt)
	fmt.Println()

	check := func(label string, ok bool, key string) {
		status := "PASS"
		if !ok {
			status = "FAIL"
		}
		line := fmt.Sprintf("  [%s] %s", status, label)
		if !ok && r.Errors[key] != "" {
			line += " — " + r.Errors[key]
		}
		fmt.Println(line)
	}

	check("File hash match", r.HashMatch, "hash")
	check("Institutional signature (Ed25519)", r.SignatureValid, "signature")
	check("OTS timestamp (Bitcoin)", r.TimestampValid, "timestamp")

	if r.SignatureKeyStatus != "" {
		fmt.Printf("       Key status: %s\n", r.SignatureKeyStatus)
	}

	fmt.Println()
	if r.Overall() {
		fmt.Println("RESULT: VERIFIED  [Tier 1 — cryptographic proof]")
	} else {
		fmt.Println("RESULT: VERIFICATION FAILED")
	}
	fmt.Println()
}

func printResultJSON(r *verify.Result) error {
	out, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}
