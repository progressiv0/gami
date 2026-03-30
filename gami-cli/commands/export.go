package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"authenticmemory.org/gami-core/gpr"
	"authenticmemory.org/gami-core/hash"
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Download a GPR from the index by file hash or GPR ID",
	Long: `Fetches a GPR from a GAMI index server and writes it to a file or stdout.

Examples:
  gami export --hash sha256:3a7f91... --server https://authenticmemory.org
  gami export --id urn:uuid:a1b2c3... --server https://authenticmemory.org --output proof.gpr.json
  gami export --id urn:uuid:a1b2c3... --server https://authenticmemory.org --chain`,
	RunE: runExport,
}

var (
	exportHash   string
	exportID     string
	exportServer string
	exportChain  bool
	exportOutput string
)

func init() {
	exportCmd.Flags().StringVar(&exportHash, "hash", "", "SHA-256 hash to look up (with or without sha256: prefix)")
	exportCmd.Flags().StringVar(&exportID, "id", "", "GPR ID to fetch (urn:uuid:...)")
	exportCmd.Flags().StringVar(&exportServer, "server", "", "GAMI server base URL")
	exportCmd.Flags().BoolVar(&exportChain, "chain", false, "Download the full provenance chain (requires --id)")
	exportCmd.Flags().StringVar(&exportOutput, "output", "", "Write to file (default: stdout)")

	_ = exportCmd.MarkFlagRequired("server")
}

func runExport(cmd *cobra.Command, args []string) error {
	if exportHash == "" && exportID == "" {
		return fmt.Errorf("either --hash or --id is required")
	}
	if exportChain && exportID == "" {
		return fmt.Errorf("--chain requires --id")
	}

	var (
		url     string
		isLookup bool
	)

	switch {
	case exportHash != "":
		hexHash := hash.Hex(exportHash)
		url = fmt.Sprintf("%s/v1/gpr/lookup/%s", exportServer, hexHash)
		isLookup = true
	case exportChain:
		url = fmt.Sprintf("%s/v1/gpr/%s/chain", exportServer, exportID)
	default:
		url = fmt.Sprintf("%s/v1/gpr/%s", exportServer, exportID)
	}

	logf("Fetching %s ...", url)
	body, err := fetchJSON(url)
	if err != nil {
		return err
	}

	// For lookup responses, unwrap the envelope and validate the GPR
	if isLookup {
		var envelope struct {
			Found bool            `json:"found"`
			GPR   json.RawMessage `json:"gpr"`
		}
		if err := json.Unmarshal(body, &envelope); err != nil {
			return fmt.Errorf("parse server response: %w", err)
		}
		if !envelope.Found {
			fmt.Fprintln(os.Stderr, "NOT FOUND — no GPR exists for this hash")
			os.Exit(1)
		}
		// Validate it parses as a real GPR
		if _, err := gpr.FromJSON(envelope.GPR); err != nil {
			return fmt.Errorf("server returned invalid GPR: %w", err)
		}
		body = envelope.GPR
	}

	// Pretty-print
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return fmt.Errorf("parse response body: %w", err)
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}

	if exportOutput != "" {
		if err := os.WriteFile(exportOutput, out, 0644); err != nil {
			return fmt.Errorf("write output file: %w", err)
		}
		logf("Written to %s", exportOutput)
	} else {
		fmt.Println(string(out))
	}
	return nil
}

func fetchJSON(url string) ([]byte, error) {
	resp, err := http.Get(url) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("not found: %s", url)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned HTTP %d for %s", resp.StatusCode, url)
	}
	return io.ReadAll(resp.Body)
}
