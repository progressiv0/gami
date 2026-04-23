package commands

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/progressiv0/gami/gami-core/gpr"
)

// otsHeaderMagic is the 31-byte magic that starts every .ots DetachedTimestampFile.
var otsHeaderMagic = []byte("\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94")

// buildDetachedTimestampFile wraps the raw timestamp-tree bytes stored in
// GPR.Proof.Timestamp.OTSData into the standard DetachedTimestampFile format
// that the reference OTS client and opentimestamps.org expect:
//
//	HEADER_MAGIC (31 B) | version=0x01 (1 B) | SHA256-op=0x08 (1 B) | docHash (32 B) | tree
func buildDetachedTimestampFile(docHashHex string, treeBytes []byte) ([]byte, error) {
	docHashHex = strings.TrimPrefix(docHashHex, "sha256:")
	docHash, err := hex.DecodeString(docHashHex)
	if err != nil || len(docHash) != 32 {
		return nil, fmt.Errorf("invalid document_hash: %w", err)
	}

	out := make([]byte, 0, len(otsHeaderMagic)+1+1+32+len(treeBytes))
	out = append(out, otsHeaderMagic...) // magic (31 bytes)
	out = append(out, 0x01)              // version
	out = append(out, 0x08)              // SHA256 CryptOp tag
	out = append(out, docHash...)        // 32-byte file digest
	out = append(out, treeBytes...)      // timestamp tree
	return out, nil
}

var extractOTSCmd = &cobra.Command{
	Use:   "ots",
	Short: "Extract OTS proof and canonical document for opentimestamps.org",
	Long: `Writes two files needed to verify the Bitcoin timestamp externally:

  <name>.ots            — OTS DetachedTimestampFile (compatible with ots CLI and opentimestamps.org)
  <name>.canonical.json — JCS document that was hashed (signed, timestamp block absent)

The .canonical.json file contains the exact bytes whose SHA-256 equals
proof.timestamp.document_hash. Verify with:

  ots verify <name>.canonical.json <name>.ots`,
	RunE: runExtractOTS,
}

var (
	extractOTSGPRPath string
	extractOTSPrefix  string
)

func init() {
	extractOTSCmd.Flags().StringVar(&extractOTSGPRPath, "gpr", "", "Path to the GPR file")
	extractOTSCmd.Flags().StringVar(&extractOTSPrefix, "output", "", "Output prefix (default: derived from GPR filename)")

	_ = extractOTSCmd.MarkFlagRequired("gpr")
}

func runExtractOTS(cmd *cobra.Command, args []string) error {
	rawGPR, err := os.ReadFile(extractOTSGPRPath)
	if err != nil {
		return fmt.Errorf("read GPR: %w", err)
	}
	g, err := gpr.FromJSON(rawGPR)
	if err != nil {
		return fmt.Errorf("parse GPR: %w", err)
	}
	if g.Proof.Timestamp == nil || g.Proof.Timestamp.OTSData == "" {
		return fmt.Errorf("GPR has no OTS proof — run 'gami stamp' first")
	}

	prefix := extractOTSPrefix
	if prefix == "" {
		// archive_sample.gpr.json → archive_sample
		prefix = strings.TrimSuffix(extractOTSGPRPath, ".json")
		prefix = strings.TrimSuffix(prefix, ".gpr")
	}

	// 1. Decode the raw timestamp-tree bytes from the GPR
	treeBytes, err := base64.StdEncoding.DecodeString(g.Proof.Timestamp.OTSData)
	if err != nil {
		return fmt.Errorf("decode ots_data: %w", err)
	}

	// 2. Wrap in DetachedTimestampFile format (magic + version + hash-op + docHash + tree)
	otsFile, err := buildDetachedTimestampFile(g.Proof.Timestamp.DocumentHash, treeBytes)
	if err != nil {
		return fmt.Errorf("build .ots file: %w", err)
	}
	otsPath := prefix + ".ots"
	if err := os.WriteFile(otsPath, otsFile, 0644); err != nil {
		return fmt.Errorf("write .ots file: %w", err)
	}

	// 3. Write JCS canonical document (the bytes whose SHA-256 = document_hash)
	canonical, err := g.CanonicaliseForTimestamp()
	if err != nil {
		return fmt.Errorf("canonicalise document: %w", err)
	}
	canonicalPath := prefix + ".canonical.json"
	if err := os.WriteFile(canonicalPath, canonical, 0644); err != nil {
		return fmt.Errorf("write canonical document: %w", err)
	}

	logf("OTS proof written to     %s", otsPath)
	logf("Canonical doc written to %s", canonicalPath)
	logf("document_hash: %s", g.Proof.Timestamp.DocumentHash)
	logf("upgraded:      %v", g.Proof.Timestamp.Upgraded)
	logf("")
	logf("Verify with: ots verify %s %s", canonicalPath, otsPath)
	return nil
}
