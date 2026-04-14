package handlers

import (
	"net/http"

	"authenticmemory.org/gami-core/gpr"
	"authenticmemory.org/gami-core/verify"
)

// VerifyHandler handles POST /v1/verify.
// Public endpoint — no key material required.
//
// Request modes:
//
//  1. Full verification (GPR provided by caller):
//     { "file_hash": "sha256:...", "gpr": {...} }
//
//  2. Full verification with public key override:
//     { "file_hash": "sha256:...", "gpr": {...}, "public_key_hex": "..." }
//
//  3. OTS-only from raw GPR ots_data (tree bytes, no file header):
//     { "ots_data": "base64...", "file_hash": "sha256:..." }
//
//  4. OTS-only from exported .ots file (DetachedTimestampFile format):
//     { "ots_file": "base64...", "canonical": "...text..." }
//     canonical is optional; if provided its SHA-256 is checked against the .ots digest.
type VerifyHandler struct {
	engine *verify.Engine
}

// NewVerifyHandler creates a VerifyHandler.
func NewVerifyHandler() *VerifyHandler {
	return &VerifyHandler{engine: verify.New()}
}

// ServeHTTP handles the request.
func (h *VerifyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var raw struct {
		FileHash     string   `json:"file_hash"`
		GPR          *gpr.GPR `json:"gpr"`
		PublicKeyHex string   `json:"public_key_hex"`
		OTSData      string   `json:"ots_data"`     // raw tree bytes from GPR (no file header)
		OTSFile      string   `json:"ots_file"`     // full DetachedTimestampFile binary
		Canonical    string   `json:"canonical"`    // text content of .canonical file
	}
	if err := decode(r, &raw); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	// Mode 4 — exported .ots DetachedTimestampFile + optional canonical
	if raw.OTSFile != "" && raw.GPR == nil {
		result := h.engine.VerifyOTSFile(raw.OTSFile, []byte(raw.Canonical))
		writeJSON(w, http.StatusOK, result)
		return
	}

	// Mode 3 — raw OTS tree bytes from GPR ots_data field
	if raw.OTSData != "" && raw.GPR == nil {
		result := h.engine.VerifyOTS(raw.FileHash, raw.OTSData)
		writeJSON(w, http.StatusOK, result)
		return
	}

	// Modes 1 & 2 — full GPR verification (optional key override)
	if raw.GPR == nil {
		writeError(w, http.StatusBadRequest, errMissing("gpr, ots_file, or ots_data"))
		return
	}
	if raw.FileHash == "" {
		writeError(w, http.StatusBadRequest, errMissing("file_hash"))
		return
	}

	opts := verify.Options{PublicKeyHex: raw.PublicKeyHex}
	result := h.engine.VerifyWithOptions(raw.FileHash, raw.GPR, opts)
	writeJSON(w, http.StatusOK, result)
}
