package handlers

import (
	"net/http"

	"authenticmemory.org/gami-core/gpr"
	"authenticmemory.org/gami-core/service"
)

// StampHandler handles POST /v1/stamp.
// Accepts a signed GPR, computes document_hash, and optionally submits to OTS.
type StampHandler struct{}

// NewStampHandler creates a StampHandler.
func NewStampHandler() *StampHandler { return &StampHandler{} }

// ServeHTTP handles the request.
func (h *StampHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var raw struct {
		GPR       gpr.GPR `json:"gpr"`
		SubmitOTS bool    `json:"submit_ots"`
	}
	if err := decode(r, &raw); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	result, err := service.Stamp(&raw.GPR, raw.SubmitOTS)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	resp := map[string]any{"gpr": result.GPR}
	if result.Calendar != "" {
		resp["calendar"] = result.Calendar
	}
	if result.OTSError != nil {
		resp["ots_error"] = result.OTSError.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}
