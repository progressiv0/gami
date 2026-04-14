package handlers

import (
	"net/http"

	"authenticmemory.org/gami-api/config"
	"authenticmemory.org/gami-core/hash"
	"authenticmemory.org/gami-core/service"
)

// AnchorHandler handles POST /v1/anchor.
type AnchorHandler struct{ cfg *config.Config }

// NewAnchorHandler creates an AnchorHandler.
func NewAnchorHandler(cfg *config.Config) *AnchorHandler { return &AnchorHandler{cfg: cfg} }

// anchorRequest is the JSON body for POST /v1/anchor.
// The server holds the private key; callers never send key material.
type anchorRequest struct {
	// FileHash is the SHA-256 of the file: "sha256:<64 hex chars>".
	// Clients compute this locally before calling the API.
	FileHash string `json:"file_hash"`

	Filename  string            `json:"filename,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	ParentID  *string           `json:"parent_id,omitempty"`
	SubmitOTS bool              `json:"submit_ots"`
}

type anchorResponse struct {
	GPR      any    `json:"gpr"`
	Calendar string `json:"calendar,omitempty"`
	OTSError string `json:"ots_error,omitempty"`
}

// ServeHTTP handles the request.
func (h *AnchorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := h.cfg.CanSign(); err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}

	var req anchorRequest
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := hash.Validate(req.FileHash); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	result, err := service.Anchor(service.AnchorRequest{
		FileHash:   req.FileHash,
		Filename:   req.Filename,
		KeyID:      h.cfg.KeyID,
		PrivKeyHex: h.cfg.PrivKeyHex,
		PubKeyHex:  h.cfg.PubKeyHex,
		Metadata:   req.Metadata,
		ParentID:   req.ParentID,
		SubmitOTS:  req.SubmitOTS,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	resp := anchorResponse{GPR: result.GPR, Calendar: result.Calendar}
	if result.OTSError != nil {
		resp.OTSError = result.OTSError.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}
