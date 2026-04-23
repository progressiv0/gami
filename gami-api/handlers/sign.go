package handlers

import (
	"net/http"

	"github.com/progressiv0/gami/gami-api/config"
	"github.com/progressiv0/gami/gami-core/gpr"
	"github.com/progressiv0/gami/gami-core/service"
)

// SignHandler handles POST /v1/sign.
// Signs a GPR using the server's key.  The caller supplies the unsigned GPR;
// key material never travels over the wire.
type SignHandler struct{ cfg *config.Config }

// NewSignHandler creates a SignHandler.
func NewSignHandler(cfg *config.Config) *SignHandler { return &SignHandler{cfg: cfg} }

// ServeHTTP handles the request.
func (h *SignHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := h.cfg.CanSign(); err != nil {
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}

	var raw struct {
		GPR gpr.GPR `json:"gpr"`
	}
	if err := decode(r, &raw); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	signed, err := service.Sign(service.SignRequest{
		GPR:        &raw.GPR,
		PrivKeyHex: h.cfg.PrivKeyHex,
		PubKeyHex:  h.cfg.PubKeyHex,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, signed)
}
