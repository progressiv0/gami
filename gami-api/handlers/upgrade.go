package handlers

import (
	"net/http"

	"github.com/progressiv0/gami/gami-core/gpr"
	"github.com/progressiv0/gami/gami-core/service"
)

// UpgradeHandler handles POST /v1/upgrade.
// Contacts OTS calendars to retrieve the completed Bitcoin proof.
type UpgradeHandler struct{}

// NewUpgradeHandler creates an UpgradeHandler.
func NewUpgradeHandler() *UpgradeHandler { return &UpgradeHandler{} }

// ServeHTTP handles the request.
func (h *UpgradeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var raw struct {
		GPR gpr.GPR `json:"gpr"`
	}
	if err := decode(r, &raw); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	result, err := service.Upgrade(&raw.GPR)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"gpr":       result.GPR,
		"confirmed": result.Confirmed,
		"calendar":  result.Calendar,
	})
}
