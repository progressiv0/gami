// Package server wires up the HTTP routes and starts the listener.
package server

import (
	"fmt"
	"net/http"

	"github.com/progressiv0/gami/gami-api/config"
	"github.com/progressiv0/gami/gami-api/handlers"
)

// New returns an http.Handler with all routes registered.
func New(cfg *config.Config) http.Handler {
	mux := http.NewServeMux()

	// Institution-level operations — require GAMI_PRIVATE_KEY to be set.
	mux.Handle("POST /v1/anchor", handlers.NewAnchorHandler(cfg))
	mux.Handle("POST /v1/sign", handlers.NewSignHandler(cfg))

	// Stateless operations — no key material needed server-side.
	mux.Handle("POST /v1/stamp", handlers.NewStampHandler())
	mux.Handle("POST /v1/upgrade", handlers.NewUpgradeHandler())
	mux.Handle("POST /v1/verify", handlers.NewVerifyHandler())

	return mux
}

// ListenAndServe starts the HTTP server on cfg.Port.
func ListenAndServe(cfg *config.Config) error {
	addr := fmt.Sprintf(":%s", cfg.Port)
	fmt.Printf("GAMI API listening on %s\n", addr)
	return http.ListenAndServe(addr, New(cfg)) //nolint:gosec
}
