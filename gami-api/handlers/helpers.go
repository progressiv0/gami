// Package handlers contains HTTP handlers for the GAMI REST API.
package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// writeJSON serialises v and writes it to w with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON error response: {"error": "..."}.
func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

// decode deserialises the request body into v.
func decode(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// errMissing returns a simple "field is required" error.
func errMissing(field string) error {
	return fmt.Errorf("%s is required", field)
}
