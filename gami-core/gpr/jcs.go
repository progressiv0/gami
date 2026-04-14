// JCS canonicalization (RFC 8785) for GPR signing and verification. §5.2
package gpr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// CanonicaliseForSigning returns JCS bytes for Ed25519 signing.
// Omits proof.signature and proof.timestamp — neither exists at signing time.
func (g *GPR) CanonicaliseForSigning() ([]byte, error) {
	return g.canonicaliseOmitProofFields("signature", "timestamp")
}

// CanonicaliseForTimestamp returns JCS bytes for the OTS document_hash computation.
// Includes proof.signature but omits proof.timestamp (not yet known).
func (g *GPR) CanonicaliseForTimestamp() ([]byte, error) {
	return g.canonicaliseOmitProofFields("timestamp")
}

// canonicaliseOmitProofFields marshals the GPR to a map, deletes named fields
// from the proof object, then returns the JCS canonical bytes.
func (g *GPR) canonicaliseOmitProofFields(fields ...string) ([]byte, error) {
	raw, err := json.Marshal(g)
	if err != nil {
		return nil, fmt.Errorf("marshal GPR: %w", err)
	}

	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("unmarshal to map: %w", err)
	}

	if proof, ok := m["proof"].(map[string]any); ok {
		for _, f := range fields {
			delete(proof, f)
		}
		m["proof"] = proof
	}

	return canonicaliseValue(m)
}

func canonicaliseValue(v any) ([]byte, error) {
	switch val := v.(type) {
	case map[string]any:
		return canonicaliseObject(val)
	case []any:
		return canonicaliseArray(val)
	case nil:
		return []byte("null"), nil
	default:
		// string, float64, bool — standard JSON encoding is already canonical
		return json.Marshal(val)
	}
}

// canonicaliseObject sorts keys lexicographically as required by RFC 8785.
func canonicaliseObject(m map[string]any) ([]byte, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		keyBytes, err := json.Marshal(k)
		if err != nil {
			return nil, fmt.Errorf("marshal key %q: %w", k, err)
		}
		buf.Write(keyBytes)
		buf.WriteByte(':')
		valBytes, err := canonicaliseValue(m[k])
		if err != nil {
			return nil, fmt.Errorf("marshal value for key %q: %w", k, err)
		}
		buf.Write(valBytes)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func canonicaliseArray(arr []any) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, v := range arr {
		if i > 0 {
			buf.WriteByte(',')
		}
		valBytes, err := canonicaliseValue(v)
		if err != nil {
			return nil, fmt.Errorf("array element %d: %w", i, err)
		}
		buf.Write(valBytes)
	}
	buf.WriteByte(']')
	return buf.Bytes(), nil
}
