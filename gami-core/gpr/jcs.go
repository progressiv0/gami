// JCS canonicalization (RFC 8785) for GPR signing and verification. §5.2
package gpr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// Canonicalise produces the JCS (RFC 8785) canonical byte representation
// of the GPR with the specified top-level fields omitted.
//
// Before signing: omit "signature" and "timestamp".
// Before OTS verification: omit "timestamp".
func (g *GPR) Canonicalise(omit ...string) ([]byte, error) {
	data, err := json.Marshal(g)
	if err != nil {
		return nil, fmt.Errorf("marshal GPR: %w", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("unmarshal to map: %w", err)
	}

	for _, field := range omit {
		delete(m, field)
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
