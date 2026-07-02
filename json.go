// Copyright (c) the go-ruby-jwt/jwt authors
//
// SPDX-License-Identifier: BSD-3-Clause

package jwt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// The gem serialises header and payload with Ruby's JSON.generate, which emits
// compact JSON (no spaces) and preserves a Hash's insertion order. To be byte-
// faithful we mirror both properties: OrderedMap keeps key order, and marshalJSON
// emits compact, insertion-ordered objects. A plain Go map has no order, so we
// sort its keys — deterministic, and the shape callers reach for when order does
// not matter.

// OrderedMap is an insertion-ordered string-keyed object, the analogue of a Ruby
// Hash. Encode accepts one as payload or header so a caller can pin claim / header
// order; Decode returns payload and header as *OrderedMap so key order round-trips.
type OrderedMap struct {
	keys   []string
	values map[string]any
}

// NewOrderedMap returns an empty ordered object.
func NewOrderedMap() *OrderedMap {
	return &OrderedMap{values: map[string]any{}}
}

// Set stores val under key, appending the key on first insertion and preserving
// its position on update (Ruby Hash#[]= semantics).
func (m *OrderedMap) Set(key string, val any) {
	if _, ok := m.values[key]; !ok {
		m.keys = append(m.keys, key)
	}
	m.values[key] = val
}

// Get returns the value stored under key and whether it was present.
func (m *OrderedMap) Get(key string) (any, bool) {
	v, ok := m.values[key]
	return v, ok
}

// Keys returns the keys in insertion order.
func (m *OrderedMap) Keys() []string { return m.keys }

// Len reports the number of entries.
func (m *OrderedMap) Len() int { return len(m.keys) }

// marshalJSON renders a value as the gem's JSON.generate would: compact, and
// insertion-ordered for an *OrderedMap (sorted for a plain map, which has no order).
func marshalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeJSON(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// writeJSON is the compact encoder. It handles the object shapes specially to
// control key order and delegates every scalar / array to encoding/json (whose
// compact scalar rendering matches JSON.generate).
func writeJSON(buf *bytes.Buffer, v any) error {
	switch m := v.(type) {
	case *OrderedMap:
		return writeObject(buf, m.keys, func(k string) any { v, _ := m.Get(k); return v })
	case map[string]any:
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return writeObject(buf, keys, func(k string) any { return m[k] })
	case []any:
		buf.WriteByte('[')
		for i, e := range m {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeJSON(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	default:
		// Scalars and any other JSON-encodable value. json.Marshal on a scalar is
		// already compact and matches JSON.generate's rendering.
		b, err := json.Marshal(v)
		if err != nil {
			return newError(ErrEncode, fmt.Sprintf("cannot encode value of type %T", v))
		}
		buf.Write(b)
		return nil
	}
}

// writeObject emits {"k":v,...} for the given keys in order, recursing on values.
func writeObject(buf *bytes.Buffer, keys []string, get func(string) any) error {
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		buf.Write(kb)
		buf.WriteByte(':')
		if err := writeJSON(buf, get(k)); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

// unmarshalJSON parses a JSON object into an *OrderedMap, preserving key order (so
// a decoded header/payload round-trips), with nested objects also ordered.
func unmarshalJSON(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	v, err := decodeValue(dec)
	if err != nil {
		return nil, err
	}
	// Reject trailing garbage so a malformed segment is caught, matching the gem's
	// "Invalid segment encoding".
	if dec.More() {
		return nil, newError(ErrDecode, "Invalid segment encoding")
	}
	return v, nil
}

// decodeValue reads one JSON value, materialising objects as *OrderedMap.
func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, newError(ErrDecode, "Invalid segment encoding")
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			return decodeObject(dec)
		case '[':
			return decodeArray(dec)
		default:
			return nil, newError(ErrDecode, "Invalid segment encoding")
		}
	default:
		return t, nil
	}
}

// decodeObject reads an object body (the opening '{' already consumed) into order.
func decodeObject(dec *json.Decoder) (any, error) {
	m := NewOrderedMap()
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, newError(ErrDecode, "Invalid segment encoding")
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, newError(ErrDecode, "Invalid segment encoding")
		}
		val, err := decodeValue(dec)
		if err != nil {
			return nil, err
		}
		m.Set(key, val)
	}
	if _, err := dec.Token(); err != nil { // consume '}'
		return nil, newError(ErrDecode, "Invalid segment encoding")
	}
	return m, nil
}

// decodeArray reads an array body (the opening '[' already consumed).
func decodeArray(dec *json.Decoder) (any, error) {
	arr := []any{}
	for dec.More() {
		v, err := decodeValue(dec)
		if err != nil {
			return nil, err
		}
		arr = append(arr, v)
	}
	if _, err := dec.Token(); err != nil { // consume ']'
		return nil, newError(ErrDecode, "Invalid segment encoding")
	}
	return arr, nil
}
