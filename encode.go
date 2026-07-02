// Copyright (c) the go-ruby-jwt/jwt authors
//
// SPDX-License-Identifier: BSD-3-Clause

package jwt

import "sort"

// Encode builds a signed JWS compact token from a payload, mirroring the gem's
// JWT.encode(payload, key, algorithm, header_fields).
//
// The header is header_fields with "alg" set to algorithm: if header_fields
// already carries an "alg" key its position (and value) is kept, otherwise "alg"
// is appended last — exactly the gem's ordering. The header and payload are
// serialised with order-preserving compact JSON, base64url-encoded (no padding),
// joined with ".", signed, and the base64url signature appended.
//
// key is the signing key for the chosen algorithm: an HMAC secret (string /
// []byte) for HS*, an *rsa.PrivateKey for RS*/PS*, an *ecdsa.PrivateKey for ES*.
// For the unsecured "none" algorithm key is ignored and the signature is empty.
//
// payload and header_fields may be an *OrderedMap (to pin order), a
// map[string]any, or nil (header only — header_fields nil means just {"alg":...}).
func Encode(payload any, key any, algorithm string, headerFields any) (string, error) {
	header := buildHeader(algorithm, headerFields)

	headerJSON, err := marshalJSON(header)
	if err != nil {
		return "", err
	}
	payloadJSON, err := marshalJSON(payloadOrEmpty(payload))
	if err != nil {
		return "", err
	}

	signingInput := encodeSegment(headerJSON) + "." + encodeSegment(payloadJSON)

	if algorithm == "none" {
		// Unsecured JWS (RFC 7515 App. A.5): empty signature, trailing dot.
		return signingInput + ".", nil
	}

	s := lookupSigner(algorithm)
	if s == nil {
		return "", newError(ErrEncode, "Unsupported signing method "+algorithm)
	}
	sig, err := s.sign(key, []byte(signingInput), s.hash)
	if err != nil {
		return "", err
	}
	return signingInput + "." + encodeSegment(sig), nil
}

// buildHeader produces the JWS header: header_fields with "alg" set. When
// header_fields already carries "alg", the gem keeps its position and value;
// otherwise "alg" is appended. A nil header_fields yields just {"alg":algorithm}.
func buildHeader(algorithm string, headerFields any) *OrderedMap {
	out := NewOrderedMap()
	switch h := headerFields.(type) {
	case nil:
		// no custom fields
	case *OrderedMap:
		for _, k := range h.keys {
			v, _ := h.Get(k)
			out.Set(k, v)
		}
	case map[string]any:
		// A plain map has no order; emit its keys sorted for determinism, then
		// let the "alg" rule below place alg.
		for _, k := range sortedKeys(h) {
			out.Set(k, h[k])
		}
	}
	if _, ok := out.Get("alg"); !ok {
		out.Set("alg", algorithm)
	}
	return out
}

// payloadOrEmpty maps a nil payload to an empty ordered object, so Encode(nil,...)
// yields the "{}" body the gem produces for an empty claim set.
func payloadOrEmpty(payload any) any {
	if payload == nil {
		return NewOrderedMap()
	}
	return payload
}

// sortedKeys returns a plain map's keys in sorted order (a plain Go map is
// unordered, so we choose a deterministic order).
func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
