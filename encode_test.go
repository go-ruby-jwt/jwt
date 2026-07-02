// Copyright (c) the go-ruby-jwt/jwt authors
//
// SPDX-License-Identifier: BSD-3-Clause

package jwt

import (
	"strings"
	"testing"
)

// TestEncodeGoldenHMAC asserts our HS* tokens are byte-identical to the gem's
// golden vectors — the ruby-free proof of HMAC parity.
func TestEncodeGoldenHMAC(t *testing.T) {
	cases := map[string]string{"HS256": goldenHS256, "HS384": goldenHS384, "HS512": goldenHS512}
	for alg, want := range cases {
		got, err := Encode(goldenPayload(), goldenSecret, alg, nil)
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		if got != want {
			t.Errorf("%s token\n got %q\nwant %q", alg, got, want)
		}
	}
}

// TestEncodeGoldenRSA asserts our RS* (deterministic PKCS1v15) tokens match the
// gem's golden vectors byte-for-byte.
func TestEncodeGoldenRSA(t *testing.T) {
	key := loadRSAPrivate(t)
	cases := map[string]string{"RS256": goldenRS256, "RS384": goldenRS384, "RS512": goldenRS512}
	for alg, want := range cases {
		got, err := Encode(goldenPayload(), key, alg, nil)
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		if got != want {
			t.Errorf("%s token\n got %q\nwant %q", alg, got, want)
		}
	}
}

// TestEncodeSecretBytes covers an HMAC secret given as a []byte (not string).
func TestEncodeSecretBytes(t *testing.T) {
	got, err := Encode(goldenPayload(), []byte(goldenSecret), "HS256", nil)
	if err != nil || got != goldenHS256 {
		t.Fatalf("bytes secret: %q %v", got, err)
	}
}

// TestEncodeHeaderOrdering covers the gem's header rule: custom fields precede an
// appended "alg", but an explicit "alg" in header_fields keeps its position/value.
func TestEncodeHeaderOrdering(t *testing.T) {
	// custom field, alg appended.
	h := NewOrderedMap()
	h.Set("kid", "x")
	tok, err := Encode(NewOrderedMap(), goldenSecret, "HS256", h)
	if err != nil {
		t.Fatal(err)
	}
	if got := decodeHeaderJSON(t, tok); got != `{"kid":"x","alg":"HS256"}` {
		t.Errorf("header = %s", got)
	}

	// explicit alg keeps position + value.
	h2 := NewOrderedMap()
	h2.Set("alg", "OVERRIDE")
	h2.Set("kid", "x")
	tok2, _ := Encode(NewOrderedMap(), goldenSecret, "HS256", h2)
	if got := decodeHeaderJSON(t, tok2); got != `{"alg":"OVERRIDE","kid":"x"}` {
		t.Errorf("override header = %s", got)
	}
}

// TestEncodeHeaderPlainMap covers a plain map[string]any header (sorted keys) and a
// plain map payload.
func TestEncodeHeaderPlainMap(t *testing.T) {
	tok, err := Encode(map[string]any{"b": 2, "a": 1}, goldenSecret, "HS256",
		map[string]any{"typ": "JWT", "cty": "x"})
	if err != nil {
		t.Fatal(err)
	}
	// header keys sorted (cty,typ) then alg; payload keys sorted (a,b).
	if got := decodeHeaderJSON(t, tok); got != `{"cty":"x","typ":"JWT","alg":"HS256"}` {
		t.Errorf("header = %s", got)
	}
}

// TestEncodeNone covers the unsecured algorithm: empty signature, trailing dot.
func TestEncodeNone(t *testing.T) {
	tok, err := Encode(map[string]any{"a": 1}, nil, "none", nil)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "eyJhbGciOiJub25lIn0.eyJhIjoxfQ." {
		t.Errorf("none = %q", tok)
	}
}

// TestEncodeNilPayload covers the empty-object body.
func TestEncodeNilPayload(t *testing.T) {
	tok, err := Encode(nil, goldenSecret, "HS256", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := decodePayloadJSON(t, tok); got != "{}" {
		t.Errorf("payload = %s", got)
	}
}

// TestEncodeUnsupportedAlg covers the unknown-algorithm error.
func TestEncodeUnsupportedAlg(t *testing.T) {
	_, err := Encode(nil, goldenSecret, "HS999", nil)
	if err == nil || !strings.Contains(err.Error(), "Unsupported signing method") {
		t.Fatalf("want unsupported error, got %v", err)
	}
}

// TestEncodeBadKeyType covers each signer's key-type guard.
func TestEncodeBadKeyType(t *testing.T) {
	for _, alg := range []string{"HS256", "RS256", "ES256", "PS256"} {
		if _, err := Encode(nil, 12345, alg, nil); err == nil {
			t.Errorf("%s: want key-type error", alg)
		}
	}
}

// TestEncodeBadPayloadValue covers a payload value JSON cannot encode.
func TestEncodeBadPayloadValue(t *testing.T) {
	if _, err := Encode(map[string]any{"c": make(chan int)}, goldenSecret, "HS256", nil); err == nil {
		t.Fatal("want encode error for chan value")
	}
	// Also in nested array and header.
	if _, err := Encode([]any{make(chan int)}, goldenSecret, "HS256", nil); err == nil {
		t.Fatal("want encode error for array chan")
	}
	h := NewOrderedMap()
	h.Set("x", make(chan int))
	if _, err := Encode(nil, goldenSecret, "HS256", h); err == nil {
		t.Fatal("want encode error for header chan")
	}
}

// decodeHeaderJSON returns the token's decoded header JSON text.
func decodeHeaderJSON(t *testing.T, tok string) string {
	t.Helper()
	b, err := decodeSegment(strings.Split(tok, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// decodePayloadJSON returns the token's decoded payload JSON text.
func decodePayloadJSON(t *testing.T, tok string) string {
	t.Helper()
	b, err := decodeSegment(strings.Split(tok, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
