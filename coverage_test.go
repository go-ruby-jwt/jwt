// Copyright (c) the go-ruby-jwt/jwt authors
//
// SPDX-License-Identifier: BSD-3-Clause

package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

// TestDecodeSegmentPaddedFallback covers the padded-base64url fallback in
// decodeSegment: a segment that carries explicit "=" padding still decodes.
func TestDecodeSegmentPaddedFallback(t *testing.T) {
	// base64url of "hi" is "aGk"; the padded form "aGk=" fails RawURLEncoding but
	// succeeds under URLEncoding (the lenient fallback).
	padded := base64.URLEncoding.EncodeToString([]byte("hi"))
	got, err := decodeSegment(padded)
	if err != nil || string(got) != "hi" {
		t.Fatalf("padded fallback: %q %v", got, err)
	}
}

// TestDecodeArrayPayload decodes a token whose payload is a JSON array, covering
// decodeArray and the nested decodeValue recursion.
func TestDecodeArrayPayload(t *testing.T) {
	tok := signStringPayload(t, `[1,"two",[3],{"k":"v"}]`)
	pl, _, err := Decode(tok, goldenSecret, true, Options{Algorithms: []string{"HS256"}})
	if err != nil {
		t.Fatalf("array payload: %v", err)
	}
	arr, ok := pl.([]any)
	if !ok || len(arr) != 4 {
		t.Fatalf("array = %#v", pl)
	}
	// Nested object round-tripped to *OrderedMap.
	if _, ok := arr[3].(*OrderedMap); !ok {
		t.Errorf("nested obj = %T", arr[3])
	}
}

// TestDecodeJSONErrorPaths covers the malformed-JSON error branches in json.go:
// a bad top-level token, a non-string object key, a truncated object, and a
// truncated array.
func TestDecodeJSONErrorPaths(t *testing.T) {
	cases := []string{
		`}`,          // decodeValue: leading '}' delim (not '{'/'[')
		`{1:2}`,      // decodeObject: non-string key
		`{"a":1`,     // decodeObject: missing closing '}'
		`[1,2`,       // decodeArray: missing closing ']'
		`{"a":}`,     // decodeObject: bad value token
		`[}]`,        // decodeArray: bad element token
		``,           // decodeValue: empty input (token error)
		`{"a" 1}`,    // decodeObject: value read finds no ':' structure
	}
	for _, body := range cases {
		tok := signStringPayload(t, body)
		if _, _, err := Decode(tok, goldenSecret, true, Options{Algorithms: []string{"HS256"}}); !errors.Is(err, ErrDecode) {
			t.Errorf("body %q: got %v, want DecodeError", body, err)
		}
	}
}

// TestDecodeObjectKeyTokenError covers decodeObject's key-token read error via a
// stream that ends right after '{' with an unterminated string key.
func TestDecodeObjectKeyTokenError(t *testing.T) {
	tok := signStringPayload(t, `{"a`)
	if _, _, err := Decode(tok, goldenSecret, true, Options{Algorithms: []string{"HS256"}}); !errors.Is(err, ErrDecode) {
		t.Errorf("unterminated key: %v", err)
	}
}

// TestEcdsaSigLenAll covers all three curve lengths (SHA256/384/512) by signing and
// verifying real ES384/ES512 tokens (the fixture is only P-256).
func TestEcdsaSigLenAll(t *testing.T) {
	pairs := []struct {
		curve elliptic.Curve
		alg   string
	}{
		{elliptic.P256(), "ES256"},
		{elliptic.P384(), "ES384"},
		{elliptic.P521(), "ES512"},
	}
	for _, p := range pairs {
		priv, err := ecdsa.GenerateKey(p.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tok, err := Encode(map[string]any{"a": 1}, priv, p.alg, nil)
		if err != nil {
			t.Fatalf("%s encode: %v", p.alg, err)
		}
		if _, _, err := Decode(tok, &priv.PublicKey, true, Options{Algorithms: []string{p.alg}}); err != nil {
			t.Errorf("%s verify: %v", p.alg, err)
		}
	}
}

// TestVerifyKeyExtractionErrors covers the rsaPublic/ecdsaPublic non-key branches
// reached from verifyRSA/verifyPSS/verifyECDSA (they collapse to verificationFailed).
func TestVerifyKeyExtractionErrors(t *testing.T) {
	// RS256 verify with a nil key → rsaPublic default branch.
	if err := verifyRSA(nil, []byte("in"), []byte("sig"), crypto.SHA256); !errors.Is(err, ErrVerification) {
		t.Errorf("verifyRSA nil key: %v", err)
	}
	// PS256 verify with a wrong key type.
	if err := verifyPSS(42, []byte("in"), []byte("sig"), crypto.SHA256); !errors.Is(err, ErrVerification) {
		t.Errorf("verifyPSS bad key: %v", err)
	}
	// ES256 verify with a wrong key type.
	if err := verifyECDSA("str", []byte("in"), []byte("sig"), crypto.SHA256); !errors.Is(err, ErrVerification) {
		t.Errorf("verifyECDSA bad key: %v", err)
	}
	// rsaPublic / ecdsaPublic accept a private key (public-half extraction).
	if _, err := rsaPublic(loadRSAPrivate(t)); err != nil {
		t.Errorf("rsaPublic(priv): %v", err)
	}
	if _, err := ecdsaPublic(loadECPrivate(t)); err != nil {
		t.Errorf("ecdsaPublic(priv): %v", err)
	}
}

// TestVerifyRSAWrongSignature covers verifyRSA's VerifyPKCS1v15-fails branch with a
// valid public key but a garbage signature (distinct from the key-extraction path).
func TestVerifyRSAWrongSignature(t *testing.T) {
	pub := loadRSAPublic(t)
	if err := verifyRSA(pub, []byte("in"), []byte("garbage"), crypto.SHA256); !errors.Is(err, ErrVerification) {
		t.Errorf("verifyRSA bad sig: %v", err)
	}
	if err := verifyPSS(pub, []byte("in"), []byte("garbage"), crypto.SHA256); !errors.Is(err, ErrVerification) {
		t.Errorf("verifyPSS bad sig: %v", err)
	}
	ecPub := loadECPublic(t)
	// Correct length (P-256 → 64) but wrong content.
	if err := verifyECDSA(ecPub, []byte("in"), make([]byte, 64), crypto.SHA256); !errors.Is(err, ErrVerification) {
		t.Errorf("verifyECDSA bad sig: %v", err)
	}
}

// TestHMACVerifyKeyError covers verifyHMAC's signHMAC-fails branch (a key that is
// neither string nor []byte).
func TestHMACVerifyKeyError(t *testing.T) {
	if err := verifyHMAC(3.14, []byte("in"), []byte("sig"), crypto.SHA256); !errors.Is(err, ErrVerification) {
		t.Errorf("verifyHMAC bad key: %v", err)
	}
}

// TestErrorHierarchy covers the error constructors and the family Unwrap chain,
// including newError's plain-root branch.
func TestErrorHierarchy(t *testing.T) {
	// A concrete sub-error Is both its own sentinel and the DecodeError root.
	e := newError(ErrExpiredSignature, "boom")
	if !errors.Is(e, ErrExpiredSignature) || !errors.Is(e, ErrDecode) {
		t.Errorf("chain: %v", e)
	}
	if e.Error() != "boom" {
		t.Errorf("message = %q", e.Error())
	}
	// newError over a plain errors.New root (ErrEncode) uses its Error() as Kind.
	enc := newError(ErrEncode, "cannot")
	if enc.Kind != "JWT::EncodeError" || !errors.Is(enc, ErrEncode) {
		t.Errorf("encode error: %+v", enc)
	}
}
