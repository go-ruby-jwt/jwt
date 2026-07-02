// Copyright (c) the go-ruby-jwt/jwt authors
//
// SPDX-License-Identifier: BSD-3-Clause

package jwt

import (
	"errors"
	"testing"
)

// TestDecodeGoldenHMAC round-trips the golden HS* tokens: our decoder verifies the
// gem's bytes and returns the payload + header.
func TestDecodeGoldenHMAC(t *testing.T) {
	cases := map[string]string{"HS256": goldenHS256, "HS384": goldenHS384, "HS512": goldenHS512}
	for alg, tok := range cases {
		pl, hdr, err := Decode(tok, goldenSecret, true, Options{Algorithms: []string{alg}})
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		claims := pl.(*OrderedMap)
		if u, _ := claims.Get("user"); u != "amy" {
			t.Errorf("%s user = %v", alg, u)
		}
		if a, _ := hdr.(*OrderedMap).Get("alg"); a != alg {
			t.Errorf("%s header alg = %v", alg, a)
		}
	}
}

// TestDecodeGoldenRSA verifies the golden RS* tokens against the public key.
func TestDecodeGoldenRSA(t *testing.T) {
	pub := loadRSAPublic(t)
	cases := map[string]string{"RS256": goldenRS256, "RS384": goldenRS384, "RS512": goldenRS512}
	for alg, tok := range cases {
		if _, _, err := Decode(tok, pub, true, Options{Algorithms: []string{alg}}); err != nil {
			t.Errorf("%s: %v", alg, err)
		}
	}
}

// TestRoundTripAll signs and verifies with every algorithm, including the non-
// deterministic ES*/PS* (self round-trip), and cross-checks against a public key.
func TestRoundTripAll(t *testing.T) {
	rsa := loadRSAPrivate(t)
	rsaPub := loadRSAPublic(t)
	ec := loadECPrivate(t)
	ecPub := loadECPublic(t)

	type kp struct{ priv, pub any }
	keys := map[string]kp{
		"HS256": {goldenSecret, goldenSecret}, "HS384": {goldenSecret, goldenSecret}, "HS512": {goldenSecret, goldenSecret},
		"RS256": {rsa, rsaPub}, "RS384": {rsa, rsaPub}, "RS512": {rsa, rsaPub},
		"PS256": {rsa, rsaPub}, "PS384": {rsa, rsaPub}, "PS512": {rsa, rsaPub},
		"ES256": {ec, ecPub}, "ES384": {ec, ecPub}, "ES512": {ec, ecPub},
	}
	// ES384/ES512 need matching curves; our fixture is P-256, so only ES256 works
	// with it — drop the mismatched ones and cover them via the oracle instead.
	delete(keys, "ES384")
	delete(keys, "ES512")

	for alg, k := range keys {
		tok, err := Encode(map[string]any{"x": 1}, k.priv, alg, nil)
		if err != nil {
			t.Fatalf("%s encode: %v", alg, err)
		}
		if _, _, err := Decode(tok, k.pub, true, Options{Algorithms: []string{alg}}); err != nil {
			t.Errorf("%s verify: %v", alg, err)
		}
		// Also verify the private key is accepted on the verify side.
		if _, _, err := Decode(tok, k.priv, true, Options{Algorithms: []string{alg}}); err != nil {
			t.Errorf("%s verify (priv): %v", alg, err)
		}
	}
}

// TestDecodeNoVerify covers verify=false: no key, no algorithm needed.
func TestDecodeNoVerify(t *testing.T) {
	pl, _, err := Decode(goldenHS256, nil, false, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if u, _ := pl.(*OrderedMap).Get("user"); u != "amy" {
		t.Errorf("user = %v", u)
	}
}

// TestDecodeNone covers verifying an unsecured token when "none" is allowed, and
// rejecting a "none" token that carries a signature.
func TestDecodeNone(t *testing.T) {
	tok, _ := Encode(map[string]any{"a": 1}, nil, "none", nil)
	if _, _, err := Decode(tok, nil, true, Options{Algorithms: []string{"none"}}); err != nil {
		t.Fatalf("none allowed: %v", err)
	}
	// A none token with a non-empty signature must fail.
	bad := tok + "AAAA"
	if _, _, err := Decode(bad[:len(bad)-4]+"QUFB", nil, true, Options{Algorithms: []string{"none"}}); err == nil {
		t.Fatal("want verification error for signed none")
	}
}

// TestDecodeSegmentErrors covers segment-count and base64/JSON decode failures.
func TestDecodeSegmentErrors(t *testing.T) {
	cases := []struct{ name, tok, kind string }{
		{"one segment", "abc", "JWT::DecodeError"},
		{"four segments", "a.b.c.d", "JWT::DecodeError"},
		{"bad base64 header", "!!!.eyJhIjoxfQ.", "JWT::Base64DecodeError"},
		{"bad base64 payload", "eyJhbGciOiJub25lIn0.!!!.", "JWT::Base64DecodeError"},
		{"bad base64 sig", "eyJhbGciOiJub25lIn0.eyJhIjoxfQ.!!!", "JWT::Base64DecodeError"},
	}
	for _, c := range cases {
		_, _, err := Decode(c.tok, goldenSecret, false, Options{})
		var e *Error
		if !errors.As(err, &e) || e.Kind != c.kind {
			t.Errorf("%s: got %v, want kind %s", c.name, err, c.kind)
		}
		if !errors.Is(err, ErrDecode) {
			t.Errorf("%s: not in DecodeError family", c.name)
		}
	}
}

// TestDecodeBadJSON covers a segment that base64-decodes but is not a JSON object.
func TestDecodeBadJSON(t *testing.T) {
	// "abc" (not JSON) base64url = YWJj.
	if _, _, err := Decode("YWJj.YWJj.", goldenSecret, false, Options{}); err == nil {
		t.Fatal("want decode error for non-JSON segment")
	}
	// Trailing garbage after a valid object.
	// {"a":1}{  -> base64url
	if _, _, err := Decode(encodeSegment([]byte(`{"a":1}x`))+".eyJhIjoxfQ.", goldenSecret, false, Options{}); err == nil {
		t.Fatal("want decode error for trailing garbage")
	}
}

// TestVerifyAlgorithmGuard covers the alg-confusion rejections.
func TestVerifyAlgorithmGuard(t *testing.T) {
	// Wrong alg in allow-list.
	_, _, err := Decode(goldenHS256, goldenSecret, true, Options{Algorithms: []string{"HS512"}})
	if !errors.Is(err, ErrIncorrectAlgorithm) {
		t.Errorf("mismatch: %v", err)
	}
	// Empty allow-list.
	_, _, err = Decode(goldenHS256, goldenSecret, true, Options{Algorithms: nil})
	if !errors.Is(err, ErrIncorrectAlgorithm) {
		t.Errorf("empty: %v", err)
	}
	// Unknown alg in token but present in list → no signer.
	tok := encodeSegment([]byte(`{"alg":"HS999"}`)) + "." + encodeSegment([]byte(`{"a":1}`)) + ".AAAA"
	_, _, err = Decode(tok, goldenSecret, true, Options{Algorithms: []string{"HS999"}})
	if !errors.Is(err, ErrIncorrectAlgorithm) {
		t.Errorf("unknown-but-listed: %v", err)
	}
	// alg missing from header entirely (non-OrderedMap path already covered; here a
	// header object with no alg key).
	tok2 := encodeSegment([]byte(`{"typ":"JWT"}`)) + "." + encodeSegment([]byte(`{"a":1}`)) + ".AAAA"
	_, _, err = Decode(tok2, goldenSecret, true, Options{Algorithms: []string{"HS256"}})
	if !errors.Is(err, ErrIncorrectAlgorithm) {
		t.Errorf("no-alg: %v", err)
	}
}

// TestVerifyBadSignature covers a wrong-key signature failure across families.
func TestVerifyBadSignature(t *testing.T) {
	if _, _, err := Decode(goldenHS256, "wrong", true, Options{Algorithms: []string{"HS256"}}); !errors.Is(err, ErrVerification) {
		t.Errorf("HS bad sig: %v", err)
	}
	// RSA/EC/PS wrong-key: verify with an unrelated key type triggers the
	// verificationFailed path (public-key extraction fails).
	if _, _, err := Decode(goldenRS256, "not-a-key", true, Options{Algorithms: []string{"RS256"}}); !errors.Is(err, ErrVerification) {
		t.Errorf("RS bad key: %v", err)
	}
	ecTok, _ := Encode(map[string]any{"a": 1}, loadECPrivate(t), "ES256", nil)
	if _, _, err := Decode(ecTok, "not-a-key", true, Options{Algorithms: []string{"ES256"}}); !errors.Is(err, ErrVerification) {
		t.Errorf("ES bad key: %v", err)
	}
	psTok, _ := Encode(map[string]any{"a": 1}, loadRSAPrivate(t), "PS256", nil)
	if _, _, err := Decode(psTok, "not-a-key", true, Options{Algorithms: []string{"PS256"}}); !errors.Is(err, ErrVerification) {
		t.Errorf("PS bad key: %v", err)
	}
	// ES256 signature of wrong length.
	shortES := encodeSegment([]byte(`{"alg":"ES256"}`)) + "." + encodeSegment([]byte(`{"a":1}`)) + "." + encodeSegment([]byte("short"))
	if _, _, err := Decode(shortES, loadECPublic(t), true, Options{Algorithms: []string{"ES256"}}); !errors.Is(err, ErrVerification) {
		t.Errorf("ES short sig: %v", err)
	}
	// HMAC with a non-string/bytes key on verify.
	if _, _, err := Decode(goldenHS256, 999, true, Options{Algorithms: []string{"HS256"}}); !errors.Is(err, ErrVerification) {
		t.Errorf("HS bad key type: %v", err)
	}
}

// TestDecodeHeaderNonObject covers a header that is valid JSON but not an object,
// so alg lookup yields "".
func TestDecodeHeaderNonObject(t *testing.T) {
	tok := encodeSegment([]byte(`"nothdr"`)) + "." + encodeSegment([]byte(`{"a":1}`)) + ".AAAA"
	if _, _, err := Decode(tok, goldenSecret, true, Options{Algorithms: []string{"HS256"}}); !errors.Is(err, ErrIncorrectAlgorithm) {
		t.Errorf("non-object header: %v", err)
	}
}
