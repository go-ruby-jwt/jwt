// Copyright (c) the go-ruby-jwt/jwt authors
//
// SPDX-License-Identifier: BSD-3-Clause

package jwt

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// fixedNow pins the claim-validation clock to a known instant for the duration of
// a test, restoring time.Now afterwards. Every exp/nbf/iat vector reads it.
func fixedNow(t *testing.T, unix int64) {
	t.Helper()
	prev := nowFunc
	nowFunc = func() time.Time { return time.Unix(unix, 0) }
	t.Cleanup(func() { nowFunc = prev })
}

// tokenWith signs an ordered claim set with HS256 so the claim-validation paths run
// on a verified token (the golden secret keeps it deterministic).
func tokenWith(t *testing.T, pairs ...any) string {
	t.Helper()
	m := NewOrderedMap()
	for i := 0; i+1 < len(pairs); i += 2 {
		m.Set(pairs[i].(string), pairs[i+1])
	}
	tok, err := Encode(m, goldenSecret, "HS256", nil)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return tok
}

// decodeClaims verifies tok with HS256 under opts and returns the error.
func decodeClaims(tok string, opts Options) error {
	opts.Algorithms = []string{"HS256"}
	_, _, err := Decode(tok, goldenSecret, true, opts)
	return err
}

// TestVerifyExp covers the exp branches: valid, expired, leeway rescue, the
// per-claim ExpLeeway override, disabling via VerifyExpirationSet, and a bad type.
func TestVerifyExp(t *testing.T) {
	fixedNow(t, 1000)

	// Not yet expired.
	if err := decodeClaims(tokenWith(t, "exp", 2000), Options{}); err != nil {
		t.Errorf("valid exp: %v", err)
	}
	// Expired.
	if err := decodeClaims(tokenWith(t, "exp", 500), Options{}); !errors.Is(err, ErrExpiredSignature) {
		t.Errorf("expired: %v", err)
	}
	if err := decodeClaims(tokenWith(t, "exp", 500), Options{}); err == nil ||
		!strings.Contains(err.Error(), "Signature has expired") {
		t.Errorf("expired message: %v", err)
	}
	// Expired but inside global leeway.
	if err := decodeClaims(tokenWith(t, "exp", 500), Options{Leeway: 600}); err != nil {
		t.Errorf("exp leeway rescue: %v", err)
	}
	// ExpLeeway override (global leeway too small, exp-specific big enough).
	el := int64(600)
	if err := decodeClaims(tokenWith(t, "exp", 500), Options{Leeway: 1, ExpLeeway: &el}); err != nil {
		t.Errorf("ExpLeeway override: %v", err)
	}
	// Disabled: an expired exp is ignored when VerifyExpiration=false.
	if err := decodeClaims(tokenWith(t, "exp", 500),
		Options{VerifyExpirationSet: true, VerifyExpiration: false}); err != nil {
		t.Errorf("exp disabled: %v", err)
	}
	// No exp claim → nothing to check.
	if err := decodeClaims(tokenWith(t, "a", 1), Options{}); err != nil {
		t.Errorf("no exp: %v", err)
	}
	// Non-numeric exp → InvalidPayload.
	if err := decodeClaims(tokenWith(t, "exp", "soon"), Options{}); !errors.Is(err, ErrInvalidPayload) {
		t.Errorf("bad exp type: %v", err)
	}
	if err := decodeClaims(tokenWith(t, "exp", "soon"), Options{}); err == nil ||
		!strings.Contains(err.Error(), "exp claim must be a Numeric value but it is a String") {
		t.Errorf("bad exp message: %v", err)
	}
}

// TestVerifyNbf covers the nbf branches: valid, immature, leeway rescue, the
// NbfLeeway override, disabling, and a bad type.
func TestVerifyNbf(t *testing.T) {
	fixedNow(t, 1000)

	// Already mature.
	if err := decodeClaims(tokenWith(t, "nbf", 500), Options{}); err != nil {
		t.Errorf("mature nbf: %v", err)
	}
	// Immature.
	if err := decodeClaims(tokenWith(t, "nbf", 2000), Options{}); !errors.Is(err, ErrImmatureSignature) {
		t.Errorf("immature: %v", err)
	}
	if err := decodeClaims(tokenWith(t, "nbf", 2000), Options{}); err == nil ||
		!strings.Contains(err.Error(), "Signature nbf has not been reached") {
		t.Errorf("immature message: %v", err)
	}
	// Immature but inside global leeway.
	if err := decodeClaims(tokenWith(t, "nbf", 1500), Options{Leeway: 600}); err != nil {
		t.Errorf("nbf leeway rescue: %v", err)
	}
	// NbfLeeway override.
	nl := int64(600)
	if err := decodeClaims(tokenWith(t, "nbf", 1500), Options{Leeway: 1, NbfLeeway: &nl}); err != nil {
		t.Errorf("NbfLeeway override: %v", err)
	}
	// Disabled.
	if err := decodeClaims(tokenWith(t, "nbf", 2000),
		Options{VerifyNotBeforeSet: true, VerifyNotBefore: false}); err != nil {
		t.Errorf("nbf disabled: %v", err)
	}
	// No nbf.
	if err := decodeClaims(tokenWith(t, "a", 1), Options{}); err != nil {
		t.Errorf("no nbf: %v", err)
	}
	// Bad type.
	if err := decodeClaims(tokenWith(t, "nbf", "later"), Options{}); !errors.Is(err, ErrInvalidPayload) {
		t.Errorf("bad nbf type: %v", err)
	}
}

// TestVerifyIat covers the iat branches (off by default, present/future/bad type,
// and the leeway on the future check).
func TestVerifyIat(t *testing.T) {
	fixedNow(t, 1000)

	// Off by default: a future iat is ignored when VerifyIat is false.
	if err := decodeClaims(tokenWith(t, "iat", 9999), Options{}); err != nil {
		t.Errorf("iat off: %v", err)
	}
	// On, valid (past iat).
	if err := decodeClaims(tokenWith(t, "iat", 500), Options{VerifyIat: true}); err != nil {
		t.Errorf("iat valid: %v", err)
	}
	// On, future iat → InvalidIat.
	if err := decodeClaims(tokenWith(t, "iat", 9999), Options{VerifyIat: true}); !errors.Is(err, ErrInvalidIat) {
		t.Errorf("iat future: %v", err)
	}
	// Future iat rescued by leeway.
	if err := decodeClaims(tokenWith(t, "iat", 1100), Options{VerifyIat: true, Leeway: 200}); err != nil {
		t.Errorf("iat leeway: %v", err)
	}
	// On, no iat present.
	if err := decodeClaims(tokenWith(t, "a", 1), Options{VerifyIat: true}); err != nil {
		t.Errorf("iat absent: %v", err)
	}
	// On, bad type.
	if err := decodeClaims(tokenWith(t, "iat", "now"), Options{VerifyIat: true}); !errors.Is(err, ErrInvalidIat) {
		t.Errorf("iat bad type: %v", err)
	}
}

// TestVerifyIss covers the issuer branches: single-issuer match/mismatch, a list of
// acceptable issuers, an absent iss, and the off-by-default path.
func TestVerifyIss(t *testing.T) {
	// Off by default.
	if err := decodeClaims(tokenWith(t, "iss", "bad"), Options{}); err != nil {
		t.Errorf("iss off: %v", err)
	}
	// Single issuer match.
	if err := decodeClaims(tokenWith(t, "iss", "me"),
		Options{VerifyIss: true, Issuer: "me"}); err != nil {
		t.Errorf("iss match: %v", err)
	}
	// Mismatch.
	err := decodeClaims(tokenWith(t, "iss", "them"), Options{VerifyIss: true, Issuer: "me"})
	if !errors.Is(err, ErrInvalidIssuer) {
		t.Errorf("iss mismatch: %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), `Invalid issuer. Expected ["me"], received them`) {
		t.Errorf("iss message: %v", err)
	}
	// List of acceptable issuers (match second entry).
	if err := decodeClaims(tokenWith(t, "iss", "b"),
		Options{VerifyIss: true, Issuer: []string{"a", "b"}}); err != nil {
		t.Errorf("iss list match: %v", err)
	}
	// List, []any form.
	if err := decodeClaims(tokenWith(t, "iss", "b"),
		Options{VerifyIss: true, Issuer: []any{"a", "b"}}); err != nil {
		t.Errorf("iss []any match: %v", err)
	}
	// Absent iss → <none> in message.
	err = decodeClaims(tokenWith(t, "a", 1), Options{VerifyIss: true, Issuer: "me"})
	if err == nil || !strings.Contains(err.Error(), "received <none>") {
		t.Errorf("iss absent message: %v", err)
	}
}

// TestVerifyAud covers the audience branches: string/list on both sides,
// intersection, mismatch messages (bare string vs Array#inspect), and off-default.
func TestVerifyAud(t *testing.T) {
	// Off by default.
	if err := decodeClaims(tokenWith(t, "aud", "x"), Options{}); err != nil {
		t.Errorf("aud off: %v", err)
	}
	// String token aud vs string expected.
	if err := decodeClaims(tokenWith(t, "aud", "cli"),
		Options{VerifyAud: true, Audience: "cli"}); err != nil {
		t.Errorf("aud match: %v", err)
	}
	// Array token aud intersecting a list expectation.
	if err := decodeClaims(tokenWith(t, "aud", []any{"a", "c"}),
		Options{VerifyAud: true, Audience: []string{"c", "d"}}); err != nil {
		t.Errorf("aud list intersect: %v", err)
	}
	// Mismatch, both scalars → bare-string message.
	err := decodeClaims(tokenWith(t, "aud", "web"), Options{VerifyAud: true, Audience: "cli"})
	if !errors.Is(err, ErrInvalidAud) {
		t.Errorf("aud mismatch: %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "Invalid audience. Expected cli, received web") {
		t.Errorf("aud scalar message: %v", err)
	}
	// Mismatch, list expectation + array token → Array#inspect message.
	err = decodeClaims(tokenWith(t, "aud", []any{"x", "y"}),
		Options{VerifyAud: true, Audience: []string{"a", "c"}})
	if err == nil || !strings.Contains(err.Error(), `Expected ["a", "c"], received ["x", "y"]`) {
		t.Errorf("aud list message: %v", err)
	}
	// Absent aud → received <none>.
	err = decodeClaims(tokenWith(t, "a", 1), Options{VerifyAud: true, Audience: "cli"})
	if err == nil || !strings.Contains(err.Error(), "received <none>") {
		t.Errorf("aud absent message: %v", err)
	}
	// Expected audience given as []any renders like a list.
	err = decodeClaims(tokenWith(t, "aud", "z"),
		Options{VerifyAud: true, Audience: []any{"a", "b"}})
	if err == nil || !strings.Contains(err.Error(), `Expected ["a", "b"]`) {
		t.Errorf("aud []any expected message: %v", err)
	}
	// Expected audience of an unusual type falls to fmt.Sprint.
	err = decodeClaims(tokenWith(t, "aud", "z"), Options{VerifyAud: true, Audience: 42})
	if err == nil || !strings.Contains(err.Error(), "Expected 42") {
		t.Errorf("aud int expected message: %v", err)
	}
}

// TestVerifySub covers subject match, mismatch, and absent.
func TestVerifySub(t *testing.T) {
	// Off by default.
	if err := decodeClaims(tokenWith(t, "sub", "x"), Options{}); err != nil {
		t.Errorf("sub off: %v", err)
	}
	// Match.
	if err := decodeClaims(tokenWith(t, "sub", "amy"),
		Options{VerifySub: true, Subject: "amy"}); err != nil {
		t.Errorf("sub match: %v", err)
	}
	// Mismatch.
	err := decodeClaims(tokenWith(t, "sub", "bob"), Options{VerifySub: true, Subject: "amy"})
	if !errors.Is(err, ErrInvalidSub) {
		t.Errorf("sub mismatch: %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "Invalid subject. Expected amy, received bob") {
		t.Errorf("sub message: %v", err)
	}
	// Absent.
	err = decodeClaims(tokenWith(t, "a", 1), Options{VerifySub: true, Subject: "amy"})
	if err == nil || !strings.Contains(err.Error(), "received <none>") {
		t.Errorf("sub absent message: %v", err)
	}
}

// TestVerifyJti covers the default present/non-empty rule and a custom validator.
func TestVerifyJti(t *testing.T) {
	// Off by default.
	if err := decodeClaims(tokenWith(t, "a", 1), Options{}); err != nil {
		t.Errorf("jti off: %v", err)
	}
	// Present, non-empty → ok.
	if err := decodeClaims(tokenWith(t, "jti", "abc"), Options{VerifyJti: true}); err != nil {
		t.Errorf("jti present: %v", err)
	}
	// Missing → InvalidJti "Missing jti".
	err := decodeClaims(tokenWith(t, "a", 1), Options{VerifyJti: true})
	if !errors.Is(err, ErrInvalidJti) || !strings.Contains(err.Error(), "Missing jti") {
		t.Errorf("jti missing: %v", err)
	}
	// Present but empty → Missing jti.
	if err := decodeClaims(tokenWith(t, "jti", ""), Options{VerifyJti: true}); !errors.Is(err, ErrInvalidJti) {
		t.Errorf("jti empty: %v", err)
	}
	// Custom validator accepts.
	if err := decodeClaims(tokenWith(t, "jti", "ok"),
		Options{VerifyJti: true, JtiValidator: func(any) bool { return true }}); err != nil {
		t.Errorf("jti validator ok: %v", err)
	}
	// Custom validator rejects → "Invalid jti".
	err = decodeClaims(tokenWith(t, "jti", "no"),
		Options{VerifyJti: true, JtiValidator: func(any) bool { return false }})
	if !errors.Is(err, ErrInvalidJti) || !strings.Contains(err.Error(), "Invalid jti") {
		t.Errorf("jti validator reject: %v", err)
	}
}

// TestVerifyRequired covers required-claim presence.
func TestVerifyRequired(t *testing.T) {
	// All present.
	if err := decodeClaims(tokenWith(t, "iss", "me", "sub", "amy"),
		Options{RequiredClaims: []string{"iss", "sub"}}); err != nil {
		t.Errorf("required present: %v", err)
	}
	// One missing → MissingRequiredClaim.
	err := decodeClaims(tokenWith(t, "iss", "me"), Options{RequiredClaims: []string{"iss", "sub"}})
	if !errors.Is(err, ErrMissingRequiredClaim) {
		t.Errorf("required missing: %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "Missing required claim sub") {
		t.Errorf("required message: %v", err)
	}
}

// TestVerifyClaimsNonObject covers a bare (non-object) payload: no claims to check.
func TestVerifyClaimsNonObject(t *testing.T) {
	// A string payload token, verified with jti-on and a required claim: the
	// non-object payload short-circuits verifyClaims before either fires.
	full := signStringPayload(t, `"amy"`)
	if err := decodeClaims(full, Options{VerifyJti: true, RequiredClaims: []string{"x"}}); err != nil {
		t.Errorf("non-object payload should skip claim checks: %v", err)
	}
}

// signStringPayload builds an HS256 token whose payload segment is the given raw
// JSON (used to exercise the non-object payload path in verifyClaims).
func signStringPayload(t *testing.T, rawJSON string) string {
	t.Helper()
	header := encodeSegment([]byte(`{"alg":"HS256"}`))
	payload := encodeSegment([]byte(rawJSON))
	in := header + "." + payload
	s := lookupSigner("HS256")
	sig, err := s.sign(goldenSecret, []byte(in), s.hash)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return in + "." + encodeSegment(sig)
}

// TestToFloatShapes covers every numeric shape toFloat accepts, and rubyClass.
func TestToFloatShapes(t *testing.T) {
	cases := []any{json.Number("12"), float64(3), int(4), int64(5)}
	for _, v := range cases {
		if _, ok := toFloat(v); !ok {
			t.Errorf("toFloat(%T) = false", v)
		}
	}
	// A json.Number that is not a float.
	if _, ok := toFloat(json.Number("not-a-number")); ok {
		t.Error("toFloat(bad json.Number) = true")
	}
	// Non-numeric.
	if _, ok := toFloat("x"); ok {
		t.Error("toFloat(string) = true")
	}

	// rubyClass over each mapped kind.
	want := map[string]any{
		"String":    "s",
		"TrueClass": true,
		"NilClass":  nil,
		"Array":     []any{1},
		"Hash":      NewOrderedMap(),
		"Object":    3.14,
	}
	for name, v := range want {
		if got := rubyClass(v); got != name {
			t.Errorf("rubyClass(%T) = %s, want %s", v, got, name)
		}
	}
}

// TestIssuerListShapes covers issuerList's nil and default (non-string) branches.
func TestIssuerListShapes(t *testing.T) {
	if issuerList(nil) != nil {
		t.Error("issuerList(nil) not nil")
	}
	// A non-string, non-slice issuer stringifies.
	if got := issuerList(42); len(got) != 1 || got[0] != "42" {
		t.Errorf("issuerList(42) = %v", got)
	}
}

// TestBadExpNumberFromToken decodes a token whose exp is a genuine JSON number, so
// numericClaim's json.Number path (not the int path from Go) is exercised.
func TestBadExpNumberFromToken(t *testing.T) {
	fixedNow(t, 1000)
	// exp far in the future as a JSON number literal.
	tok := signStringPayload(t, `{"exp":5000}`)
	if err := decodeClaims(tok, Options{}); err != nil {
		t.Errorf("json.Number exp: %v", err)
	}
	// nbf/iat as JSON numbers too.
	tok = signStringPayload(t, `{"nbf":100}`)
	if err := decodeClaims(tok, Options{}); err != nil {
		t.Errorf("json.Number nbf: %v", err)
	}
	tok = signStringPayload(t, `{"iat":100}`)
	if err := decodeClaims(tok, Options{VerifyIat: true}); err != nil {
		t.Errorf("json.Number iat: %v", err)
	}
}
