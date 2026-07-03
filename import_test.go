// Copyright (c) the go-ruby-jwt/jwt authors
//
// SPDX-License-Identifier: BSD-3-Clause

package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
)

// rsaJWKJSON renders the fixture RSA public key as a JWK JSON object with the given
// kid and (optional) alg/use.
func rsaJWKJSON(t *testing.T, kid, alg, use string) string {
	t.Helper()
	j, err := NewJWK(loadRSAPublic(t))
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf(`{"kty":"RSA","kid":%q,"alg":%q,"use":%q,"n":%q,"e":%q}`, kid, alg, use, j.N, j.E)
}

// ecJWKJSON renders the fixture EC public key as a JWK JSON object.
func ecJWKJSON(t *testing.T, kid string) string {
	t.Helper()
	j, err := NewJWK(loadECPublic(t))
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf(`{"kty":"EC","kid":%q,"crv":%q,"x":%q,"y":%q}`, kid, j.Crv, j.X, j.Y)
}

// TestParseJWKRSA imports a single RSA JWK and checks the provider fields and that
// the materialised key is usable.
func TestParseJWKRSA(t *testing.T) {
	jwk, err := ParseJWK([]byte(rsaJWKJSON(t, "k1", "RS256", "sig")))
	if err != nil {
		t.Fatalf("ParseJWK: %v", err)
	}
	if jwk.Kty != "RSA" || jwk.Kid != "k1" || jwk.Alg != "RS256" || jwk.Use != "sig" {
		t.Errorf("fields = %+v", jwk)
	}
	if jwk.PublicKey() == nil {
		t.Error("PublicKey nil")
	}
	// The imported key round-trips a real RS256 verification.
	h := NewOrderedMap()
	h.Set("kid", "k1")
	tok, err := Encode(map[string]any{"a": 1}, loadRSAPrivate(t), "RS256", h)
	if err != nil {
		t.Fatal(err)
	}
	set := NewJWKS(jwk)
	if _, _, err := Decode(tok, set, true, Options{Algorithms: []string{"RS256"}}); err != nil {
		t.Errorf("decode with imported JWK: %v", err)
	}
}

// TestParseJWKEC imports a single EC JWK.
func TestParseJWKEC(t *testing.T) {
	jwk, err := ParseJWK([]byte(ecJWKJSON(t, "e1")))
	if err != nil {
		t.Fatalf("ParseJWK EC: %v", err)
	}
	if jwk.Kty != "EC" || jwk.Kid != "e1" || jwk.Crv == "" || jwk.PublicKey() == nil {
		t.Errorf("EC JWK = %+v", jwk)
	}
	if _, ok := jwk.PublicKey().(*ecdsa.PublicKey); !ok {
		t.Errorf("EC public key type = %T", jwk.PublicKey())
	}
}

// TestParseJWKErrors covers ParseJWK's failure arms: malformed JSON and an
// unsupported key type (which ParseJWK, unlike ParseJWKS, rejects).
func TestParseJWKErrors(t *testing.T) {
	if _, err := ParseJWK([]byte("{not json")); !errors.Is(err, ErrJWK) {
		t.Errorf("malformed JSON: %v", err)
	}
	if _, err := ParseJWK([]byte(`{"kty":"oct","k":"AAAA"}`)); !errors.Is(err, ErrJWK) {
		t.Errorf("unsupported kty: %v", err)
	}
	// A supported type (RSA/EC) with bad material propagates the build error through
	// ParseJWK (covering jwkFromJSON's RSA and EC error arms).
	if _, err := ParseJWK([]byte(`{"kty":"RSA","kid":"k1","n":"@@@","e":"AQAB"}`)); !errors.Is(err, ErrJWK) {
		t.Errorf("bad RSA material via ParseJWK: %v", err)
	}
	if _, err := ParseJWK([]byte(`{"kty":"EC","kid":"e1","crv":"P-224","x":"AA","y":"AA"}`)); !errors.Is(err, ErrJWK) {
		t.Errorf("bad EC material via ParseJWK: %v", err)
	}
}

// TestParseJWKS imports a key set with an RSA and an EC key and selects each by kid.
func TestParseJWKS(t *testing.T) {
	body := fmt.Sprintf(`{"keys":[%s,%s]}`, rsaJWKJSON(t, "k1", "RS256", "sig"), ecJWKJSON(t, "e1"))
	set, err := ParseJWKS([]byte(body))
	if err != nil {
		t.Fatalf("ParseJWKS: %v", err)
	}
	if set.Find("k1") == nil || set.Find("e1") == nil {
		t.Fatal("kid lookup failed")
	}
	if set.Find("k1").Kty != "RSA" || set.Find("e1").Kty != "EC" {
		t.Error("kty mismatch")
	}
	if set.Find("nope") != nil {
		t.Error("Find miss")
	}
}

// TestParseJWKSSkipsUnknownKty imports a set mixing an "oct" (symmetric) key with an
// RSA key: the unusable key is skipped, the RSA key retained.
func TestParseJWKSSkipsUnknownKty(t *testing.T) {
	body := fmt.Sprintf(`{"keys":[{"kty":"oct","kid":"sym","k":"AAAA"},%s]}`, rsaJWKJSON(t, "k1", "", ""))
	set, err := ParseJWKS([]byte(body))
	if err != nil {
		t.Fatalf("ParseJWKS: %v", err)
	}
	if len(set.keys) != 1 || set.Find("k1") == nil || set.Find("sym") != nil {
		t.Errorf("unknown kty not skipped: %d keys", len(set.keys))
	}
}

// TestParseJWKSMalformed covers the set-level JSON error and a supported key with
// bad material (a member that is not skipped but fails the whole parse).
func TestParseJWKSMalformed(t *testing.T) {
	if _, err := ParseJWKS([]byte("{not json")); !errors.Is(err, ErrJWK) {
		t.Errorf("malformed JWKS JSON: %v", err)
	}
	// An RSA member with an invalid base64url modulus fails the parse.
	bad := `{"keys":[{"kty":"RSA","kid":"k1","n":"@@@","e":"AQAB"}]}`
	if _, err := ParseJWKS([]byte(bad)); !errors.Is(err, ErrJWK) {
		t.Errorf("bad RSA material: %v", err)
	}
}

// TestRSAFromJWKErrors exercises every RSA-materialisation failure arm.
func TestRSAFromJWKErrors(t *testing.T) {
	cases := map[string]jwkJSON{
		"bad modulus":     {Kty: "RSA", N: "@@@", E: "AQAB"},
		"bad exponent":    {Kty: "RSA", N: "AQAB", E: "@@@"},
		"missing modulus": {Kty: "RSA", N: "", E: "AQAB"},
		// e = 0 (base64url "AA") is out of range.
		"zero exponent": {Kty: "RSA", N: "AQAB", E: "AA"},
	}
	for name, j := range cases {
		if _, err := rsaFromJWK(j); !errors.Is(err, ErrJWK) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// An exponent too large to fit an int64 is rejected (9 bytes > 63 bits).
	big9 := jwkJSON{Kty: "RSA", N: "AQAB", E: "AQAAAAAAAAAA"}
	if _, err := rsaFromJWK(big9); !errors.Is(err, ErrJWK) {
		t.Errorf("oversized exponent: %v", err)
	}
}

// TestECFromJWKErrors exercises every EC-materialisation failure arm.
func TestECFromJWKErrors(t *testing.T) {
	valid := ecJWKJSON(t, "e1") // reuse its coordinates for the missing-curve case
	_ = valid
	cases := map[string]jwkJSON{
		"unsupported curve": {Kty: "EC", Crv: "P-224", X: "AA", Y: "AA"},
		"bad x":             {Kty: "EC", Crv: "P-256", X: "@@@", Y: "AA"},
		"bad y":             {Kty: "EC", Crv: "P-256", X: "AA", Y: "@@@"},
		"missing coord":     {Kty: "EC", Crv: "P-256", X: "", Y: ""},
	}
	for name, j := range cases {
		if _, _, err := ecFromJWK(j); !errors.Is(err, ErrJWK) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

// TestCurveByName covers all supported curves and the unsupported arm.
func TestCurveByName(t *testing.T) {
	for _, n := range []string{"P-256", "P-384", "P-521"} {
		if c, err := curveByName(n); err != nil || c == nil {
			t.Errorf("curveByName(%s) = %v, %v", n, c, err)
		}
	}
	if _, err := curveByName("P-224"); !errors.Is(err, ErrJWK) {
		t.Errorf("unsupported curve: %v", err)
	}
}

// TestSelectByKid covers Select's kid path: hit and miss.
func TestSelectByKid(t *testing.T) {
	set, err := ParseJWKS([]byte(fmt.Sprintf(`{"keys":[%s]}`, rsaJWKJSON(t, "k1", "RS256", "sig"))))
	if err != nil {
		t.Fatal(err)
	}
	if k, err := set.Select("k1", "RS256"); err != nil || k == nil {
		t.Errorf("Select hit: %v", err)
	}
	if _, err := set.Select("nope", "RS256"); !errors.Is(err, ErrJWK) {
		t.Errorf("Select miss: %v", err)
	}
}

// TestSelectKidless covers Select's kid-less fallback: a sole matching key wins,
// an ambiguous set is rejected, a non-sig use is skipped, and an unmatched alg
// yields no candidate.
func TestSelectKidless(t *testing.T) {
	// Sole RSA key, no kid on the wire.
	single, err := ParseJWKS([]byte(fmt.Sprintf(`{"keys":[%s]}`, rsaJWKJSON(t, "", "RS256", "sig"))))
	if err != nil {
		t.Fatal(err)
	}
	if k, err := single.Select("", "RS256"); err != nil || k == nil {
		t.Errorf("kid-less sole key: %v", err)
	}
	// ES256 has no EC key here -> no candidate -> error.
	if _, err := single.Select("", "ES256"); !errors.Is(err, ErrJWK) {
		t.Errorf("kid-less no-candidate: %v", err)
	}
	// Unknown alg -> algMatchesKty default false -> error.
	if _, err := single.Select("", "XX999"); !errors.Is(err, ErrJWK) {
		t.Errorf("kid-less unknown alg: %v", err)
	}
	// Two RSA keys -> ambiguous.
	two, err := ParseJWKS([]byte(fmt.Sprintf(`{"keys":[%s,%s]}`,
		rsaJWKJSON(t, "", "RS256", "sig"), rsaJWKJSON(t, "", "RS256", "sig"))))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := two.Select("", "RS256"); !errors.Is(err, ErrJWK) {
		t.Errorf("kid-less ambiguous: %v", err)
	}
	// An enc-use key is skipped for a signing selection.
	encSet, err := ParseJWKS([]byte(fmt.Sprintf(`{"keys":[%s]}`, rsaJWKJSON(t, "", "RS256", "enc"))))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := encSet.Select("", "RS256"); !errors.Is(err, ErrJWK) {
		t.Errorf("kid-less enc-use skipped: %v", err)
	}
}

// TestAlgMatchesKty covers each arm of the alg/kty compatibility table.
func TestAlgMatchesKty(t *testing.T) {
	cases := []struct {
		alg, kty string
		want     bool
	}{
		{"RS256", "RSA", true},
		{"PS512", "RSA", true},
		{"ES256", "EC", true},
		{"RS256", "EC", false},
		{"ES256", "RSA", false},
		{"HS256", "RSA", false}, // default arm
	}
	for _, c := range cases {
		if got := algMatchesKty(c.alg, c.kty); got != c.want {
			t.Errorf("algMatchesKty(%q,%q) = %v", c.alg, c.kty, got)
		}
	}
}

// TestKeyForHeaderKidless drives the kid-less JWKS resolution through Decode: a
// token with no "kid" verifies against a single-key imported set.
func TestKeyForHeaderKidless(t *testing.T) {
	set, err := ParseJWKS([]byte(fmt.Sprintf(`{"keys":[%s]}`, rsaJWKJSON(t, "", "RS256", "sig"))))
	if err != nil {
		t.Fatal(err)
	}
	// No kid in the header at all.
	tok, err := Encode(map[string]any{"a": 1}, loadRSAPrivate(t), "RS256", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Decode(tok, set, true, Options{Algorithms: []string{"RS256"}}); err != nil {
		t.Errorf("kid-less decode: %v", err)
	}
}

// TestImportGoldenSelection is the golden-vector check: a fixed JWKS JSON with two
// keys resolves each token to the correct key by kid, and cross-verification against
// the wrong key fails.
func TestImportGoldenSelection(t *testing.T) {
	// A second independent RSA key so a wrong-key selection is observable.
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherJWK, err := NewJWK(&other.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	otherJSON := fmt.Sprintf(`{"kty":"EC","kid":"e2","crv":%q,"x":%q,"y":%q}`, otherJWK.Crv, otherJWK.X, otherJWK.Y)
	body := fmt.Sprintf(`{"keys":[%s,%s]}`, rsaJWKJSON(t, "k1", "RS256", "sig"), otherJSON)
	set, err := ParseJWKS([]byte(body))
	if err != nil {
		t.Fatal(err)
	}

	// Token signed by the RSA key carries kid k1 -> selects k1 -> verifies.
	h := NewOrderedMap()
	h.Set("kid", "k1")
	tok, err := Encode(map[string]any{"a": 1}, loadRSAPrivate(t), "RS256", h)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Decode(tok, set, true, Options{Algorithms: []string{"RS256"}}); err != nil {
		t.Errorf("golden kid k1: %v", err)
	}

	// Same token but pointing at the EC kid e2 -> wrong key -> verification fails.
	h2 := NewOrderedMap()
	h2.Set("kid", "e2")
	tokWrong, err := Encode(map[string]any{"a": 1}, loadRSAPrivate(t), "RS256", h2)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Decode(tokWrong, set, true, Options{Algorithms: []string{"RS256"}}); !errors.Is(err, ErrVerification) {
		t.Errorf("golden wrong kid: want ErrVerification, got %v", err)
	}
}
