// Copyright (c) the go-ruby-jwt/jwt authors
//
// SPDX-License-Identifier: BSD-3-Clause

package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

// TestJWKFromRSA builds a JWK from the fixture RSA key and checks its exported
// shape (kty,n,e,kid order) and that the thumbprint is 64 lowercase-hex chars.
func TestJWKFromRSA(t *testing.T) {
	pub := loadRSAPublic(t)
	j, err := NewJWK(pub)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	if j.Kty != "RSA" || j.N == "" || j.E == "" {
		t.Fatalf("RSA JWK = %+v", j)
	}
	if len(j.Kid) != 64 || strings.ToLower(j.Kid) != j.Kid {
		t.Errorf("kid = %q", j.Kid)
	}
	exp := j.Export()
	if got := exp.Keys(); len(got) != 4 || got[0] != "kty" || got[1] != "n" || got[2] != "e" || got[3] != "kid" {
		t.Errorf("RSA export order = %v", got)
	}
	if exp.Len() != 4 {
		t.Errorf("RSA export len = %d", exp.Len())
	}
	// PublicKey round-trips the wrapped key.
	if j.PublicKey() == nil {
		t.Error("PublicKey nil")
	}
	// The RFC 7638 thumbprint is the unpadded-base64url of the same digest family
	// (distinct from the hex Kid): non-empty, no '=' padding.
	if tp := j.Thumbprint(); tp == "" || strings.Contains(tp, "=") {
		t.Errorf("RSA thumbprint = %q", tp)
	}
	// Building from a private key reduces to the public half.
	if _, err := NewJWK(loadRSAPrivate(t)); err != nil {
		t.Errorf("NewJWK(priv RSA): %v", err)
	}
}

// TestJWKFromEC builds a JWK for each supported curve and checks the EC export
// shape (kty,crv,x,y,kid).
func TestJWKFromEC(t *testing.T) {
	for _, c := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		priv, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		j, err := NewJWK(&priv.PublicKey)
		if err != nil {
			t.Fatalf("NewJWK EC: %v", err)
		}
		if j.Kty != "EC" || j.Crv == "" || j.X == "" || j.Y == "" {
			t.Errorf("EC JWK = %+v", j)
		}
		exp := j.Export()
		want := []string{"kty", "crv", "x", "y", "kid"}
		for i, k := range want {
			if exp.Keys()[i] != k {
				t.Errorf("EC export order[%d] = %s, want %s", i, exp.Keys()[i], k)
			}
		}
		// EC thumbprint covers the EC branch of Thumbprint.
		if tp := j.Thumbprint(); tp == "" {
			t.Error("EC thumbprint empty")
		}
		// From a private key too.
		if _, err := NewJWK(priv); err != nil {
			t.Errorf("NewJWK(priv EC): %v", err)
		}
	}
}

// TestJWKUnsupported covers the unsupported-key-type and unsupported-curve errors.
func TestJWKUnsupported(t *testing.T) {
	if _, err := NewJWK("not-a-key"); !errors.Is(err, ErrEncode) {
		t.Errorf("unsupported key: %v", err)
	}
	// An EC key on an unsupported curve (P-224).
	priv, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewJWK(&priv.PublicKey); !errors.Is(err, ErrEncode) {
		t.Errorf("unsupported curve: %v", err)
	}
}

// TestLeftPad covers both branches of the coordinate padding helper.
func TestLeftPad(t *testing.T) {
	// Already >= n: returned unchanged.
	if got := leftPad([]byte{1, 2, 3}, 2); len(got) != 3 {
		t.Errorf("leftPad no-pad = %v", got)
	}
	// Shorter: left-zero-padded to n.
	got := leftPad([]byte{9}, 3)
	if len(got) != 3 || got[0] != 0 || got[1] != 0 || got[2] != 9 {
		t.Errorf("leftPad = %v", got)
	}
}

// TestJWKS covers the key-set: Find hit/miss, and the kid-resolving Decode path
// (matched kid verifies, unmatched kid fails).
func TestJWKS(t *testing.T) {
	rsaPub := loadRSAPublic(t)
	jwk, err := NewJWK(rsaPub)
	if err != nil {
		t.Fatal(err)
	}
	set := NewJWKS(jwk)

	// Find hit and miss.
	if set.Find(jwk.Kid) == nil {
		t.Error("Find hit = nil")
	}
	if set.Find("nope") != nil {
		t.Error("Find miss != nil")
	}

	// Encode a token carrying the kid in its header, then decode via the set.
	h := NewOrderedMap()
	h.Set("kid", jwk.Kid)
	tok, err := Encode(map[string]any{"a": 1}, loadRSAPrivate(t), "RS256", h)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Decode(tok, set, true, Options{Algorithms: []string{"RS256"}}); err != nil {
		t.Errorf("JWKS decode (matched kid): %v", err)
	}

	// A token whose kid is absent from the set fails verification.
	h2 := NewOrderedMap()
	h2.Set("kid", "unknown")
	tok2, _ := Encode(map[string]any{"a": 1}, loadRSAPrivate(t), "RS256", h2)
	if _, _, err := Decode(tok2, set, true, Options{Algorithms: []string{"RS256"}}); !errors.Is(err, ErrVerification) {
		t.Errorf("JWKS decode (unmatched kid): %v", err)
	}
}
