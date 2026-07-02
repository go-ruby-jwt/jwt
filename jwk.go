// Copyright (c) the go-ruby-jwt/jwt authors
//
// SPDX-License-Identifier: BSD-3-Clause

package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
)

// JWK is a JSON Web Key (RFC 7517) for an RSA or EC public key — the export/import
// half of the gem's JWT::JWK. It mirrors the gem's export byte-for-byte: an RSA key
// exports {"kty":"RSA","n":..,"e":..,"kid":..}, an EC key
// {"kty":"EC","crv":..,"x":..,"y":..,"kid":..}, and Kid is the RFC 7638 thumbprint
// (SHA-256 of the canonical key) rendered as lowercase hex, exactly as the gem.
type JWK struct {
	// Kty is "RSA" or "EC".
	Kty string
	// Crv is the EC curve name ("P-256"/"P-384"/"P-521"), empty for RSA.
	Crv string
	// N, E are the base64url RSA modulus and exponent (RSA only).
	N, E string
	// X, Y are the base64url EC coordinates (EC only).
	X, Y string
	// Kid is the RFC 7638 thumbprint of the key.
	Kid string

	key any // the parsed crypto.PublicKey, cached for verification
}

// NewJWK builds a JWK from an RSA or EC key (public, or the public half of a
// private key), mirroring JWT::JWK.new. The thumbprint Kid is computed on build.
func NewJWK(key any) (*JWK, error) {
	switch k := publicOf(key).(type) {
	case *rsa.PublicKey:
		return rsaJWK(k), nil
	case *ecdsa.PublicKey:
		return ecJWK(k)
	default:
		return nil, newError(ErrEncode, "unsupported key type for JWK")
	}
}

// publicOf reduces a private key to its public half, leaving other keys untouched.
func publicOf(key any) any {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return key
	}
}

// rsaJWK renders an RSA public key as a JWK.
func rsaJWK(pub *rsa.PublicKey) *JWK {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	j := &JWK{Kty: "RSA", N: n, E: e, key: pub}
	// RFC 7638 canonical form for RSA is {"e":..,"kty":"RSA","n":..}.
	j.Kid = thumbprint(fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, e, n))
	return j
}

// ecJWK renders an EC public key as a JWK.
func ecJWK(pub *ecdsa.PublicKey) (*JWK, error) {
	crv, size, err := curveParams(pub.Curve)
	if err != nil {
		return nil, err
	}
	x := base64.RawURLEncoding.EncodeToString(leftPad(pub.X.Bytes(), size))
	y := base64.RawURLEncoding.EncodeToString(leftPad(pub.Y.Bytes(), size))
	j := &JWK{Kty: "EC", Crv: crv, X: x, Y: y, key: pub}
	// RFC 7638 canonical form for EC is {"crv":..,"kty":"EC","x":..,"y":..}.
	j.Kid = thumbprint(fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, crv, x, y))
	return j, nil
}

// curveParams maps an elliptic.Curve to its JWA name and coordinate octet length.
func curveParams(c elliptic.Curve) (string, int, error) {
	switch c {
	case elliptic.P256():
		return "P-256", 32, nil
	case elliptic.P384():
		return "P-384", 48, nil
	case elliptic.P521():
		return "P-521", 66, nil
	default:
		return "", 0, newError(ErrEncode, "unsupported EC curve for JWK")
	}
}

// thumbprint is the RFC 7638 key thumbprint: SHA-256 of the canonical JSON, as
// lowercase hex (the gem renders it hex, not base64url).
func thumbprint(canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

// leftPad left-zero-pads b to n bytes (fixed-width coordinate encoding).
func leftPad(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

// Export renders the JWK as an ordered object, key-for-key as the gem's
// JWK#export: RSA → kty,n,e,kid; EC → kty,crv,x,y,kid.
func (j *JWK) Export() *OrderedMap {
	m := NewOrderedMap()
	m.Set("kty", j.Kty)
	if j.Kty == "RSA" {
		m.Set("n", j.N)
		m.Set("e", j.E)
	} else {
		m.Set("crv", j.Crv)
		m.Set("x", j.X)
		m.Set("y", j.Y)
	}
	m.Set("kid", j.Kid)
	return m
}

// PublicKey returns the parsed crypto public key the JWK wraps, for verification.
func (j *JWK) PublicKey() any { return j.key }

// JWKS is a set of JWKs, the key-lookup input to Decode for a token whose header
// carries a "kid" (the gem's JWT::JWK::Set). VerifyKey resolves the kid.
type JWKS struct {
	keys []*JWK
}

// NewJWKS builds a key set.
func NewJWKS(keys ...*JWK) *JWKS { return &JWKS{keys: keys} }

// Find returns the JWK with the given kid, or nil.
func (s *JWKS) Find(kid string) *JWK {
	for _, k := range s.keys {
		if k.Kid == kid {
			return k
		}
	}
	return nil
}

// keyForHeader resolves the verification key for a token header from the set: it
// reads the header "kid" and returns that JWK's public key, or nil if unmatched.
func (s *JWKS) keyForHeader(header any) any {
	kid, _ := headerString(header, "kid")
	if jwk := s.Find(kid); jwk != nil {
		return jwk.key
	}
	return nil
}
