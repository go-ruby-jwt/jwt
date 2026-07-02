// Copyright (c) the go-ruby-jwt/jwt authors
//
// SPDX-License-Identifier: BSD-3-Clause

package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
)

// JWK is a JSON Web Key (RFC 7517) for an RSA or EC public key — the export/import
// half of the gem's JWT::JWK. It mirrors the gem's export byte-for-byte: an RSA key
// exports {"kty":"RSA","n":..,"e":..,"kid":..}, an EC key
// {"kty":"EC","crv":..,"x":..,"y":..,"kid":..}.
//
// Kid is the gem's default key id (JWK#kid), which is NOT the RFC 7638 thumbprint:
// the gem derives it as the lowercase-hex SHA-256 of the DER of an ASN.1 SEQUENCE of
// the key's two defining integers — (n, e) for RSA, (x, y) for EC — matching
// JWT::JWK's key_digest byte-for-byte. The RFC 7638 thumbprint (base64url) is
// available separately via Thumbprint.
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
	// Gem key_digest: SHA-256(DER(SEQUENCE(INTEGER n, INTEGER e))) as lowercase hex.
	j.Kid = keyDigest(pub.N, big.NewInt(int64(pub.E)))
	return j
}

// ecJWK renders an EC public key as a JWK.
func ecJWK(pub *ecdsa.PublicKey) (*JWK, error) {
	crv, size, err := curveParams(pub.Curve)
	if err != nil {
		return nil, err
	}
	xOct := leftPad(pub.X.Bytes(), size)
	yOct := leftPad(pub.Y.Bytes(), size)
	x := base64.RawURLEncoding.EncodeToString(xOct)
	y := base64.RawURLEncoding.EncodeToString(yOct)
	j := &JWK{Kty: "EC", Crv: crv, X: x, Y: y, key: pub}
	// Gem key_digest: SHA-256(DER(SEQUENCE(INTEGER x, INTEGER y))) over the fixed-
	// width coordinate octets read as positive integers, lowercase hex.
	j.Kid = keyDigest(new(big.Int).SetBytes(xOct), new(big.Int).SetBytes(yOct))
	return j, nil
}

// keyDigest is the gem's default kid: the lowercase-hex SHA-256 of the DER encoding
// of an ASN.1 SEQUENCE of the key's two defining integers. asn1.Marshal of a struct
// of two *big.Int is total (INTEGER encoding never fails), so its error is dropped.
func keyDigest(a, b *big.Int) string {
	der, _ := asn1.Marshal(struct{ A, B *big.Int }{a, b})
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
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

// Thumbprint is the RFC 7638 key thumbprint: the unpadded base64url SHA-256 of the
// key's canonical JSON (members sorted, compact), byte-for-byte the gem's
// JWT::JWK::Thumbprint. It is distinct from Kid (the gem's default key_digest).
func (j *JWK) Thumbprint() string {
	var canonical string
	if j.Kty == "RSA" {
		canonical = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, j.E, j.N)
	} else {
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, j.Crv, j.X, j.Y)
	}
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
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
