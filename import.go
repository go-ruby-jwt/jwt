// Copyright (c) the go-ruby-jwt/jwt authors
//
// SPDX-License-Identifier: BSD-3-Clause

package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"math/big"
	"strings"
)

// This file is the import half of the gem's JWT::JWK: it reads a JWK (RFC 7517)
// or a JWKS ({"keys":[...]}) from JSON and materialises each RSA/EC entry into a
// usable public key, keyed by the provider-assigned "kid" and selectable by
// kid/alg/kty/use. It is deliberately transport- and protocol-agnostic — there is
// no issuer/audience/nonce logic here — so any consumer (not just OIDC) can turn a
// provider's key set into verification keys.
//
// Endianness note: every field is base64url text decoded with encoding/base64 and
// the resulting octets are read big-endian by math/big.Int.SetBytes, both of which
// are byte-order independent, so import is identical on little- and big-endian
// (e.g. s390x) targets.

// jwkJSON is the wire shape of a single JWK member this library reads. Unknown
// members (e.g. an "oct" key's "k") are ignored.
type jwkJSON struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// jwksJSON is the wire shape of a key set.
type jwksJSON struct {
	Keys []jwkJSON `json:"keys"`
}

// ParseJWK reads a single JSON Web Key from JSON and materialises its RSA (n/e) or
// EC (crv/x/y) public key, mirroring JWT::JWK.import for a lone key. The returned
// JWK carries the provider's "kid"/"alg"/"use" (for later selection) and the parsed
// public key (reachable via PublicKey). An unsupported key type is an error — unlike
// ParseJWKS, which skips a key it cannot use.
func ParseJWK(data []byte) (*JWK, error) {
	var j jwkJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, newError(ErrJWK, "invalid JWK JSON: "+err.Error())
	}
	jwk, err := jwkFromJSON(j)
	if err != nil {
		return nil, err
	}
	if jwk == nil {
		return nil, newError(ErrJWK, "unsupported key type "+j.Kty)
	}
	return jwk, nil
}

// ParseJWKS reads a JSON Web Key Set ({"keys":[...]}) from JSON, materialising each
// RSA/EC key into a public key and keying it by the provider's "kid". A key whose
// type this library cannot use for JWS verification (e.g. an "oct" symmetric key) is
// skipped rather than failing the whole set, matching a client that ignores keys it
// has no use for; a key of a supported type with bad material is an error.
func ParseJWKS(data []byte) (*JWKS, error) {
	var doc jwksJSON
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, newError(ErrJWK, "invalid JWKS JSON: "+err.Error())
	}
	set := &JWKS{}
	for _, j := range doc.Keys {
		jwk, err := jwkFromJSON(j)
		if err != nil {
			return nil, err
		}
		if jwk == nil { // unsupported key type — skip it.
			continue
		}
		set.keys = append(set.keys, jwk)
	}
	return set, nil
}

// jwkFromJSON materialises one wire JWK. It returns (nil, nil) for an unsupported
// key type so ParseJWKS can skip it, and (nil, err) for a supported type whose
// material is malformed.
func jwkFromJSON(j jwkJSON) (*JWK, error) {
	switch j.Kty {
	case "RSA":
		pub, err := rsaFromJWK(j)
		if err != nil {
			return nil, err
		}
		return &JWK{Kty: "RSA", N: j.N, E: j.E, Kid: j.Kid, Alg: j.Alg, Use: j.Use, key: pub}, nil
	case "EC":
		pub, crv, err := ecFromJWK(j)
		if err != nil {
			return nil, err
		}
		return &JWK{Kty: "EC", Crv: crv, X: j.X, Y: j.Y, Kid: j.Kid, Alg: j.Alg, Use: j.Use, key: pub}, nil
	default:
		return nil, nil
	}
}

// rsaFromJWK builds an *rsa.PublicKey from the base64url modulus and exponent.
func rsaFromJWK(j jwkJSON) (*rsa.PublicKey, error) {
	nb, err := jwkOctets("RSA modulus", j.N)
	if err != nil {
		return nil, err
	}
	eb, err := jwkOctets("RSA exponent", j.E)
	if err != nil {
		return nil, err
	}
	if len(nb) == 0 || len(eb) == 0 {
		return nil, newError(ErrJWK, "RSA key missing modulus or exponent")
	}
	e := new(big.Int).SetBytes(eb)
	if !e.IsInt64() || e.Int64() < 1 {
		return nil, newError(ErrJWK, "RSA exponent out of range")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(e.Int64())}, nil
}

// ecFromJWK builds an *ecdsa.PublicKey from the curve name and base64url
// coordinates, returning the normalised curve name too. An off-curve point is left
// for the verifier to reject (ecdsa.Verify returns false), so no on-curve check is
// duplicated here.
func ecFromJWK(j jwkJSON) (*ecdsa.PublicKey, string, error) {
	crv, err := curveByName(j.Crv)
	if err != nil {
		return nil, "", err
	}
	xb, err := jwkOctets("EC x", j.X)
	if err != nil {
		return nil, "", err
	}
	yb, err := jwkOctets("EC y", j.Y)
	if err != nil {
		return nil, "", err
	}
	if len(xb) == 0 || len(yb) == 0 {
		return nil, "", newError(ErrJWK, "EC key missing coordinate")
	}
	pub := &ecdsa.PublicKey{
		Curve: crv,
		X:     new(big.Int).SetBytes(xb),
		Y:     new(big.Int).SetBytes(yb),
	}
	return pub, j.Crv, nil
}

// curveByName maps a JWA curve name to its elliptic.Curve (the inverse of
// curveParams). An unsupported curve is a JWKError.
func curveByName(name string) (elliptic.Curve, error) {
	switch name {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, newError(ErrJWK, "unsupported EC curve "+name)
	}
}

// jwkOctets base64url-decodes a JWK field (n/e/x/y), reusing the gem's lenient
// segment decoder (padded or unpadded), and reporting a JWKError on failure.
func jwkOctets(field, s string) ([]byte, error) {
	b, err := decodeSegment(s)
	if err != nil {
		return nil, newError(ErrJWK, "invalid base64url for "+field)
	}
	return b, nil
}

// Select resolves a verification key from the set by kid and (fallback) alg,
// mirroring how a client picks a JWKS key: a non-empty kid selects that exact key;
// an empty kid falls back to the sole signing-capable key whose type serves alg,
// rejecting an ambiguous (or empty) set. It is OIDC-agnostic — no issuer/audience
// logic — so any JWS consumer can reuse it.
func (s *JWKS) Select(kid, alg string) (*JWK, error) {
	if kid != "" {
		if k := s.Find(kid); k != nil {
			return k, nil
		}
		return nil, newError(ErrJWK, "no key with kid "+kid)
	}
	var cands []*JWK
	for _, k := range s.keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if !algMatchesKty(alg, k.Kty) {
			continue
		}
		cands = append(cands, k)
	}
	if len(cands) == 1 {
		return cands[0], nil
	}
	return nil, newError(ErrJWK, "cannot select a signing key without a kid")
}

// algMatchesKty reports whether a JWS algorithm is served by a key type: the RSA
// families (RS*/PS*) by "RSA", the ECDSA family (ES*) by "EC".
func algMatchesKty(alg, kty string) bool {
	switch {
	case strings.HasPrefix(alg, "RS"), strings.HasPrefix(alg, "PS"):
		return kty == "RSA"
	case strings.HasPrefix(alg, "ES"):
		return kty == "EC"
	default:
		return false
	}
}
