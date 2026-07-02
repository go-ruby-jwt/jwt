// Copyright (c) the go-ruby-jwt/jwt authors
//
// SPDX-License-Identifier: BSD-3-Clause

package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"math/big"

	// register the SHA implementations for crypto.Hash.New via rsa's hashing.
	_ "crypto/sha256"
	_ "crypto/sha512"
)

// signer signs the "<header>.<payload>" signing input for one JWS algorithm and
// verifies a candidate signature over it, mirroring the gem's per-algorithm sign/
// verify. "none" is handled separately (empty signature) in encode/decode.
type signer struct {
	// alg is the JWA name ("HS256", "RS384", "ES512", "PS256", "none").
	alg string
	// hash is the digest the algorithm signs over.
	hash crypto.Hash
	// sign produces the raw signature bytes for signingInput under key.
	sign func(key any, signingInput []byte, h crypto.Hash) ([]byte, error)
	// verify reports whether sig is a valid signature of signingInput under key.
	verify func(key any, signingInput, sig []byte, h crypto.Hash) error
}

// signers is the algorithm registry the gem exposes: HS/RS/ES/PS in the 256/384/
// 512 digests, plus "none". lookupSigner reads it.
var signers = func() map[string]*signer {
	m := map[string]*signer{}
	for name, h := range map[string]crypto.Hash{
		"256": crypto.SHA256, "384": crypto.SHA384, "512": crypto.SHA512,
	} {
		m["HS"+name] = &signer{alg: "HS" + name, hash: h, sign: signHMAC, verify: verifyHMAC}
		m["RS"+name] = &signer{alg: "RS" + name, hash: h, sign: signRSA, verify: verifyRSA}
		m["ES"+name] = &signer{alg: "ES" + name, hash: h, sign: signECDSA, verify: verifyECDSA}
		m["PS"+name] = &signer{alg: "PS" + name, hash: h, sign: signPSS, verify: verifyPSS}
	}
	return m
}()

// lookupSigner returns the signer for a JWA name, or nil if unknown ("none" is not
// in the registry — it is handled inline by encode/decode).
func lookupSigner(alg string) *signer {
	return signers[alg]
}

// digest hashes b with h.
func digest(h crypto.Hash, b []byte) []byte {
	var hh hash.Hash
	switch h {
	case crypto.SHA256:
		hh = sha256.New()
	case crypto.SHA384:
		hh = sha512.New384()
	default: // crypto.SHA512 — the registry never builds another digest.
		hh = sha512.New()
	}
	hh.Write(b)
	return hh.Sum(nil)
}

// --- HMAC (HS256/384/512) ---------------------------------------------------

// hmacKey coerces the many shapes the gem accepts for an HMAC secret — a String, a
// byte slice — into raw key bytes.
func hmacKey(key any) ([]byte, error) {
	switch k := key.(type) {
	case string:
		return []byte(k), nil
	case []byte:
		return k, nil
	default:
		return nil, newError(ErrEncode, "HMAC key must be a string or byte slice")
	}
}

func signHMAC(key any, in []byte, h crypto.Hash) ([]byte, error) {
	kb, err := hmacKey(key)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(func() hash.Hash { return newHash(h) }, kb)
	mac.Write(in)
	return mac.Sum(nil), nil
}

func verifyHMAC(key any, in, sig []byte, h crypto.Hash) error {
	expected, err := signHMAC(key, in, h)
	if err != nil {
		return verificationFailed()
	}
	if !hmac.Equal(expected, sig) {
		return verificationFailed()
	}
	return nil
}

// newHash builds the hash.Hash for an HMAC digest.
func newHash(h crypto.Hash) hash.Hash {
	switch h {
	case crypto.SHA256:
		return sha256.New()
	case crypto.SHA384:
		return sha512.New384()
	default:
		return sha512.New()
	}
}

// --- RSA PKCS#1 v1.5 (RS256/384/512) ---------------------------------------

func signRSA(key any, in []byte, h crypto.Hash) ([]byte, error) {
	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, newError(ErrEncode, "RSA key must be an *rsa.PrivateKey")
	}
	return rsa.SignPKCS1v15(rand.Reader, priv, h, digest(h, in))
}

func verifyRSA(key any, in, sig []byte, h crypto.Hash) error {
	pub, err := rsaPublic(key)
	if err != nil {
		return verificationFailed()
	}
	if err := rsa.VerifyPKCS1v15(pub, h, digest(h, in), sig); err != nil {
		return verificationFailed()
	}
	return nil
}

// --- RSA-PSS (PS256/384/512) ------------------------------------------------

func signPSS(key any, in []byte, h crypto.Hash) ([]byte, error) {
	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, newError(ErrEncode, "RSA key must be an *rsa.PrivateKey")
	}
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h}
	return rsa.SignPSS(rand.Reader, priv, h, digest(h, in), opts)
}

func verifyPSS(key any, in, sig []byte, h crypto.Hash) error {
	pub, err := rsaPublic(key)
	if err != nil {
		return verificationFailed()
	}
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: h}
	if err := rsa.VerifyPSS(pub, h, digest(h, in), sig, opts); err != nil {
		return verificationFailed()
	}
	return nil
}

// rsaPublic extracts an RSA public key from either an *rsa.PublicKey or the public
// half of an *rsa.PrivateKey (the gem accepts a private key on verify too).
func rsaPublic(key any) (*rsa.PublicKey, error) {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return k, nil
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	default:
		return nil, newError(ErrVerification, "not an RSA key")
	}
}

// --- ECDSA (ES256/384/512) --------------------------------------------------

// ecdsaSigLen is the fixed byte length of the r||s JWS signature for each curve:
// P-256 → 32-byte coordinates (64), P-384 → 48 (96), P-521 → 66 (132). RFC 7518
// §3.4 fixes these; the octet length is ceil(bits/8) per coordinate.
func ecdsaSigLen(h crypto.Hash) int {
	switch h {
	case crypto.SHA256:
		return 32
	case crypto.SHA384:
		return 48
	default: // SHA512 → P-521, whose 521-bit coordinate is 66 octets.
		return 66
	}
}

func signECDSA(key any, in []byte, h crypto.Hash) ([]byte, error) {
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, newError(ErrEncode, "ECDSA key must be an *ecdsa.PrivateKey")
	}
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest(h, in))
	if err != nil {
		return nil, err
	}
	n := ecdsaSigLen(h)
	sig := make([]byte, 2*n)
	r.FillBytes(sig[:n])
	s.FillBytes(sig[n:])
	return sig, nil
}

func verifyECDSA(key any, in, sig []byte, h crypto.Hash) error {
	pub, err := ecdsaPublic(key)
	if err != nil {
		return verificationFailed()
	}
	n := ecdsaSigLen(h)
	if len(sig) != 2*n {
		return verificationFailed()
	}
	r := new(big.Int).SetBytes(sig[:n])
	s := new(big.Int).SetBytes(sig[n:])
	if !ecdsa.Verify(pub, digest(h, in), r, s) {
		return verificationFailed()
	}
	return nil
}

// ecdsaPublic extracts an ECDSA public key from an *ecdsa.PublicKey or the public
// half of an *ecdsa.PrivateKey.
func ecdsaPublic(key any) (*ecdsa.PublicKey, error) {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		return k, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	default:
		return nil, newError(ErrVerification, "not an ECDSA key")
	}
}

// verificationFailed is the single gem message every failed signature check
// raises: JWT::VerificationError "Signature verification failed".
func verificationFailed() error {
	return newError(ErrVerification, "Signature verification failed")
}
