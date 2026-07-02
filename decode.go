// Copyright (c) the go-ruby-jwt/jwt authors
//
// SPDX-License-Identifier: BSD-3-Clause

package jwt

import "strings"

// Options mirrors the decode-options Hash the gem accepts as JWT.decode's fourth
// argument. The zero value verifies nothing beyond the signature and the always-on
// exp/nbf checks (which the gem also runs by default) — set the Verify* flags and
// their companion expected values to switch on claim validation.
type Options struct {
	// Algorithms is the allow-list of acceptable "alg" header values (the gem's
	// algorithm:/algorithms: options). A token whose alg is not listed is rejected
	// with IncorrectAlgorithm — the alg-confusion guard. Empty (with verify=true)
	// is an error, matching the gem's "An algorithm must be specified".
	Algorithms []string

	// Leeway is the clock-skew allowance (seconds) applied to exp, nbf and iat.
	Leeway int64
	// ExpLeeway / NbfLeeway override Leeway for the respective claim when non-nil.
	ExpLeeway *int64
	NbfLeeway *int64

	// VerifyExpiration toggles the exp check; the gem defaults it on, so this
	// package treats it as on unless explicitly disabled via VerifyExpirationSet.
	VerifyExpiration    bool
	VerifyExpirationSet bool // distinguishes "false" from "unset (=> true)"

	// VerifyNotBefore toggles the nbf check (gem default on; same set-flag rule).
	VerifyNotBefore    bool
	VerifyNotBeforeSet bool

	// VerifyIat, when true, rejects a payload whose iat is malformed or in the
	// future (the gem's verify_iat:).
	VerifyIat bool

	// Issuer + VerifyIss check the iss claim. Issuer may be a single string or a
	// []string of acceptable issuers.
	Issuer    any
	VerifyIss bool

	// Audience + VerifyAud check the aud claim. Either side may be a string or a
	// []string; the check passes when they intersect.
	Audience  any
	VerifyAud bool

	// Subject + VerifySub check the sub claim against an expected string.
	Subject   string
	VerifySub bool

	// VerifyJti, when true, requires the jti claim to be present and non-empty.
	// A JtiValidator, when set, replaces that default with a custom predicate.
	VerifyJti    bool
	JtiValidator func(jti any) bool

	// RequiredClaims lists claim names that must be present in the payload
	// (the gem's required_claims:).
	RequiredClaims []string
}

// Decode parses and (optionally) verifies a JWS compact token, mirroring the gem's
// JWT.decode(token, key, verify, options) => [payload, header]. It returns the
// decoded payload and header, both as *OrderedMap (so key order round-trips).
//
// When verify is false the signature and claims are not checked and key/options may
// be nil/zero — the gem's "no verification" mode. When verify is true the signature
// is checked against key using an algorithm from opts.Algorithms (which must be
// non-empty), and the exp/nbf/iat/iss/aud/sub/jti/required-claim rules the options
// enable are applied.
func Decode(token string, key any, verify bool, opts Options) (payload any, header any, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, newError(ErrDecode, "Not enough or too many segments")
	}

	headerBytes, err := decodeSegment(parts[0])
	if err != nil {
		return nil, nil, err
	}
	payloadBytes, err := decodeSegment(parts[1])
	if err != nil {
		return nil, nil, err
	}
	sig, err := decodeSegment(parts[2])
	if err != nil {
		return nil, nil, err
	}

	hdr, err := unmarshalJSON(headerBytes)
	if err != nil {
		return nil, nil, err
	}
	pl, err := unmarshalJSON(payloadBytes)
	if err != nil {
		return nil, nil, err
	}

	if verify {
		if err := verifySignature(parts[0], parts[1], sig, key, hdr, opts); err != nil {
			return nil, nil, err
		}
		if err := verifyClaims(pl, opts); err != nil {
			return nil, nil, err
		}
	}
	return pl, hdr, nil
}

// verifySignature enforces the algorithm allow-list and checks the signature. It
// reads the token's alg from the header, rejects any alg not in opts.Algorithms
// (the alg-confusion guard), and dispatches to the matching signer — or accepts an
// empty signature for the unsecured "none" only when the caller allowed it.
func verifySignature(headerSeg, payloadSeg string, sig []byte, key any, header any, opts Options) error {
	alg, _ := headerString(header, "alg")

	if len(opts.Algorithms) == 0 {
		return newError(ErrIncorrectAlgorithm, "An algorithm must be specified")
	}
	if !containsFold(opts.Algorithms, alg) {
		return newError(ErrIncorrectAlgorithm, "Expected a different algorithm")
	}

	signingInput := headerSeg + "." + payloadSeg

	if alg == "none" {
		if len(sig) != 0 {
			return verificationFailed()
		}
		return nil
	}

	s := lookupSigner(alg)
	if s == nil {
		return newError(ErrIncorrectAlgorithm, "Expected a different algorithm")
	}
	return s.verify(key, []byte(signingInput), sig, s.hash)
}

// headerString reads a string-valued header field.
func headerString(header any, key string) (string, bool) {
	m, ok := header.(*OrderedMap)
	if !ok {
		return "", false
	}
	v, ok := m.Get(key)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// containsFold reports whether want appears in list under an ASCII-case-insensitive
// comparison (JWA alg names are compared case-insensitively by the gem).
func containsFold(list []string, want string) bool {
	for _, e := range list {
		if strings.EqualFold(e, want) {
			return true
		}
	}
	return false
}
