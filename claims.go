// Copyright (c) the go-ruby-jwt/jwt authors
//
// SPDX-License-Identifier: BSD-3-Clause

package jwt

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// nowFunc is the clock claim validation reads; a test seam overrides it so the
// exp/nbf/iat vectors are deterministic.
var nowFunc = time.Now

// verifyClaims runs the reserved-claim checks the options enable, in the gem's
// order: required-claims presence, then exp, nbf, iat, iss, aud, sub, jti.
func verifyClaims(payload any, opts Options) error {
	claims, ok := payload.(*OrderedMap)
	if !ok {
		// A non-object payload (e.g. a bare string) carries no claims to check.
		return nil
	}
	if err := verifyRequired(claims, opts); err != nil {
		return err
	}
	if err := verifyExp(claims, opts); err != nil {
		return err
	}
	if err := verifyNbf(claims, opts); err != nil {
		return err
	}
	if err := verifyIat(claims, opts); err != nil {
		return err
	}
	if err := verifyIss(claims, opts); err != nil {
		return err
	}
	if err := verifyAud(claims, opts); err != nil {
		return err
	}
	if err := verifySub(claims, opts); err != nil {
		return err
	}
	return verifyJti(claims, opts)
}

// verifyRequired enforces that every name in RequiredClaims is present.
func verifyRequired(claims *OrderedMap, opts Options) error {
	for _, name := range opts.RequiredClaims {
		if _, ok := claims.Get(name); !ok {
			return newError(ErrMissingRequiredClaim, "Missing required claim "+name)
		}
	}
	return nil
}

// verifyExp rejects a token whose exp is in the past (minus leeway). The check is
// on by default (like the gem); VerifyExpirationSet with VerifyExpiration=false
// disables it. A non-numeric exp is an InvalidPayload, as in the gem.
func verifyExp(claims *OrderedMap, opts Options) error {
	if opts.VerifyExpirationSet && !opts.VerifyExpiration {
		return nil
	}
	v, ok := claims.Get("exp")
	if !ok {
		return nil
	}
	exp, err := numericClaim(v, "exp")
	if err != nil {
		return err
	}
	leeway := opts.Leeway
	if opts.ExpLeeway != nil {
		leeway = *opts.ExpLeeway
	}
	if now().Unix() >= exp+leeway {
		return newError(ErrExpiredSignature, "Signature has expired")
	}
	return nil
}

// verifyNbf rejects a token whose nbf is still in the future (plus leeway). On by
// default like the gem; disabled via VerifyNotBeforeSet + VerifyNotBefore=false.
func verifyNbf(claims *OrderedMap, opts Options) error {
	if opts.VerifyNotBeforeSet && !opts.VerifyNotBefore {
		return nil
	}
	v, ok := claims.Get("nbf")
	if !ok {
		return nil
	}
	nbf, err := numericClaim(v, "nbf")
	if err != nil {
		return err
	}
	leeway := opts.Leeway
	if opts.NbfLeeway != nil {
		leeway = *opts.NbfLeeway
	}
	if now().Unix() < nbf-leeway {
		return newError(ErrImmatureSignature, "Signature nbf has not been reached")
	}
	return nil
}

// verifyIat rejects a payload whose iat is malformed or in the future, but only
// when VerifyIat is set (the gem's verify_iat: defaults off).
func verifyIat(claims *OrderedMap, opts Options) error {
	if !opts.VerifyIat {
		return nil
	}
	v, ok := claims.Get("iat")
	if !ok {
		return nil
	}
	iat, err := iatValue(v)
	if err != nil {
		return err
	}
	if iat > float64(now().Unix())+float64(opts.Leeway) {
		return newError(ErrInvalidIat, "Invalid iat")
	}
	return nil
}

// verifyIss checks the iss claim against the expected issuer(s) when VerifyIss is
// set. Issuer may be a single value or a list of acceptable issuers.
func verifyIss(claims *OrderedMap, opts Options) error {
	if !opts.VerifyIss {
		return nil
	}
	expected := issuerList(opts.Issuer)
	got, present := claims.Get("iss")
	gotStr := ""
	if present {
		gotStr = fmt.Sprint(got)
	}
	for _, e := range expected {
		if present && gotStr == e {
			return nil
		}
	}
	received := "<none>"
	if present {
		received = gotStr
	}
	return newError(ErrInvalidIssuer,
		fmt.Sprintf("Invalid issuer. Expected %s, received %s", rubyInspectStrings(expected), received))
}

// verifyAud checks the aud claim against the expected audience when VerifyAud is
// set. Either side may be a string or a list; the check passes when they intersect.
func verifyAud(claims *OrderedMap, opts Options) error {
	if !opts.VerifyAud {
		return nil
	}
	expected := audienceList(opts.Audience)
	tokenAud := audienceOf(claims)
	for _, e := range expected {
		for _, t := range tokenAud {
			if e == t {
				return nil
			}
		}
	}
	return newError(ErrInvalidAud,
		fmt.Sprintf("Invalid audience. Expected %s, received %s",
			rubyInspectAud(opts.Audience), rubyInspectAud(rawAud(claims))))
}

// verifySub checks the sub claim equals the expected subject when VerifySub is set.
func verifySub(claims *OrderedMap, opts Options) error {
	if !opts.VerifySub {
		return nil
	}
	got, present := claims.Get("sub")
	gotStr := ""
	if present {
		gotStr = fmt.Sprint(got)
	}
	if present && gotStr == opts.Subject {
		return nil
	}
	received := "<none>"
	if present {
		received = gotStr
	}
	return newError(ErrInvalidSub,
		fmt.Sprintf("Invalid subject. Expected %s, received %s", opts.Subject, received))
}

// verifyJti requires a present, non-empty jti when VerifyJti is set, or delegates
// to a caller-supplied JtiValidator.
func verifyJti(claims *OrderedMap, opts Options) error {
	if !opts.VerifyJti {
		return nil
	}
	v, present := claims.Get("jti")
	if opts.JtiValidator != nil {
		if !opts.JtiValidator(v) {
			return newError(ErrInvalidJti, "Invalid jti")
		}
		return nil
	}
	if !present || fmt.Sprint(v) == "" {
		return newError(ErrInvalidJti, "Missing jti")
	}
	return nil
}

// --- claim value helpers ----------------------------------------------------

// now reads the (test-overridable) clock.
func now() time.Time { return nowFunc() }

// numericClaim coerces a numeric reserved claim (exp/nbf) to an int64 second count,
// raising the gem's InvalidPayload for a non-numeric value.
func numericClaim(v any, name string) (int64, error) {
	f, ok := toFloat(v)
	if !ok {
		return 0, newError(ErrInvalidPayload,
			fmt.Sprintf("%s claim must be a Numeric value but it is a %s", name, rubyClass(v)))
	}
	return int64(f), nil
}

// iatValue coerces the iat claim to a float, raising InvalidIat for a bad type.
func iatValue(v any) (float64, error) {
	f, ok := toFloat(v)
	if !ok {
		return 0, newError(ErrInvalidIat, "Invalid iat")
	}
	return f, nil
}

// toFloat converts the numeric shapes JSON decoding yields (json.Number, float64,
// int) to a float64.
func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}

// rubyClass names the Ruby class of a decoded JSON value, for the InvalidPayload
// message ("... but it is a String").
func rubyClass(v any) string {
	switch v.(type) {
	case string:
		return "String"
	case bool:
		return "TrueClass"
	case nil:
		return "NilClass"
	case []any:
		return "Array"
	case *OrderedMap:
		return "Hash"
	default:
		return "Object"
	}
}

// issuerList normalises the expected-issuer option to a slice of strings.
func issuerList(iss any) []string {
	switch v := iss.(type) {
	case nil:
		return nil
	case string:
		return []string{v}
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			out = append(out, fmt.Sprint(e))
		}
		return out
	default:
		return []string{fmt.Sprint(v)}
	}
}

// audienceList normalises the expected-audience option to a slice of strings.
func audienceList(aud any) []string {
	return issuerList(aud) // same string/[]string/[]any normalisation
}

// audienceOf returns the token's aud claim as a slice (a string becomes one entry,
// an array is flattened to strings).
func audienceOf(claims *OrderedMap) []string {
	v, ok := claims.Get("aud")
	if !ok {
		return nil
	}
	switch a := v.(type) {
	case []any:
		out := make([]string, 0, len(a))
		for _, e := range a {
			out = append(out, fmt.Sprint(e))
		}
		return out
	default:
		return []string{fmt.Sprint(a)}
	}
}

// rawAud returns the token's raw aud value (for the error message's "received").
func rawAud(claims *OrderedMap) any {
	v, _ := claims.Get("aud")
	return v
}

// rubyInspectStrings renders a slice of strings as Ruby's Array#inspect would
// (["a", "b"]), for the InvalidIssuer message.
func rubyInspectStrings(ss []string) string {
	parts := make([]string, len(ss))
	for i, s := range ss {
		parts[i] = fmt.Sprintf("%q", s)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// rubyInspectAud renders the aud side of the InvalidAud message: a plain string is
// shown bare (Expected cli), a list as Ruby's Array#inspect (Expected ["a", "c"]).
func rubyInspectAud(v any) string {
	switch a := v.(type) {
	case nil:
		return "<none>"
	case string:
		return a
	case []string:
		return rubyInspectStrings(a)
	case []any:
		parts := make([]string, len(a))
		for i, e := range a {
			parts[i] = fmt.Sprintf("%q", fmt.Sprint(e))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	default:
		return fmt.Sprint(a)
	}
}
