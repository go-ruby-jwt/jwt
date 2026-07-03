// Copyright (c) the go-ruby-jwt/jwt authors
//
// SPDX-License-Identifier: BSD-3-Clause

package jwt

import "errors"

// Error is the shared interface of every error this package raises. It mirrors the
// gem's exception hierarchy, whose root is JWT::DecodeError < StandardError: a
// caller can match a single kind with errors.As, or the whole family with
// errors.Is(err, jwt.ErrDecode).
type Error struct {
	// Kind names the gem exception class (e.g. "JWT::ExpiredSignature").
	Kind string
	// Message is the human-readable text, byte-for-byte the gem's message.
	Message string
	// parent lets errors.Is walk the gem's inheritance chain: every decode-time
	// error Is ErrDecode, matching `rescue JWT::DecodeError`.
	parent error
}

func (e *Error) Error() string { return e.Message }

// Unwrap exposes the parent sentinel so errors.Is(err, ErrDecode) matches any
// decode-time error, just as `rescue JWT::DecodeError` catches the whole family.
func (e *Error) Unwrap() error { return e.parent }

// The sentinels below are the gem's exception classes. Match a specific one with
// errors.Is(err, jwt.ErrExpiredSignature), or the whole decode family with
// errors.Is(err, jwt.ErrDecode).
var (
	// ErrEncode is JWT::EncodeError — a token could not be produced.
	ErrEncode = errors.New("JWT::EncodeError")

	// ErrDecode is JWT::DecodeError, the root of every decode-time failure.
	ErrDecode = errors.New("JWT::DecodeError")

	// ErrVerification is JWT::VerificationError — the signature did not verify.
	ErrVerification = newParent("JWT::VerificationError", ErrDecode)
	// ErrIncorrectAlgorithm is JWT::IncorrectAlgorithm — the token's alg is not
	// among those the caller allowed (alg-confusion guard).
	ErrIncorrectAlgorithm = newParent("JWT::IncorrectAlgorithm", ErrDecode)
	// ErrExpiredSignature is JWT::ExpiredSignature — the exp claim is in the past.
	ErrExpiredSignature = newParent("JWT::ExpiredSignature", ErrDecode)
	// ErrImmatureSignature is JWT::ImmatureSignature — nbf is still in the future.
	ErrImmatureSignature = newParent("JWT::ImmatureSignature", ErrDecode)
	// ErrInvalidIat is JWT::InvalidIatError — the iat claim is malformed or future.
	ErrInvalidIat = newParent("JWT::InvalidIatError", ErrDecode)
	// ErrInvalidIssuer is JWT::InvalidIssuerError — the iss claim did not match.
	ErrInvalidIssuer = newParent("JWT::InvalidIssuerError", ErrDecode)
	// ErrInvalidAud is JWT::InvalidAudError — the aud claim did not match.
	ErrInvalidAud = newParent("JWT::InvalidAudError", ErrDecode)
	// ErrInvalidSub is JWT::InvalidSubError — the sub claim did not match.
	ErrInvalidSub = newParent("JWT::InvalidSubError", ErrDecode)
	// ErrInvalidJti is JWT::InvalidJtiError — the jti claim failed validation.
	ErrInvalidJti = newParent("JWT::InvalidJtiError", ErrDecode)
	// ErrInvalidPayload is JWT::InvalidPayload — a reserved claim has a bad type.
	ErrInvalidPayload = newParent("JWT::InvalidPayload", ErrDecode)
	// ErrMissingRequiredClaim is JWT::MissingRequiredClaim — a required claim is
	// absent from the payload.
	ErrMissingRequiredClaim = newParent("JWT::MissingRequiredClaim", ErrDecode)
	// ErrBase64Decode is JWT::Base64DecodeError — a segment was not valid base64url.
	ErrBase64Decode = newParent("JWT::Base64DecodeError", ErrDecode)
	// ErrJWK is JWT::JWKError — a JWK/JWKS could not be parsed or materialised into
	// a usable public key (malformed JSON, missing or bad key material, an
	// unsupported key type or curve). Like the gem's JWKError it is a DecodeError.
	ErrJWK = newParent("JWT::JWKError", ErrDecode)
)

// newParent builds a sentinel whose Is chain reaches parent, so the family-level
// errors.Is checks (and the gem's `rescue JWT::DecodeError`) hold.
func newParent(kind string, parent error) error {
	return &Error{Kind: kind, Message: kind, parent: parent}
}

// newError constructs a concrete failure of the given sentinel kind. The sentinel
// carries the parent chain (so errors.Is spans the hierarchy) and its own Kind.
func newError(sentinel error, msg string) *Error {
	var s *Error
	if errors.As(sentinel, &s) {
		return &Error{Kind: s.Kind, Message: msg, parent: sentinel}
	}
	// sentinel is a plain errors.New root (ErrEncode / ErrDecode itself).
	return &Error{Kind: sentinel.Error(), Message: msg, parent: sentinel}
}
