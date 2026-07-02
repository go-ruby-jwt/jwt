// Copyright (c) the go-ruby-jwt/jwt authors
//
// SPDX-License-Identifier: BSD-3-Clause

package jwt

import "encoding/base64"

// The gem encodes every segment with base64url and no padding (RFC 7515 §2's
// BASE64URL(...)); it strips "=" on encode and re-pads on decode. crypto's
// RawURLEncoding is exactly that alphabet with padding disabled.

// encodeSegment renders bytes as an unpadded base64url segment.
func encodeSegment(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeSegment parses an unpadded base64url segment. The gem is lenient: it
// accepts a segment whether or not the caller left trailing "=" padding on it, so
// we try the strict-unpadded form first and fall back to the padded decoder. A
// segment that decodes under neither is reported as JWT::Base64DecodeError, the
// gem's "Invalid base64 encoding".
func decodeSegment(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, newError(ErrBase64Decode, "Invalid base64 encoding")
}
