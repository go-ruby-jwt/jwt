// Copyright (c) the go-ruby-jwt/jwt authors
//
// SPDX-License-Identifier: BSD-3-Clause

// Package jwt is a pure-Go (no cgo) reimplementation of Ruby's `jwt` gem — the
// JSON Web Token library. It encodes and decodes JWS (JSON Web Signature)
// compact-serialisation tokens, byte-faithfully to the gem: given the same key,
// algorithm, payload and header, deterministic algorithms (HS*, RS*, PS-with-
// verification, none) produce identical tokens, and every algorithm (HS/RS/ES/PS)
// cross-verifies with MRI in both directions.
//
// The whole surface is built on Go's standard crypto/* — crypto/hmac (HS),
// crypto/rsa PKCS1v15 (RS) and PSS (PS), crypto/ecdsa (ES) — so it is CGO-free
// and dependency-free.
//
//	tok, _ := jwt.Encode(map[string]any{"user": "amy", "exp": exp}, secret, "HS256", nil)
//	payload, header, _ := jwt.Decode(tok, secret, true, jwt.Options{Algorithms: []string{"HS256"}})
//
// It is the JWT backend for go-embedded-ruby, but is a standalone, reusable
// module — a sibling of go-ruby-yaml (Psych) and go-ruby-regexp (Onigmo).
package jwt

// Version mirrors the JWT::VERSION::STRING constant the gem exposes; it is the
// gem release this port tracks.
const Version = "3.2.0"
