# jwt — go-ruby-jwt

[![Go Reference](https://pkg.go.dev/badge/github.com/go-ruby-jwt/jwt.svg)](https://pkg.go.dev/github.com/go-ruby-jwt/jwt)
[![License: BSD-3-Clause](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)
[![CI](https://github.com/go-ruby-jwt/jwt/actions/workflows/ci.yml/badge.svg)](https://github.com/go-ruby-jwt/jwt/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-100%25-1a7f37)](#tests--coverage)

**A pure-Go (no cgo) reimplementation of Ruby's
[`jwt`](https://github.com/jwt/ruby-jwt) gem** (tracking release `3.2.0`) — the
JSON Web Token library. It encodes and decodes JWS (JSON Web Signature)
compact-serialisation tokens **byte-faithfully to the gem**: given the same key,
algorithm, payload and header, the deterministic algorithms produce identical
tokens, and every algorithm cross-verifies with MRI in both directions —
**without any Ruby runtime**.

It is the JWT backend for
[go-embedded-ruby](https://github.com/go-embedded-ruby/ruby), but is a
**standalone, reusable** module with no dependency on the Ruby runtime — a
sibling of [go-ruby-yaml](https://github.com/go-ruby-yaml/yaml) (the Psych
emitter/loader) and [go-ruby-regexp](https://github.com/go-ruby-regexp/regexp)
(the Onigmo engine).

## Algorithms

The whole surface is built on Go's standard `crypto/*` — `crypto/hmac` (HS),
`crypto/rsa` PKCS1v15 (RS) and PSS (PS), `crypto/ecdsa` (ES) — so it is CGO-free
and dependency-free:

- **HS256 / HS384 / HS512** — HMAC
- **RS256 / RS384 / RS512** — RSA PKCS#1 v1.5
- **PS256 / PS384 / PS512** — RSA-PSS
- **ES256 / ES384 / ES512** — ECDSA
- **none** — unsecured, per the JWA `none` algorithm

Registered claim verification (`exp`, `nbf`, `iat`, `iss`, `aud`, `sub`, `jti`)
matches the gem's semantics, and JWK import/export is supported.

## Usage

```go
import "github.com/go-ruby-jwt/jwt"

tok, _ := jwt.Encode(map[string]any{"user": "amy", "exp": exp}, secret, "HS256", nil)

payload, header, _ := jwt.Decode(tok, secret, true, jwt.Options{
	Algorithms: []string{"HS256"},
})
```

## Tests & coverage

`go test ./...` runs the unit and differential-oracle suites (cross-verified
against MRI's `jwt` gem). The CI gate enforces **100% statement coverage** and
builds/tests on all six 64-bit Go targets — `amd64`, `arm64`, `riscv64`,
`loong64`, `ppc64le`, `s390x`.

## License

BSD-3-Clause. Copyright (c) the go-ruby-jwt/jwt authors.
