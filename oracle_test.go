// Copyright (c) the go-ruby-jwt/jwt authors
//
// SPDX-License-Identifier: BSD-3-Clause

package jwt

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// The oracle tests cross-verify this library against MRI's `jwt` gem in both
// directions: a token this package produces must decode+verify under the gem, and
// a token the gem produces must decode+verify here. They are best-effort — they
// skip on Windows (the CI Windows lane has no ruby) and wherever ruby or the gem
// is absent, so the ruby-free golden-vector + self-round-trip tests alone keep the
// coverage gate at 100% on every lane. When ruby+jwt are present (the ubuntu/macos
// CI lanes, and a dev box with the gem) they run and pin gem parity for every
// algorithm, including the non-deterministic ES*/PS* that golden vectors cannot.

// requireRuby skips the test unless a ruby with the jwt gem is available.
func requireRuby(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("oracle: no ruby on the Windows CI lane")
	}
	if _, err := exec.LookPath("ruby"); err != nil {
		t.Skip("oracle: ruby not found")
	}
	if err := exec.Command("ruby", "-e", "require 'jwt'").Run(); err != nil {
		t.Skip("oracle: jwt gem not installed")
	}
}

// runRuby executes a ruby script (reading the token/keys it needs from argv/env)
// and returns its trimmed stdout, failing the test on a non-zero exit.
func runRuby(t *testing.T, script string, args ...string) string {
	t.Helper()
	cmd := exec.Command("ruby", append([]string{"-e", script}, args...)...)
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("ruby: %v\nstderr: %s", err, errb.String())
	}
	return strings.TrimSpace(out.String())
}

// pemPrivateFor returns the PEM path holding the private key for an algorithm
// family, so the ruby oracle can load the same key this test signs/verifies with.
func pemPrivateFor(alg string) string {
	switch alg[:2] {
	case "RS", "PS":
		return "testdata/rsa_test.pem"
	default: // ES*
		return "testdata/ec_test.pem"
	}
}

func pemPublicFor(alg string) string {
	switch alg[:2] {
	case "RS", "PS":
		return "testdata/rsa_test_pub.pem"
	default:
		return "testdata/ec_test_pub.pem"
	}
}

// TestOracleGoToRuby: every algorithm's token, produced here, decodes+verifies
// under the gem and yields the round-tripped claim.
func TestOracleGoToRuby(t *testing.T) {
	requireRuby(t)

	// Symmetric HS*: the gem verifies with the shared secret.
	for _, alg := range []string{"HS256", "HS384", "HS512"} {
		tok, err := Encode(map[string]any{"user": "amy"}, goldenSecret, alg, nil)
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		script := `require 'jwt'
payload, = JWT.decode(ARGV[0], ARGV[1], true, {algorithm: ARGV[2]})
print payload["user"]`
		if got := runRuby(t, script, tok, goldenSecret, alg); got != "amy" {
			t.Errorf("%s go->ruby: %q", alg, got)
		}
	}

	// Asymmetric RS*/PS*/ES*: the gem verifies with the public key PEM.
	asym := []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256"}
	for _, alg := range asym {
		key := loadPrivateFor(t, alg)
		tok, err := Encode(map[string]any{"user": "amy"}, key, alg, nil)
		if err != nil {
			t.Fatalf("%s encode: %v", alg, err)
		}
		script := `require 'jwt'; require 'openssl'
pub = OpenSSL::PKey.read(File.read(ARGV[3]))
payload, = JWT.decode(ARGV[0], pub, true, {algorithm: ARGV[2]})
print payload["user"]`
		if got := runRuby(t, script, tok, "", alg, pemPublicFor(alg)); got != "amy" {
			t.Errorf("%s go->ruby: %q", alg, got)
		}
	}
}

// TestOracleRubyToGo: a token the gem produces for each algorithm decodes+verifies
// here, proving the reverse direction (crucial for the non-deterministic ES*/PS*).
func TestOracleRubyToGo(t *testing.T) {
	requireRuby(t)

	for _, alg := range []string{"HS256", "HS384", "HS512"} {
		script := `require 'jwt'
print JWT.encode({"user"=>"amy"}, ARGV[0], ARGV[1])`
		tok := runRuby(t, script, goldenSecret, alg)
		pl, _, err := Decode(tok, goldenSecret, true, Options{Algorithms: []string{alg}})
		if err != nil {
			t.Fatalf("%s ruby->go: %v", alg, err)
		}
		if u, _ := pl.(*OrderedMap).Get("user"); u != "amy" {
			t.Errorf("%s ruby->go user = %v", alg, u)
		}
	}

	asym := []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256"}
	for _, alg := range asym {
		script := `require 'jwt'; require 'openssl'
priv = OpenSSL::PKey.read(File.read(ARGV[1]))
print JWT.encode({"user"=>"amy"}, priv, ARGV[0])`
		tok := runRuby(t, script, alg, pemPrivateFor(alg))
		pub := loadPublicFor(t, alg)
		pl, _, err := Decode(tok, pub, true, Options{Algorithms: []string{alg}})
		if err != nil {
			t.Fatalf("%s ruby->go: %v", alg, err)
		}
		if u, _ := pl.(*OrderedMap).Get("user"); u != "amy" {
			t.Errorf("%s ruby->go user = %v", alg, u)
		}
	}
}

// TestOracleJWKKid cross-checks our Kid (the gem's default key_digest) and our
// RFC 7638 Thumbprint against the gem for the fixture RSA and EC keys — both must
// match byte-for-byte, in both encodings.
func TestOracleJWKKid(t *testing.T) {
	requireRuby(t)

	// The gem's default kid (export[:kid]) is key_digest; its RFC 7638 thumbprint is
	// JWT::JWK::Thumbprint. Print both, tab-separated.
	script := `require 'jwt'; require 'openssl'
pub = OpenSSL::PKey.read(File.read(ARGV[0]))
jwk = JWT::JWK.new(pub)
print "#{jwk[:kid]}\t#{JWT::JWK::Thumbprint.new(jwk)}"`

	check := func(pubPath string, j *JWK) {
		out := runRuby(t, script, pubPath)
		parts := strings.Split(out, "\t")
		if len(parts) != 2 {
			t.Fatalf("%s: unexpected ruby output %q", pubPath, out)
		}
		if parts[0] != j.Kid {
			t.Errorf("%s kid\n go %q\ngem %q", pubPath, j.Kid, parts[0])
		}
		if parts[1] != j.Thumbprint() {
			t.Errorf("%s thumbprint\n go %q\ngem %q", pubPath, j.Thumbprint(), parts[1])
		}
	}

	rsaJWK, err := NewJWK(loadRSAPublic(t))
	if err != nil {
		t.Fatal(err)
	}
	check("testdata/rsa_test_pub.pem", rsaJWK)

	ecJWK, err := NewJWK(loadECPublic(t))
	if err != nil {
		t.Fatal(err)
	}
	check("testdata/ec_test_pub.pem", ecJWK)
}

// loadPrivateFor / loadPublicFor pick the fixture key matching an algorithm family.
func loadPrivateFor(t *testing.T, alg string) any {
	t.Helper()
	if alg[:2] == "ES" {
		return loadECPrivate(t)
	}
	return loadRSAPrivate(t)
}

func loadPublicFor(t *testing.T, alg string) any {
	t.Helper()
	if alg[:2] == "ES" {
		return loadECPublic(t)
	}
	return loadRSAPublic(t)
}
