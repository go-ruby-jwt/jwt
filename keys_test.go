// Copyright (c) the go-ruby-jwt/jwt authors
//
// SPDX-License-Identifier: BSD-3-Clause

package jwt

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

// The test fixtures are fixed RSA/EC keys generated once by the gem, committed
// under testdata/. They make the RS* golden vectors (deterministic PKCS1v15) hold
// ruby-free, and give the ES*/PS* self-round-trip and oracle tests a stable key.

// loadRSAPrivate parses testdata/rsa_test.pem (a PKCS#1 RSA private key).
func loadRSAPrivate(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	block := pemBlock(t, "testdata/rsa_test.pem")
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse RSA private: %v", err)
	}
	return key
}

// loadRSAPublic parses testdata/rsa_test_pub.pem (a PKIX public key).
func loadRSAPublic(t *testing.T) *rsa.PublicKey {
	t.Helper()
	block := pemBlock(t, "testdata/rsa_test_pub.pem")
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse RSA public: %v", err)
	}
	return pub.(*rsa.PublicKey)
}

// loadECPrivate parses testdata/ec_test.pem (a SEC1 EC private key).
func loadECPrivate(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	block := pemBlock(t, "testdata/ec_test.pem")
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse EC private: %v", err)
	}
	return key
}

// loadECPublic parses testdata/ec_test_pub.pem (a PKIX public key).
func loadECPublic(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	block := pemBlock(t, "testdata/ec_test_pub.pem")
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse EC public: %v", err)
	}
	return pub.(*ecdsa.PublicKey)
}

// pemBlock reads and decodes the first PEM block of a fixture.
func pemBlock(t *testing.T, path string) *pem.Block {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("no PEM block in %s", path)
	}
	return block
}

// The fixed HMAC secret and payload the golden vectors below were produced from.
const goldenSecret = "my$ecretK3y"

// goldenPayload is the exact ordered payload the gem encoded; JSON key order is
// user,admin, which the vectors depend on.
func goldenPayload() *OrderedMap {
	m := NewOrderedMap()
	m.Set("user", "amy")
	m.Set("admin", true)
	return m
}

// Golden tokens produced by `jwt` gem 3.2.0 from goldenPayload()+goldenSecret and
// the testdata keys. Deterministic algorithms only (HS*, RS* are PKCS1v15).
const (
	goldenHS256 = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYW15IiwiYWRtaW4iOnRydWV9.CJOpglpHz5GSoUwox78TkPuXjTY4fyatqWBlS2XZlF4"
	goldenHS384 = "eyJhbGciOiJIUzM4NCJ9.eyJ1c2VyIjoiYW15IiwiYWRtaW4iOnRydWV9.MuzAgEDuoCLPCJ4BiEvWc2JfqkFfe8WUaPfohRUTYfTkoNjlUv2k8dLt11OLOAJG"
	goldenHS512 = "eyJhbGciOiJIUzUxMiJ9.eyJ1c2VyIjoiYW15IiwiYWRtaW4iOnRydWV9.2qjLcuHI_tq2BqsZpeX7GW9Ofo-5l1chvr-FZsEptN-4_PMDRCXhuAJuYM2I0V_sVV433_i2c2uddRwa1-D2OQ"
)

// Golden RS* tokens (deterministic PKCS1v15) from the testdata RSA key.
const (
	goldenRS256 = "eyJhbGciOiJSUzI1NiJ9.eyJ1c2VyIjoiYW15IiwiYWRtaW4iOnRydWV9.THQz0r4LmgLl_myJmRPjWqq0P8LqkS-PhMTUURJSP3XSmGXNYbtMVV9QabjOzY6oLJaqRT42FSsOD9uZS5ok38DaCW--BJyRup0r0nSaOKL6nmMzJzsvzmqCUIpiMj_YBxMeble9XSx_gyK_ehtQNdcHNs9EfzqsyPUi5Vbp0R2kXaqf3Mf0nFTcuRRoxwMgCxunw4huiMIbcTEWq-SN5i-CiMwRURot1eEdnXuTraWnTuQvOqvpZFdYwfIPV8awJWnqdPFNA9mi2Ln4ebMJNmNhbvsQVEgu91NkZ7S1o9hREfufH3Er3cOcVgUzSQQGflcaDoJyANIKO62-xWzFcg"
	goldenRS384 = "eyJhbGciOiJSUzM4NCJ9.eyJ1c2VyIjoiYW15IiwiYWRtaW4iOnRydWV9.AnxlYxow_IzdBpyHtlJKoZKyr060vu6NYwbVa_3ZuWvtx0-Ua7GXOk1jZKLlLmsrsMk1Ibr5LQM1WY4RXhNL8XJbUzbmKdwVMdIj13E0jh1HbF-fTMmqmZ3kFJqZcfESnDP80ofBzq5xGCBiaoG7UeRKFlF9kDEkzj-zkDJQ838lGeM6mSoSg2WtnJ1OFJBjXd4232MbslkRNl2xT5DusIKTkImq54ykrXB4aRAH81AVz0s5tbAc4ugPOY9Hi3W2mxYWiJjvSxkDfbIRI5sHXurJlP60AFdpmfOegc-rQ3SMZa51UNn7HlcEnQ1hSew66txInALcDW4LsvYZjKjykQ"
	goldenRS512 = "eyJhbGciOiJSUzUxMiJ9.eyJ1c2VyIjoiYW15IiwiYWRtaW4iOnRydWV9.oWM_xgr2nJevYLE5QAS3mT6riZNtXOORt9VsAmRzfw8shQMPj_qSOMs1oSvU59D3CiJh2PIF2gmR1mzxIyFBOSv7N0ZW3OnB9is0e1aUV33GPLES6akQRG-co2xIYOnXOwJD6sIXchsetIphEbcGuut7LTNtt8O43ENpGc9O0OL1mDw1DhoCM0RaWKjQYiL6eBzmooghLPqHTRfE3ZnalcEiJdv4M2tJQEkFmGTrU2Fg_TCEtUOOBr24lj7NLlzTpPgpJUL0CYtumFwY1mAWFyF24eNXWH7d1zUwqBa1j9H7WMzQmsdyK4FZmOz_qsYn7gHs5xsM2xPsO5dXXFhRHQ"
)
