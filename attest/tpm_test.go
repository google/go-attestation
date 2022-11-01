package attest

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
)

// Generated using the following command:
//
// openssl genrsa 2048|openssl rsa -outform PEM -pubout
var testRSAKey = mustParseRSAKey(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq8zyTXCjVALZzjS8wgNH
nAVdt4ZGM3N450xOnLplx/RbCVwXyu83SWh0B3Ka+92aocqcHzo+j6e6Urppre/I
+7VVKTdUAr8t5gxgSLGvo+ev+zv70GF4DmJthb8JNheHCmk3RnoSFs5TnDuSdvGb
KcSzas0186LQyxvwfFjTxLweGrZKh/CTewD0/f5ozXmbTtJpl+qYrMi9GJamGlg6
N6EsWKh1xos8J/cEmS2vbyCGGADyBwRV8Zkto5EU1HJaEli10HVZf0D06vuKzzxM
+6W7LzGqzAPeaWvHi07ezShqdr5q5y1KKhFJcy8HOpwN8iFfIw70y3FtMlrMprrU
twIDAQAB
-----END PUBLIC KEY-----`)

func mustParseRSAKey(data string) *rsa.PublicKey {
	pub, err := parseRSAKey(data)
	if err != nil {
		panic(err)
	}
	return pub
}

func parseRSAKey(data string) (*rsa.PublicKey, error) {
	b, _ := pem.Decode([]byte(data))
	if b == nil {
		return nil, fmt.Errorf("failed to parse PEM key")
	}
	pub, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %v", err)
	}
	if rsaPub, ok := pub.(*rsa.PublicKey); ok {
		return rsaPub, nil
	}
	return nil, fmt.Errorf("expected *rsa.PublicKey, got %T", pub)
}

func TestIntelEKURL(t *testing.T) {
	want := "https://ekop.intel.com/ekcertservice/7YtWV2nT3LpvSCfJt7ENIznN1R1jYkj_3S6mez3yyzg="
	got := intelEKURL(testRSAKey)
	if got != want {
		t.Fatalf("intelEKURL(), got=%q, want=%q", got, want)
	}
}
