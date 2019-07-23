package attest

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"testing"
)

func TestMakeActivationBlob(t *testing.T) {
	blob, err := makeActivationBlob([]byte{1, 2, 3, 4, 5}, []byte{5, 6, 7, 8})
	if err != nil {
		t.Fatal(err)
	}

	if got, want := blob[0:2], []byte{0, 0x2b}; !bytes.Equal(got, want) {
		t.Errorf("tag = %v, want %v", got, want)
	}
	if got, want := blob[2:6], []byte{0, 0, 0, 0x0a}; !bytes.Equal(got, want) {
		t.Errorf("alg = %v, want %v", got, want)
	}
	if got, want := blob[6:8], []byte{0, 1}; !bytes.Equal(got, want) {
		t.Errorf("scheme = %v, want %v", got, want)
	}
	if got, want := blob[8:10], []byte{0, 5}; !bytes.Equal(got, want) {
		t.Errorf("len = %v, want %v", got, want)
	}
	if got, want := blob[10:15], []byte{1, 2, 3, 4, 5}; !bytes.Equal(got, want) {
		t.Errorf("symKey = %v, want %v", got, want)
	}
	if got, want := blob[15:35], []byte{133, 217, 101, 29, 154, 57, 154, 103, 224, 21, 208, 71, 253, 158, 106, 148, 30, 107, 32, 187}; !bytes.Equal(got, want) {
		t.Errorf("aik digest = %v, want %v", got, want)
	}
	if got, want := blob[35:37], []byte{0, 3}; !bytes.Equal(got, want) {
		t.Errorf("size of select = %v, want %v", got, want)
	}
	if got, want := blob[37:40], []byte{0, 0, 0}; !bytes.Equal(got, want) {
		t.Errorf("select bitfield = %v, want %v", got, want)
	}
	if got, want := blob[40:41], []byte{1}; !bytes.Equal(got, want) {
		t.Errorf("locality = %v, want %v", got, want)
	}
	if got, want := blob[41:61], bytes.Repeat([]byte{0}, 20); !bytes.Equal(got, want) {
		t.Errorf("select digest = %v, want %v", got, want)
	}
}

func TestGenerateChallengeSymHeader(t *testing.T) {
	cert, err := x509.ParseCertificate(decodeBase64("MIID2jCCA4CgAwIBAgIKFsBPsR6KEUuzHjAKBggqhkjOPQQDAjBVMVMwHwYDVQQDExhOdXZvdG9uIFRQTSBSb290IENBIDIxMTAwJQYDVQQKEx5OdXZvdG9uIFRlY2hub2xvZ3kgQ29ycG9yYXRpb24wCQYDVQQGEwJUVzAeFw0xNzEwMTgyMzQ5MjBaFw0zNzEwMTQyMzQ5MjBaMAAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCsiqa4C+4hxqQgQ93aFmVq+hvbV6FDvNod24lA1s24pVJzUdOW/D0ORY3TdvRKS1xEh+yPD+iao+XrRGELHSOrGxid/kaTiOF8KdR5BWJwCoedQasqMyQsgZNlU6nKoERcex2G6DDozkdUgrJ/A04qG8tkpEfwmS+0SVWEtDoTb4fzdehKmS32gKcY/I3ZnmpE/5+FCJHKUwIPxHPwAGdhWoYEGsb7ZwG3/S4UuPEfHaab/iwj/WxwbnGtysMu9r1ZkHjQx6FblWVLoXCqrTl0q0samTuW52MffybbOEzn9R0pnfiyQlpL8CLKP4/kBPUGkkvZm2MJsF2cwNRJtEXVAgMBAAGjggHAMIIBvDBKBgNVHREBAf8EQDA+pDwwOjE4MBQGBWeBBQIBEwtpZDo0RTU0NDMwMDAQBgVngQUCAhMHTlBDVDZ4eDAOBgVngQUCAxMFaWQ6MTMwDAYDVR0TAQH/BAIwADAQBgNVHSUECTAHBgVngQUIATAfBgNVHSMEGDAWgBSfu3mqD1JieL7RUJKacXHpajW+9zAOBgNVHQ8BAf8EBAMCBSAwcAYDVR0JBGkwZzAWBgVngQUCEDENMAsMAzIuMAIBAAIBdDBNBgVngQUCEjFEMEICAQABAf+gAwoBAaEDCgEAogMKAQCjFTATFgMzLjEKAQQKAQEBAf+gAwoBAqQPMA0WBTE0MC0yCgECAQEApQMBAQAwQQYDVR0gBDowODA2BgRVHSAAMC4wLAYIKwYBBQUHAgEWIGh0dHA6Ly93d3cubnV2b3Rvbi5jb20vc2VjdXJpdHkvMGgGCCsGAQUFBwEBBFwwWjBYBggrBgEFBQcwAoZMaHR0cDovL3d3dy5udXZvdG9uLmNvbS9zZWN1cml0eS9OVEMtVFBNLUVLLUNlcnQvTnV2b3RvbiBUUE0gUm9vdCBDQSAyMTEwLmNlcjAKBggqhkjOPQQDAgNIADBFAiEAtct+vD/l1Vv9TJOl6oRSI+IZk+k31YIqcscDZEGpZI0CIFFAsVKlFnQnXKTxo7sx9dGOio92Bschl0TQLQhVv0K7", t))
	if err != nil {
		t.Fatal(err)
	}

	_, sym, err := generateChallenge12(cert.PublicKey.(*rsa.PublicKey), []byte("pubkey yo"), []byte("secretz"))
	if err != nil {
		t.Fatal(err)
	}

	if got, want := len(sym), 36; got != want {
		t.Errorf("len(sym) = %v, want %v", got, want)
	}
	if got, want := sym[0:4], []byte{0, 0, 0, 2}; !bytes.Equal(got, want) {
		t.Errorf("symmetric mode = %v, want %v", got, want)
	}
}
