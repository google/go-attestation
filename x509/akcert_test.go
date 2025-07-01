package certinfo

import (
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"

	"google3/base/go/runfiles"
)

const (
	akCertPEM = `-----BEGIN CERTIFICATE-----
MIID/DCCA6OgAwIBAgITA6tUAFFuu4qNntjCQrwqek3NvTAKBggqhkjOPQQDAjCB
ozELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDU1v
dW50YWluIFZpZXcxEzARBgNVBAoTCkdvb2dsZSBMTEMxUjBQBgNVBAMMSXRwbV9h
a192MV9jb3JwX2hvc3Qtc2lnbmVyLTAtMjAxOS0xMi0zMFQxNDoyMzoxMVogSzox
LCAxOjJTVDFuTEZqQWd3OjA6MjgwHhcNMjAxMDE1MTQwMDE4WhcNMzgwMTE5MDMw
MDE4WjBeMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UE
BwwNTW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIExMQzENMAsGA1UECwwE
Q29ycDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMllnIzzVo/K/Syk
9jEvZkehXoVxEpWrCyt84eKtBvrmDefEGwhwPS5cZwS9XavoArXGOuYkPqa8UpIM
eueVuTN+O1TYjsN1DiTprZ21bYcR05o+a5rgvUNFr3VhypWWUvK2IUcTTfVkr1jH
9LlG6nXrgRtCHvZ+IV05rffMZws3PUDXCiEyETOgoytHknv7fXpJXoVSiJoOD0Lb
+fkQzepokbWFI76IkGP18i5KmmkUc2VtIifIZA/O/0ab8noaDE+YcHLu8j4LXE6E
6DkIeKAsu7fztQC+wq+dINFn8Gdkc5eDSgMIClC1Ms+0CsZaS07iKW+DpqYPNLWS
16KwXT8CAwEAAaOCAS0wggEpMB8GA1UdIwQYMBaAFD6Q60/Rq8oi6Bx6ztsg38Qr
xTmsMB0GA1UdDgQWBBRGnlI9djPfdwEdfqsW/T6f2lyewTAOBgNVHQ8BAf8EBAMC
B4AwDAYDVR0TAQH/BAIwADAZBgNVHSUEEjAQBgZngQULAQEGBmeBBQsBAzCBrQYD
VR0RBIGlMIGioFcGCCsGAQUFBwgDoEswSQxAZTNiMGM0NDI5OGZjMWMxNDlhZmJm
NGM4OTk2ZmI5MjQyN2FlNDFlNDY0OWI5MzRjYTQ5NTk5MWI3ODUyYjg1NQYFZ4EF
DAGkRzBFMRYwFAYFZ4EFAgEMC2lkOjQ5NDY1ODAwMRMwEQYFZ4EFAgIMCFNMQiA5
NjY1MRYwFAYFZ4EFAgMMC2lkOjAwMDUwMDNlMAoGCCqGSM49BAMCA0cAMEQCIAo0
iuu+eDD4xL55Ej5YB0V6Hh7teb/YIpDFzX4kTmu+AiBqHJREvbSijB1vezzxCspF
0SPQzVWbWyzf19HBabCl2g==
-----END CERTIFICATE-----
`
	akCertPEMWithGceID = `-----BEGIN CERTIFICATE-----
MIIDXjCCAwOgAwIBAgITA4goLPlAxkruGmHLs1V2lxVe0DAKBggqhkjOPQQDAjCB
ozELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDU1v
dW50YWluIFZpZXcxEzARBgNVBAoTCkdvb2dsZSBMTEMxUjBQBgNVBAMMSXRwbV9h
a192MV9jb3JwX2hvc3Qtc2lnbmVyLTAtMjAyMy0wMS0wM1QyMToxOTozOVogSzox
LCAxOjJTVDFuTEZqQWd3OjA6MjgwHhcNMjMwODEyMDE0MDI3WhcNMjMwODEyMDE0
MjA3WjBeMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UE
BwwNTW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIExMQzENMAsGA1UECwwE
Q29ycDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCNGkYFuVYADxRf1svu2dTxM
vso9PZhs0da96Ot24FPJ1qHru6ydS/M92p5ntUhwFjQM9ldAhcIZC++YvLHMF2Sj
ggFYMIIBVDAfBgNVHSMEGDAWgBQ+kOtP0avKIugces7bIN/EK8U5rDAdBgNVHQ4E
FgQUSWxT1nGCWM8TQHwIG939ip1lUV0wDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB
/wQCMAAwGQYDVR0lBBIwEAYGZ4EFCwEBBgZngQULAQMwYgYDVR0RBFswWaBXBggr
BgEFBQcIA6BLMEkMQGUzYjBjNDQyOThmYzFjMTQ5YWZiZjRjODk5NmZiOTI0Mjdh
ZTQxZTQ2NDliOTM0Y2E0OTU5OTFiNzg1MmI4NTUGBWeBBQwBMHUGCisGAQQB1nkC
ARUEZzBlDA11cy1jZW50cmFsMS1jAgYAjH+BYLcMDmEtcHJvamVjdC1uYW1lAggY
Nn+bhIWMQwwQYW4taW5zdGFuY2UtbmFtZaAgMB6gAwIBEaEDAQH/ogMBAf+jAwEB
/6QDAQH/pQMBAQAwCgYIKoZIzj0EAwIDSQAwRgIhAI275NRvnHXpxx/jk24n8ck8
ilMH+HHre411zR+qoLsoAiEA+Ue+r7LPoE1z8szzynUVteA04msN4nu9C8CLK9Mk
ubI=
-----END CERTIFICATE-----
`

	akCertPEMWithADID = `-----BEGIN CERTIFICATE-----
MIIC/jCCAqSgAwIBAgITAyyE4s5DggAK1n5WR1tjhmDAJTAKBggqhkjOPQQDAjCB
ozELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDU1v
dW50YWluIFZpZXcxEzARBgNVBAoTCkdvb2dsZSBMTEMxUjBQBgNVBAMMSXRwbV9h
a192MV9jb3JwX2hvc3Qtc2lnbmVyLTAtMjAyMy0wMS0wM1QyMToxOTozOVogSzox
LCAxOjJTVDFuTEZqQWd3OjA6MjgwHhcNMjMwODE0MDQ0MDIyWhcNMjMwODE0MDQ0
MjAyWjBeMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UE
BwwNTW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIExMQzENMAsGA1UECwwE
Q29ycDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCNGkYFuVYADxRf1svu2dTxM
vso9PZhs0da96Ot24FPJ1qHru6ydS/M92p5ntUhwFjQM9ldAhcIZC++YvLHMF2Sj
gfowgfcwHwYDVR0jBBgwFoAUPpDrT9GryiLoHHrO2yDfxCvFOawwHQYDVR0OBBYE
FElsU9ZxgljPE0B8CBvd/YqdZVFdMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8E
AjAAMBkGA1UdJQQSMBAGBmeBBQsBAQYGZ4EFCwEDMGIGA1UdEQRbMFmgVwYIKwYB
BQUHCAOgSzBJDEBlM2IwYzQ0Mjk4ZmMxYzE0OWFmYmY0Yzg5OTZmYjkyNDI3YWU0
MWU0NjQ5YjkzNGNhNDk1OTkxYjc4NTJiODU1BgVngQUMATAYBgorBgEEAdZ5AgEc
BAoECGFkaWQwMTIzMAoGCCqGSM49BAMCA0gAMEUCIQCOLIkyMMcjvOFm0BVn687d
WYmtlgo/P2x0X+qJZ3xBBwIgCsDwAWq/6U8emNAKCsgoWFLi3RaOIdicvjlQkeWO
Gq8=
-----END CERTIFICATE-----
`

	akFingerprint       = "3f092ad1e3aedcc6611a27a2eba018f877ded9094fb57361a42e459140c797bb"
	permanentIdentifier = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	akAdid              = "adid0123"
)

func akCert(t *testing.T) *AKCertificate {
	return akCertFromBytes(t, []byte(akCertPEM))
}

func akCertFromBytes(t *testing.T, c []byte) *AKCertificate {
	t.Helper()
	p, _ := pem.Decode(c)
	if p == nil {
		t.Fatalf("failed to decode PEM")
	}
	cert, err := ParseAKCertificate(p.Bytes)
	if err != nil {
		t.Fatalf("ParseAKCertificate failed: %v", err)
	}
	return cert
}

func TestAKFingerprint(t *testing.T) {
	cert := akCert(t)
	if got, want := cert.Fingerprint(), akFingerprint; got != want {
		t.Errorf("Fingerprint() = %v, want %v", got, want)
	}
}

func TestPermanentIdentifier(t *testing.T) {
	cert := akCert(t)
	if got, want := cert.PermanentIdentifier.IdentifierValue, permanentIdentifier; got != want {
		t.Errorf("PermanentIdentifier() = %q, want %q", got, want)
	}
}

func TestAKVerify(t *testing.T) {
	cert := akCert(t)
	_, err := cert.Verify(x509.VerifyOptions{})
	if _, ok := err.(x509.UnknownAuthorityError); !ok {
		t.Errorf("Verify() failed unexpectedly; err=%s", err)
	}
}

func TestAKGCEInstanceID(t *testing.T) {
	cert := akCertFromBytes(t, []byte(akCertPEMWithGceID))
	got, _ := cert.GCEInstanceID()
	gceInstanceID := &GCEInstanceID{
		Zone:          "us-central1-c",
		ProjectNumber: big.NewInt(603434606775),
		ProjectID:     "a-project-name",
		InstanceID:    big.NewInt(1744722211572649027),
		InstanceName:  "an-instance-name",
		SecurityProperties: GCESecurityProperties{
			SecurityVersion:             big.NewInt(17),
			IsProduction:                true,
			TpmDataAlwaysEncrypted:      true,
			SuspendResumeAlwaysDisabled: true,
			VmtdAlwaysDisabled:          true,
			AlwaysInYarn:                false,
		},
	}
	if diff := diff(gceInstanceID, got); diff != "" {
		t.Errorf("GCEInstanceID() returned unexpected diff (-want +got):\n%s", diff)
	}
}

func TestAKADIDNotPresent(t *testing.T) {
	cert := akCertFromBytes(t, []byte(akCertPEMWithGceID))
	adid, found := cert.ADID()
	if found {
		t.Errorf("ADID found: %q", *adid)
	}
}

func TestAKADID(t *testing.T) {
	cert := akCertFromBytes(t, []byte(akCertPEMWithADID))
	a, found := cert.ADID()
	if !found {
		t.Errorf("ADID not found")
	}
	if got, want := *a, akAdid; got != want {
		t.Errorf("ADID() = %q, want %q", got, want)
	}
}

func TestParseAKCertificate(t *testing.T) {
	tests := []struct {
		path string
	}{
		{
			path: "ak_cert_without_san.pem",
		},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			b, err := runfiles.ReadFile("google3/ops/security/attestation/testdata/" + test.path)
			if err != nil {
				t.Fatal(err)
			}
			p, _ := pem.Decode(b)
			if _, err = ParseAKCertificate(p.Bytes); err != nil {
				t.Errorf("ParseAKCertificate failed: %v", err)
			}
		})
	}
}
