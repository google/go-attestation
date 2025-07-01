package certinfo

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"testing"

	"google3/base/go/runfiles"
	"google3/third_party/golang/cmp/cmp"

	_ "embed"
)

var (
	ekCertPEM = []byte(`-----BEGIN CERTIFICATE-----
MIIFOTCCBCGgAwIBAgITAQxH39TYCjKTYYLVb6fkQLapiDANBgkqhkiG9w0BAQsF
ADCBuTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcT
DU1vdW50YWluIFZpZXcxEzARBgNVBAoTCkdvb2dsZSBMTEMxDjAMBgNVBAsTBUNs
b3VkMVgwVgYDVQQDDE90cG1fZWtfdjFfY2xvdWRfaG9zdC1zaWduZXItMC0yMDE4
LTAyLTE0VDE0OjQ1OjE0LTA4OjAwIEs6MSwgMTplQzZTNzJUWElCazowOjE4MCAX
DTIwMTAxNTE2MDkwN1oYDzIwNTAxMDA4MTYxNDA3WjAAMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAyWWcjPNWj8r9LKT2MS9mR6FehXESlasLK3zh4q0G
+uYN58QbCHA9LlxnBL1dq+gCtcY65iQ+prxSkgx655W5M347VNiOw3UOJOmtnbVt
hxHTmj5rmuC9Q0WvdWHKlZZS8rYhRxNN9WSvWMf0uUbqdeuBG0Ie9n4hXTmt98xn
Czc9QNcKITIRM6CjK0eSe/t9eklehVKImg4PQtv5+RDN6miRtYUjvoiQY/XyLkqa
aRRzZW0iJ8hkD87/RpvyehoMT5hwcu7yPgtcToToOQh4oCy7t/O1AL7Cr50g0Wfw
Z2Rzl4NKAwgKULUyz7QKxlpLTuIpb4Ompg80tZLXorBdPwIDAQABo4IB7jCCAeow
DAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBSsv2H/E9NJhdpJ0lG2ui0wZ3I/7TBc
BggrBgEFBQcBAQRQME4wTAYIKwYBBQUHMAKGQGh0dHBzOi8vcGtpLmdvb2cvY2xv
dWRfaW50ZWdyaXR5L3RwbV9la19pbnRlcm1lZGlhdGVfaDFfMjAxOC5jcnQwUQYD
VR0fBEowSDBGoESgQoZAaHR0cHM6Ly9wa2kuZ29vZy9jbG91ZF9pbnRlZ3JpdHkv
dHBtX2VrX2ludGVybWVkaWF0ZV9oMV8yMDE4LmNybDAOBgNVHQ8BAf8EBAMCB4Aw
EAYDVR0lBAkwBwYFZ4EFCAEwIQYDVR0JBBowGDAWBgVngQUCEDENMAsMAzIuMAIB
AQIBMDBRBgNVHREBAf8ERzBFpEMwQTEWMBQGBWeBBQIBDAtpZDo0NzRGNEY0NzEP
MA0GBWeBBQICDAR2VFBNMRYwFAYFZ4EFAgMMC2lkOjU0NDM0NzAwMHAGCisGAQQB
1nkCARUEYjBgDA11cy1jZW50cmFsMS1jAgYAjH+BYLcMDmEtcHJvamVjdC1uYW1l
AggYNn+bhIWMQwwQYW4taW5zdGFuY2UtbmFtZaAbMBmgAwIBEaEDAQEAogMBAf+j
AwEB/6QDAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAcApgp3lr0z1JloL6icor7aUMy
vFXRwev1ybPwixyH677BxeCLpDPpWT0zzLt+BXSGtPriIHsxZhFJT2u2BGB1140q
ZaAumrfaa3K3Ig8R8TZvZ+B3bHCNDdxfl1AABiZFh9SGLTjux3qUKyk1rJ9OQhJB
C67h0OEMcPA+PlgPFkZhsVuUak8W2N/J7wSfcSoOG+8S06dbvw+PdZ8kR1PvOVYB
vu41hO8OFRLUyEcSQZezizzox18uYiVVR58/wJVYc7d+17c9kxZCZdxJjzQCnlKS
J1iT6R1ujE5RGOkQu+ltEVR2IFGvqgpRMCE3ua+LTAHJj1aW1WKr8YgfXKk8
-----END CERTIFICATE-----
`)
	oaepPEM = []byte(`-----BEGIN X509 CERTIFICATE-----
MIIFbjCCBFagAwIBAgIEKp463zANBgkqhkiG9w0BAQUFADB3MQswCQYDVQQGEwJE
RTEPMA0GA1UECBMGU2F4b255MSEwHwYDVQQKExhJbmZpbmVvbiBUZWNobm9sb2dp
ZXMgQUcxDDAKBgNVBAsTA0FJTTEmMCQGA1UEAxMdSUZYIFRQTSBFSyBJbnRlcm1l
ZGlhdGUgQ0EgMjAwHhcNMTcwODAzMDgyNDA4WhcNMjcwODAzMDgyNDA4WjAAMIIB
NzAiBgkqhkiG9w0BAQcwFaITMBEGCSqGSIb3DQEBCQQEVENQQQOCAQ8AMIIBCgKC
AQEAnEsUFEJHO1M1ZaEp34p+yuX8oJ8d5enBWIiPRop9an17HhE4JPqKR8pOcbMO
GtIAJ0GXv+QxOeB+EFLs5SpLeMyn7IuR68DmGFZ/iUrpu6RXDmXNG+iZueDcpg7i
HBlsrzAj7yWpyw6TGv0y9OC5w8Xi5A3VZyTUyAiNwTlEr9fzxNzt2ONf7WxjunrA
j6OE/EBJ2OGriYAbL6hNgVK5oruk99Tokf5Kc1G46xwzJlmPUCEUmHVoGSJ1uAMZ
gTJcucMwsv2HHXN1fCdQ9VhqLNwt6WyyZLK4TcFD8p4Bk9giZGM305hdaq9Pu0e/
l4+pcZ334wOH6LUvVzY9OfPbXwIDAQABo4ICYjCCAl4wVQYDVR0RAQH/BEswSaRH
MEUxFjAUBgVngQUCAQwLaWQ6NDk0NjU4MDAxFzAVBgVngQUCAgwMU0xCOTY2MHh4
MS4yMRIwEAYFZ4EFAgMMB2lkOjA0MjgwDAYDVR0TAQH/BAIwADCBvAYDVR0gAQH/
BIGxMIGuMIGrBgtghkgBhvhFAQcvATCBmzA5BggrBgEFBQcCARYtaHR0cDovL3d3
dy52ZXJpc2lnbi5jb20vcmVwb3NpdG9yeS9pbmRleC5odG1sMF4GCCsGAQUFBwIC
MFIeUABUAEMAUABBACAAVAByAHUAcwB0AGUAZAAgAFAAbABhAHQAZgBvAHIAbQAg
AE0AbwBkAHUAbABlACAARQBuAGQAbwByAHMAZQBtAGUAbgB0MIGhBgNVHSMEgZkw
gZaAFI/9R4gOI5o6OiDeE+3xAeiCqdIdoXukeTB3MQswCQYDVQQGEwJERTEPMA0G
A1UECBMGU2F4b255MSEwHwYDVQQKExhJbmZpbmVvbiBUZWNobm9sb2dpZXMgQUcx
DDAKBgNVBAsTA0FJTTEmMCQGA1UEAxMdSUZYIFRQTSBFSyBJbnRlcm1lZGlhdGUg
Q0EgMjCCAQUwgZMGA1UdCQSBizCBiDA6BgNVBDQxMzALMAkGBSsOAwIaBQAwJDAi
BgkqhkiG9w0BAQcwFaITMBEGCSqGSIb3DQEBCQQEVENQQTAWBgVngQUCEDENMAsM
AzEuMgIBAgIBAzAyBgVngQUCEjEpMCcBAf+gAwoBAaEDCgEAogMKAQCjEDAOFgMz
LjEKAQQKAQEBAf8BAf8wDQYJKoZIhvcNAQEFBQADggEBAGKyolaAVQn1qbbgCbTy
e+Qgs0QjishRl80rV6w5Rp/P6W44ZH43uO22f97qwVPDd8nIAsaxQ35F8XfvyZZx
uLnayXibyuM3c4hG5uuIiM5yMkk9v9rX0yKvoU+xa0QShqbD4aK7PNnYvnowWyqQ
YyUGubMjwk2DHdfIgpuhuXQMrszhtrl+zJp9nL3b13sQpz2Vz//Tz+WBDz0Wy2OC
PU0+umiW6ytU8FJLLVf/QUL3GuwrDsZXGlLV1jJtkJf9PBkeY2ZrI9KSN+dONFz4
WjIfRBtZpRTzhOkEwcA+jyniBBg3vZGmnqCglN4oysYAAUMCThnFZFowQ9HlaYMZ
DQI=
-----END X509 CERTIFICATE-----
`)
	bruschettaPEM = []byte(`-----BEGIN CERTIFICATE-----
MIIDxzCCAq+gAwIBAgIWAYREumDfB7Km8Q4+lWEAAAAAAAALxTANBgkqhkiG9w0B
AQsFADCBhTEgMB4GA1UEAxMXUHJpdmFjeSBDQSBJbnRlcm1lZGlhdGUxEjAQBgNV
BAsTCUNocm9tZSBPUzETMBEGA1UEChMKR29vZ2xlIEluYzEWMBQGA1UEBxMNTW91
bnRhaW4gVmlldzETMBEGA1UECBMKQ2FsaWZvcm5pYTELMAkGA1UEBhMCVVMwHhcN
MjIxMTA0MjM1MTI2WhcNNDIxMTA1MDA1MTI2WjBHMSswKQYDVQQKEyJDaHJvbWUg
RGV2aWNlIHZUUE0gRW5kb3JzZW1lbnQgS2V5MRgwFgYDVQQDEw92RUsgQ2VydGlm
aWNhdGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARk/4a+CTlWKgF5sB8K8qnz
6xjE/uHVWZykYJeEe7YdW0cS0n4nN1ETESfdN8/QVv1YucAqbMA2EGbJepDKm0QN
o4IBMzCCAS8wKQYDVR0OBCIEIMkgENLmU8GrAm9qF/vYzmzVVk3mX6zV0nTgoKb5
bp86MCsGA1UdIwQkMCKAIPQgttnYYvaLCRXOi1ek/FdOuMF8pfnmVtvQUpQpvW1/
MA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBEGA1UdIAQKMAgwBgYEVR0g
ADAaBgorBgEEAdZ5AgEcBAwECjVDRDIyNU0wWEcwEgYKKwYBBAHWeQIBEwQEBAII
AjBRBgNVHREESjBIpEYwRDEWMBQGBWeBBQIBDAtpZDo0MzUyNEY1MzESMBAGBWeB
BQICDAdpZDowMDAwMRYwFAYFZ4EFAgMMC2lkOjAwMDAwMDAwMCEGA1UdCQQaMBgw
FgYFZ4EFAhAxDTALDAMyLjACAQACAWMwDQYJKoZIhvcNAQELBQADggEBAC6NQQmb
WLNRZNOSQ+9EgP9zARERG/ma0Lld3gZ9l+XuAed096zEfYxmYs9D2AzaUpHRQBXC
28zjYZpwYkN7QZj/UYDs8oVIzUr84lnIUgMfnEpBnlJUGerpc6joS+3AsMaokSj+
Uk8s2gSygcUiliowhUcfVNX/Y/uloWIDkzGQjltl3rlyA6qHSrXOob+IaHbci4IG
Ge/moxVJDVzFRjryecnuJ+Y54mavBgXq6aCy8tzAu+fS1NYiNJoXJNiZfksQ+J1v
3KpYKOk2BbEgozwTEpsxakFEOt/Z+Z4Qs/po/td4/OKQhDQLTptCaiPham1J2w5M
vHU3yawc7L4RJb0=
-----END CERTIFICATE-----
`)
	privateCAPEM = []byte(`-----BEGIN CERTIFICATE-----
MIIF+TCCA+GgAwIBAgITKzxgGjlTp7ScH8W4ms6+uay3rjANBgkqhkiG9w0BAQsF
ADCBhjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcT
DU1vdW50YWluIFZpZXcxEzARBgNVBAoTCkdvb2dsZSBMTEMxFTATBgNVBAsTDEdv
b2dsZSBDbG91ZDEeMBwGA1UEAxMVRUsvQUsgQ0EgSW50ZXJtZWRpYXRlMCAXDTIz
MDUxNjE0MDQxMVoYDzIwNTMwNTA4MTQwNDEwWjB4MRMwEQYDVQQHEwp1cy13ZXN0
NC1hMR4wHAYDVQQKExVHb29nbGUgQ29tcHV0ZSBFbmdpbmUxIzAhBgNVBAsTGmRh
c2luZnJhLXNhcC1idXNpbmVzcy11YXQ3MRwwGgYDVQQDExM0Mzg0MjA5Njc1Nzk4
NTg5OTY3MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4038Ml9szPUL
o3HagqoaaT1SQ4Us4bKZWCu8KocvoBjwuoZj1fqal444+faRL1jFV8ZBPXjCawPX
6+8B2h36UPl05K9S2ey/S1Ajye4wpgQUJZkAmI4huMwn21/PHKRMDkjeAPEO7sxm
02vqFYNf/lAmSLbmWE1js7LPBYIluJ1JGx+5QzCJr8CTweR+b+qct3hk5Z64u832
Vbmwv6jmJKIFq2miISHH8/+lfMzKuir59BvwLiCnXLwdO1ImXrTmLSsuIqwokdhs
OJlMDMgNGPvcRwxK0K+YRYK7/bILXiGQVXQz2I979YREr24Nh7k8z9Y5vrGQp/EX
0/0lKbIUYwIDAQABo4IBaTCCAWUwDgYDVR0PAQH/BAQDAgUgMAwGA1UdEwEB/wQC
MAAwHQYDVR0OBBYEFBRDCSqg84V4skZLTFm3C1l15EG+MB8GA1UdIwQYMBaAFOJ7
x02xgfaPUPhRbYtDen6UU2MDMIGNBggrBgEFBQcBAQSBgDB+MHwGCCsGAQUFBzAC
hnBodHRwOi8vcHJpdmF0ZWNhLWNvbnRlbnQtNjMwYzRmNzUtMDAwMC0yZjFhLTk2
NjAtZDRmNTQ3ZjAzMjJjLnN0b3JhZ2UuZ29vZ2xlYXBpcy5jb20vYmIzMmI1YWJl
M2U1MWFhOGI0Y2QvY2EuY3J0MHUGCisGAQQB1nkCARUEZzBlDAp1cy13ZXN0NC1h
AgVbbX4niQwaZGFzaW5mcmEtc2FwLWJ1c2luZXNzLXVhdDcCCDzX13i6zjIPDAhz
YXB1ZGI4M6AgMB6gAwIBAKEDAQH/ogMBAQCjAwEBAKQDAQEApQMBAQAwDQYJKoZI
hvcNAQELBQADggIBAAjwlCwpRZAh3UMlNW7s3bRbNtkP1JIpHCN7QirQUXpQaI6J
twCbeHa9zvHePJHd8UhjYuvVmIK/CiuSzZDDh0Eg9/KzvrVOJz1P5yypObmgAOe0
hCdT7a1HXAOHiHI+Ua2CXmtx24XGFvY3CE1Pe84quVGIhC30I0NhF+YbAU1RGHof
NUuGbDv7KH+y5uBJh2hMkVrPf3JXumuz2+6SpwfXS1mY1YXuHTC0NO5lt+Li87+I
NrBtclqBSMhkqxiQhmAftV/Glplxl8tBPMc1UThUYYJKWBdKkXXyo3dp2TzQhiNx
H2pRExAS9eJIs3ojtdvrJHxkxKRDqsjus0hdo4rQOfNjFXatab2CIhlnUVBYfB+t
tuY9Un/y1uPOqze9CNqS0DBnXI2Wgs7eD2LZ9ksgAr+G7WOvhcyg+d5QyrYPer5O
MUVWQrZ7/Vs0BViPTQzPKD3+lxfLu5LN59qOEhcKPpFylXF9nezcG9Rh8Gn9N4z3
/PVyC7h/3vXqTA09oD7LlpBVJSmUEZzIzJdv0b4N418UfaVMFoAt/lIanNqMaKgo
DMF8y7c1x82fUGIKShPSzekmtAZ+VvfMuhOEIsmlerwZAgbcWeirPGvVfa/qRY1M
2VsysZ8owAV5B1oVdhurRNtS9jPtwijt119C3Opfq3jORu+VlREmFTcJdFzY
-----END CERTIFICATE-----`)

	//go:embed google3/ops/security/attestation/testdata/ek_cert_gce_private_ca.pem
	privateCAPEM2 []byte

	//go:embed google3/ops/security/attestation/testdata/ek_cert_gce_private_ca2.pem
	privateCAPEM3 []byte

	fingerprint   = "9f2d40c08400fd47b8d18b46f6f169d27176d973fe182dea02fde1395ee9a8d3"
	manufacturer  = "id:474F4F47"
	model         = "vTPM"
	version       = "id:54434700"
	specFamily    = "2.0"
	specLevel     = 1
	specRevision  = 48
	gceInstanceID = &GCEInstanceID{
		Zone:          "us-central1-c",
		ProjectNumber: big.NewInt(603434606775),
		ProjectID:     "a-project-name",
		InstanceID:    big.NewInt(1744722211572649027),
		InstanceName:  "an-instance-name",
		SecurityProperties: GCESecurityProperties{
			SecurityVersion:             big.NewInt(17),
			IsProduction:                false,
			TpmDataAlwaysEncrypted:      true,
			SuspendResumeAlwaysDisabled: true,
			VmtdAlwaysDisabled:          true,
			AlwaysInYarn:                false,
		},
	}
	adid = "5CD225M0XG"
)

func ekCert(t *testing.T) *EKCertificate {
	t.Helper()
	p, _ := pem.Decode(ekCertPEM)
	cert, err := ParseEKCertificate(p.Bytes)
	if err != nil {
		t.Fatalf("ParseEKCertificate failed: %v", err)
	}
	return cert
}

// diff uses `cmp.Diff()` with a custom comparer for big.Int.
func diff(x any, y any) string {
	return cmp.Diff(x, y, cmp.Comparer(func(a *big.Int, b *big.Int) bool {
		if a == nil && b == nil {
			return true
		}
		if a == nil || b == nil {
			return false
		}
		return a.Cmp(b) == 0
	}))
}

func TestFingerprint(t *testing.T) {
	cert := ekCert(t)
	if got, want := cert.Fingerprint(), fingerprint; got != want {
		t.Errorf("Fingerprint() = %v, want %v", got, want)
	}
}

func TestManufacturer(t *testing.T) {
	cert := ekCert(t)
	if got, want := cert.Manufacturer(), manufacturer; got != want {
		t.Errorf("Manufacturer() = %v, want %v", got, want)
	}
}

func TestModel(t *testing.T) {
	cert := ekCert(t)
	if got, want := cert.Model(), model; got != want {
		t.Errorf("Model() = %v, want %v", got, want)
	}
}

func TestVersion(t *testing.T) {
	cert := ekCert(t)
	if got, want := cert.Version(), version; got != want {
		t.Errorf("Version() = %v, want %v", got, want)
	}
}

func TestSpecificationFamily(t *testing.T) {
	cert := ekCert(t)
	if got, want := cert.SpecificationFamily(), specFamily; got != want {
		t.Errorf("SpecificationFamily() = %v, want %v", got, want)
	}
}

func TestSpecificationLevel(t *testing.T) {
	cert := ekCert(t)
	if got, want := cert.SpecificationLevel(), specLevel; got != want {
		t.Errorf("SpecificationLevel() = %v, want %v", got, want)
	}
}

func TestSpecificationRevision(t *testing.T) {
	cert := ekCert(t)
	if got, want := cert.SpecificationRevision(), specRevision; got != want {
		t.Errorf("SpecificationRevision() = %v, want %v", got, want)
	}
}

func TestGCEInstanceID(t *testing.T) {
	cert := ekCert(t)
	if want, got := 0, len(cert.Certificate.UnhandledCriticalExtensions); got != want {
		t.Errorf("UnhandledCriticalExtensions: got %d, want %d: %s",
			got, want,
			cert.Certificate.UnhandledCriticalExtensions)
	}
	got, _ := cert.GCEInstanceID()
	if diff := diff(gceInstanceID, got); diff != "" {
		t.Errorf("GCEInstanceID() returned unexpected diff (-want +got):\n%s", diff)
	}
}

func TestParseGCEInstanceID(t *testing.T) {
	tests := []struct {
		data []byte
		want *GCEInstanceID
	}{
		// Data generated by ascii2der with:
		//
		// SEQUENCE {
		// 	UTF8String { "us-central1-a" }
		// 	INTEGER { 603434606775 }
		// 	UTF8String { "a-project-id" }
		// 	INTEGER { 1234 }
		// 	UTF8String { "an-instance-name" }
		// }
		{[]byte{
			0x30, 0x3b, 0x0c, 0x0d, 0x75, 0x73, 0x2d, 0x63,
			0x65, 0x6e, 0x74, 0x72, 0x61, 0x6c, 0x31, 0x2d,
			0x61, 0x02, 0x06, 0x00, 0x8c, 0x7f, 0x81, 0x60,
			0xb7, 0x0c, 0x0c, 0x61, 0x2d, 0x70, 0x72, 0x6f,
			0x6a, 0x65, 0x63, 0x74, 0x2d, 0x69, 0x64, 0x02,
			0x02, 0x04, 0xd2, 0x0c, 0x10, 0x61, 0x6e, 0x2d,
			0x69, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65,
			0x2d, 0x6e, 0x61, 0x6d, 0x65,
		}, &GCEInstanceID{
			Zone:          "us-central1-a",
			ProjectNumber: big.NewInt(603434606775),
			ProjectID:     "a-project-id",
			InstanceID:    big.NewInt(1234),
			InstanceName:  "an-instance-name",
		}},

		// Data generated by ascii2der with:
		//
		// SEQUENCE {
		// 	UTF8String { "us-central1-a" }
		// 	INTEGER { 603434606775 }
		// 	UTF8String { "a-project-id" }
		// 	INTEGER { 1234 }
		// 	UTF8String { "an-instance-name" }
		//  [] { SEQUENCE {} }
		// }
		{[]byte{
			0x30, 0x3f, 0x0c, 0x0d, 0x75, 0x73, 0x2d, 0x63,
			0x65, 0x6e, 0x74, 0x72, 0x61, 0x6c, 0x31, 0x2d,
			0x61, 0x02, 0x06, 0x00, 0x8c, 0x7f, 0x81, 0x60,
			0xb7, 0x0c, 0x0c, 0x61, 0x2d, 0x70, 0x72, 0x6f,
			0x6a, 0x65, 0x63, 0x74, 0x2d, 0x69, 0x64, 0x02,
			0x02, 0x04, 0xd2, 0x0c, 0x10, 0x61, 0x6e, 0x2d,
			0x69, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65,
			0x2d, 0x6e, 0x61, 0x6d, 0x65, 0xa0, 0x02, 0x30,
			0x00,
		}, &GCEInstanceID{
			Zone:          "us-central1-a",
			ProjectNumber: big.NewInt(603434606775),
			ProjectID:     "a-project-id",
			InstanceID:    big.NewInt(1234),
			InstanceName:  "an-instance-name",
		}},

		// Data generated by ascii2der with:
		//
		//  SEQUENCE {
		//		UTF8String { "us-central1-a" }
		//		INTEGER { 603434606775 }
		//		UTF8String { "a-project-id" }
		//		INTEGER { 1234 }
		//		UTF8String { "an-instance-name" }
		//		[0] {
		//			SEQUENCE {
		//				[0] { INTEGER { 10 } }     # security_version
		//				[1] { BOOLEAN { FALSE } }  # is_production
		//				[2] { BOOLEAN { TRUE } }   # tpm_data_always_encrypted
		//				[3] { BOOLEAN { TRUE } }   # suspend_resume_always_disabled
		//				[4] { BOOLEAN { TRUE } }   # vmtd_always_disabled
		//				[5] { BOOLEAN { TRUE } }   # always_in_yawn
		//			}
		//		}
		//	}
		{[]byte{
			0x30, 0x5d, 0x0c, 0x0d, 0x75, 0x73, 0x2d, 0x63,
			0x65, 0x6e, 0x74, 0x72, 0x61, 0x6c, 0x31, 0x2d,
			0x61, 0x02, 0x06, 0x00, 0x8c, 0x7f, 0x81, 0x60,
			0xb7, 0x0c, 0x0c, 0x61, 0x2d, 0x70, 0x72, 0x6f,
			0x6a, 0x65, 0x63, 0x74, 0x2d, 0x69, 0x64, 0x02,
			0x02, 0x04, 0xd2, 0x0c, 0x10, 0x61, 0x6e, 0x2d,
			0x69, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65,
			0x2d, 0x6e, 0x61, 0x6d, 0x65, 0xa0, 0x20, 0x30,
			0x1e, 0xa0, 0x03, 0x02, 0x01, 0x0a, 0xa1, 0x03,
			0x01, 0x01, 0x00, 0xa2, 0x03, 0x01, 0x01, 0xff,
			0xa3, 0x03, 0x01, 0x01, 0xff, 0xa4, 0x03, 0x01,
			0x01, 0xff, 0xa5, 0x03, 0x01, 0x01, 0xff,
		}, &GCEInstanceID{
			Zone:          "us-central1-a",
			ProjectNumber: big.NewInt(603434606775),
			ProjectID:     "a-project-id",
			InstanceID:    big.NewInt(1234),
			InstanceName:  "an-instance-name",
			SecurityProperties: GCESecurityProperties{
				SecurityVersion:             big.NewInt(10),
				IsProduction:                false,
				TpmDataAlwaysEncrypted:      true,
				SuspendResumeAlwaysDisabled: true,
				VmtdAlwaysDisabled:          true,
				AlwaysInYarn:                true,
			},
		}},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("test-%v", i), func(t *testing.T) {
			got, err := parseGCEInstanceID(pkix.Extension{Value: test.data})
			if err != nil {
				t.Errorf("parseGCEInstanceID() failed unexpectedly: %v", err)
			}
			if diff := diff(test.want, got); diff != "" {
				t.Errorf("parseGCEInstanceID() returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}

	// Data generated by ascii2der with:
	//
	// SEQUENCE {
	// 	INTEGER { 603434606775 }
	// 	UTF8String { "a-project-id" }
	// 	INTEGER { 1234 }
	// 	UTF8String { "an-instance-name" }
	// }
	malformedData := []byte{
		0x30, 0x33, 0x02, 0x06, 0x00, 0x8c, 0x7f, 0x81,
		0x60, 0xb7, 0x0c, 0x0c, 0x61, 0x2d, 0x70, 0x72,
		0x6f, 0x6a, 0x65, 0x63, 0x74, 0x2d, 0x69, 0x64,
		0x02, 0x09, 0x00, 0x8d, 0x06, 0xf0, 0x0d, 0x5a,
		0x62, 0x3d, 0x4c, 0x0c, 0x10, 0x61, 0x6e, 0x2d,
		0x69, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65,
		0x2d, 0x6e, 0x61, 0x6d, 0x65,
	}
	if _, err := parseGCEInstanceID(pkix.Extension{Value: malformedData}); err == nil {
		t.Errorf("parsedGCEInstanceID() didn't return an error")
	}
}

func TestADIDNotPresent(t *testing.T) {
	cert := ekCert(t)
	adid, found := cert.ADID()
	if found {
		t.Errorf("ADID found: %q", *adid)
	}
}

func TestParseEKCertificate(t *testing.T) {
	tests := []struct {
		name           string
		certPath       string
		isKuneti       bool
		expectedArchID string
		expectError    bool
	}{
		{
			name:           "Kuneti_ek_cert_rsa",
			certPath:       "google3/ops/security/attestation/testdata/ek_cert_kuneti_rsa.pem",
			isKuneti:       true,
			expectedArchID: "6ea03af0-0f13-4636-9ae7-aaaaaa3f3d49",
		},
		{
			name:           "Kuneti_ek_cert_rsa_dev_cluster",
			certPath:       "google3/ops/security/attestation/testdata/ek_cert_kuneti_rsa_dev_cluster.pem",
			isKuneti:       true,
			expectedArchID: "6ea03af0-0f13-4636-9ae7-aaaaaa3f3d49",
		},
		{
			name:           "Kuneti_ek_cert_ecc",
			certPath:       "google3/ops/security/attestation/testdata/ek_cert_kuneti_ecc.pem",
			isKuneti:       true,
			expectedArchID: "6ea03af0-0f13-4636-9ae7-aaaaaa3f3d49",
		},
		{
			name:           "Kuneti_ek_cert_ecc_dev_cluster",
			certPath:       "google3/ops/security/attestation/testdata/ek_cert_kuneti_ecc_dev_cluster.pem",
			isKuneti:       true,
			expectedArchID: "6ea03af0-0f13-4636-9ae7-aaaaaa3f3d49",
		},
		{
			name:           "GCE_ek_cert_not_kuneti",
			certPath:       "google3/ops/security/attestation/testdata/ek_cert_gce_private_ca.pem",
			isKuneti:       false,
			expectedArchID: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			certBytes, err := os.ReadFile(runfiles.Path(tc.certPath))
			if err != nil {
				t.Fatalf("failed to read cert: %v", err)
			}

			block, _ := pem.Decode(certBytes)
			if block == nil {
				t.Fatalf("failed to decode pem: %v", err)
			}

			cert, err := ParseEKCertificate(block.Bytes)
			if err != nil {
				t.Fatalf("ParseEKCertificate() failed: %v", err)
			}
			if tc.expectError {
				return
			}
			if cert.IsKuneti() != tc.isKuneti {
				t.Errorf("IsKuneti() got: %v, want: %v", cert.IsKuneti(), tc.isKuneti)
			}
			archID := cert.ArchboardID()
			if archID != tc.expectedArchID {
				t.Errorf("ArchboardID() got: %v, want: %v", archID, tc.expectedArchID)
			}
			if cert.Manufacturer() != "" {
				t.Errorf("Received Manufacturer() got: %v, want empty", cert.Manufacturer())
			}
		})
	}
}

func TestInvalidKuneti(t *testing.T) {
	certBytes, err := os.ReadFile(runfiles.Path("google3/ops/security/attestation/testdata/ek_cert_kuneti_ecc.pem"))
	if err != nil {
		t.Fatalf("failed to read cert: %v", err)
	}

	block, _ := pem.Decode(certBytes)
	if block == nil {
		t.Fatalf("failed to decode pem: %v", err)
	}

	validKunetiCert, err := ParseEKCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseEKCertificate() failed: %v", err)
	}
	tests := []struct {
		name string
		cert func() *x509.Certificate
	}{
		{
			name: "No Subject Org",
			cert: func() *x509.Certificate {
				cert := validKunetiCert.Certificate
				cert.Subject = pkix.Name{}
				return cert
			},
		},
		{
			name: "Too many Subject Orgs",
			cert: func() *x509.Certificate {
				cert := validKunetiCert.Certificate
				cert.Subject = pkix.Name{
					Organization: []string{"Kuneti", "Kuneti2"},
				}
				return cert
			},
		},
		{
			name: "Wrong Subject Org",
			cert: func() *x509.Certificate {
				cert := validKunetiCert.Certificate
				cert.Subject = pkix.Name{
					Organization: []string{"NotKuneti"},
				}
				return cert
			},
		},
		{
			name: "No Issuing Certificate URL",
			cert: func() *x509.Certificate {
				cert := validKunetiCert.Certificate
				cert.IssuingCertificateURL = []string{}
				return cert
			},
		},
		{
			name: "Wrong Issuing Certificate URL",
			cert: func() *x509.Certificate {
				cert := validKunetiCert.Certificate
				cert.IssuingCertificateURL = []string{"http://example.com/ca.crt"}
				return cert
			},
		},
		{
			name: "No Authority Key ID",
			cert: func() *x509.Certificate {
				cert := validKunetiCert.Certificate
				cert.AuthorityKeyId = nil
				return cert
			},
		},
		{
			name: "No EK Certificate OID",
			cert: func() *x509.Certificate {
				cert := validKunetiCert.Certificate
				cert.UnknownExtKeyUsage = []asn1.ObjectIdentifier{}
				return cert
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cert := tc.cert()
			ekc, err := ToEKCertificate(cert)
			if err != nil {
				t.Fatalf("failed to parse EK: %v", err)
			}
			if ekc.IsKuneti() {
				t.Fatalf("certificate is considered Kuneti:%+v", cert)
			}
		})
	}
}

func TestVersionFix(t *testing.T) {
	tests := []struct {
		tpmVersion string
		want       string
	}{
		{
			tpmVersion: "id:053E",
			want:       "id:0005003E",
		},
		{
			tpmVersion: "id:72",
			want:       "id:00720000",
		},
	}

	for _, tc := range tests {
		if got, _ := versionFix(tc.tpmVersion); got != tc.want {
			t.Errorf("versionFix(%q) = %q, want %q", tc.tpmVersion, got, tc.want)
		}
	}
}

func TestEKVerify(t *testing.T) {
	cert := ekCert(t)
	opts := x509.VerifyOptions{}
	_, err := cert.Verify(opts)
	if _, ok := err.(x509.UnknownAuthorityError); !ok {
		t.Errorf("Verify() failed unexpectedly; err=%s", err)
	}
}

func TestRSAOAEP(t *testing.T) {
	p, _ := pem.Decode(oaepPEM)
	if _, err := ParseEKCertificate(p.Bytes); err == nil {
		t.Error("ParseEKCertificate succeeded for an unsupported certificate, want error")
	}
}

func TestBruschetta(t *testing.T) {
	p, _ := pem.Decode(bruschettaPEM)
	cert, err := ParseEKCertificate(p.Bytes)
	if err != nil {
		t.Fatalf("ParseEKCertificate failed: %v", err)
	}
	if want, got := 0, len(cert.Certificate.UnhandledCriticalExtensions); got != want {
		t.Errorf("UnhandledCriticalExtensions: got %d, want %d: %s",
			got, want,
			cert.Certificate.UnhandledCriticalExtensions)
	}
	a, found := cert.ADID()
	if !found {
		t.Errorf("ADID not found")
	}
	if got, want := *a, adid; got != want {
		t.Errorf("ADID() = %q, want %q", got, want)
	}
}

// Private CA issued EK certificates for GCE instances appear to violate the
// "TCG EK Credential Profile" spec by not populating the subject alternative
// name extension.
func TestPrivateCA(t *testing.T) {
	p, _ := pem.Decode(privateCAPEM)
	cert, err := ParseEKCertificate(p.Bytes)
	if err != nil {
		t.Fatalf("ParseEKCertificate failed: %v", err)
	}
	if want, got := 0, len(cert.Certificate.UnhandledCriticalExtensions); got != want {
		t.Errorf("UnhandledCriticalExtensions: got %d, want %d: %s",
			got, want,
			cert.Certificate.UnhandledCriticalExtensions)
	}
	if got, want := cert.Version(), ""; got != want {
		t.Errorf("Version() = %q, want %q", got, want)
	}
}

func TestPrivateCA2(t *testing.T) {
	p, _ := pem.Decode(privateCAPEM2)
	cert, err := ParseEKCertificate(p.Bytes)
	if err != nil {
		t.Fatalf("ParseEKCertificate failed: %v", err)
	}
	if want, got := 0, len(cert.Certificate.UnhandledCriticalExtensions); got != want {
		t.Errorf("UnhandledCriticalExtensions: got %d, want %d: %s",
			got, want,
			cert.Certificate.UnhandledCriticalExtensions)
	}
	if got, want := cert.Version(), ""; got != want {
		t.Errorf("Version() = %q, want %q", got, want)
	}

	gceInstanceID := &GCEInstanceID{
		Zone:          "us-central1-a",
		ProjectNumber: big.NewInt(502841471840),
		ProjectID:     "cloudgtm-dev",
		InstanceID:    big.NewInt(2330613080891692518),
		InstanceName:  "cloudgtm-dev-ta-a0",
		SecurityProperties: GCESecurityProperties{
			SecurityVersion:        big.NewInt(0),
			IsProduction:           true,
			TpmDataAlwaysEncrypted: true,
		},
	}
	got, _ := cert.GCEInstanceID()
	if diff := diff(gceInstanceID, got); diff != "" {
		t.Errorf("GCEInstanceID() returned unexpected diff (-want +got):\n%s", diff)
	}
}

func TestPrivateCA3(t *testing.T) {
	p, _ := pem.Decode(privateCAPEM3)
	cert, err := ParseEKCertificate(p.Bytes)
	if err != nil {
		t.Fatalf("ParseEKCertificate failed: %v", err)
	}
	if want, got := 0, len(cert.Certificate.UnhandledCriticalExtensions); got != want {
		t.Errorf("UnhandledCriticalExtensions: got %d, want %d: %s",
			got, want,
			cert.Certificate.UnhandledCriticalExtensions)
	}
	if got, want := cert.Version(), ""; got != want {
		t.Errorf("Version() = %q, want %q", got, want)
	}

	gceInstanceID := &GCEInstanceID{
		Zone:          "us-central1-a",
		ProjectNumber: big.NewInt(1098100797290),
		ProjectID:     "cloudgtm-sbx",
		InstanceID:    big.NewInt(7410013178071730975),
		InstanceName:  "cloudgtm-sbx-ta-a0",
		SecurityProperties: GCESecurityProperties{
			SecurityVersion:             big.NewInt(0),
			IsProduction:                true,
			TpmDataAlwaysEncrypted:      true,
			SuspendResumeAlwaysDisabled: false,
			VmtdAlwaysDisabled:          false,
			AlwaysInYarn:                false,
		},
	}
	got, _ := cert.GCEInstanceID()
	if diff := diff(gceInstanceID, got); diff != "" {
		t.Errorf("GCEInstanceID() returned unexpected diff (-want +got):\n%s", diff)
	}
}
