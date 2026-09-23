package tpmsim

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/google/go-attestation/oid"
	"github.com/google/go-attestation/tcg"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var testGCEInstance = &GCEInstanceID{
	Zone:          "us-central1-a",
	ProjectNumber: big.NewInt(1234567890),
	ProjectID:     "tpmsim-test-project",
	InstanceID:    big.NewInt(9876543210),
	InstanceName:  "tpmsim-test-vm",
}

func TestDefaultSimulator(t *testing.T) {
	sim := NewT(t)
	defer sim.Close()

	if sim.TPM() == nil {
		t.Error("TPM() returned nil")
	}
	if sim.SimulatorTPM() == nil {
		t.Error("SimulatorTPM() returned nil")
	}

	certDER := sim.EKCert()
	if len(certDER) == 0 {
		t.Fatal("EKCert() returned empty byte slice")
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}

	if got, want := cert.PublicKeyAlgorithm, x509.RSA; got != want {
		t.Errorf("PublicKeyAlgorithm = %v, want %v", got, want)
	}

	if !slices.ContainsFunc(cert.UnknownExtKeyUsage, func(id asn1.ObjectIdentifier) bool { return id.Equal(oid.EKCertificate) }) {
		t.Errorf("cert.UnknownExtKeyUsage = %v, want to contain TCG EKCertificate OID (%v)", cert.UnknownExtKeyUsage, oid.EKCertificate)
	}
}

func TestWithoutEK(t *testing.T) {
	sim := NewT(t, WithoutEK())
	defer sim.Close()

	if cert := sim.EKCert(); cert != nil {
		t.Errorf("EKCert() = %v, want nil", cert)
	}
	if certs := sim.EKCerts(); len(certs) != 0 {
		t.Errorf("EKCerts() = %v, want empty map", certs)
	}
}

func TestKeyTypes(t *testing.T) {
	testCases := []struct {
		name      string
		opt       EKOption
		wantAlg   x509.PublicKeyAlgorithm
		wantBits  int
		wantCurve elliptic.Curve
	}{
		{
			name:     "RSA_2048",
			opt:      WithRSAKey(2048),
			wantAlg:  x509.RSA,
			wantBits: 2048,
		},
		{
			name:      "ECDSA_P256",
			opt:       WithECKey(elliptic.P256()),
			wantAlg:   x509.ECDSA,
			wantCurve: elliptic.P256(),
		},
		{
			name:      "ECDSA_P256_Helper",
			opt:       WithEC256Key(),
			wantAlg:   x509.ECDSA,
			wantCurve: elliptic.P256(),
		},
		{
			name:      "ECDSA_P384",
			opt:       WithECKey(elliptic.P384()),
			wantAlg:   x509.ECDSA,
			wantCurve: elliptic.P384(),
		},
		{
			name:      "ECDSA_P384_Helper",
			opt:       WithEC384Key(),
			wantAlg:   x509.ECDSA,
			wantCurve: elliptic.P384(),
		},
		{
			name:      "ECDSA_P521",
			opt:       WithECKey(elliptic.P521()),
			wantAlg:   x509.ECDSA,
			wantCurve: elliptic.P521(),
		},
		{
			name:      "ECDSA_P521_Helper",
			opt:       WithEC521Key(),
			wantAlg:   x509.ECDSA,
			wantCurve: elliptic.P521(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sim := NewT(t, WithEK(tc.opt))
			defer sim.Close()

			certDER := sim.EKCert()
			if len(certDER) == 0 {
				t.Fatal("EKCert() is empty")
			}

			cert, err := x509.ParseCertificate(certDER)
			if err != nil {
				t.Fatalf("ParseCertificate failed: %v", err)
			}

			if cert.PublicKeyAlgorithm != tc.wantAlg {
				t.Fatalf("PublicKeyAlgorithm = %v, want %v", cert.PublicKeyAlgorithm, tc.wantAlg)
			}

			switch tc.wantAlg {
			case x509.RSA:
				rsaPubKey, ok := cert.PublicKey.(*rsa.PublicKey)
				if !ok {
					t.Fatalf("PublicKey is not *rsa.PublicKey: %T", cert.PublicKey)
				}
				if got := rsaPubKey.N.BitLen(); got != tc.wantBits {
					t.Errorf("RSA BitLen = %d, want %d", got, tc.wantBits)
				}
			case x509.ECDSA:
				ecdsaPubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
				if !ok {
					t.Fatalf("PublicKey is not *ecdsa.PublicKey: %T", cert.PublicKey)
				}
				if got, want := ecdsaPubKey.Curve.Params().Name, tc.wantCurve.Params().Name; got != want {
					t.Errorf("ECDSA Curve = %s, want %s", got, want)
				}
			}
		})
	}
}

func TestMultiEKCertificates(t *testing.T) {
	sim := NewT(t,
		WithEK(
			WithRSAKey(2048),
			WithSubject(pkix.Name{CommonName: "RSA EK Cert"}),
		),
		WithEK(
			WithECKey(elliptic.P384()),
			WithSubject(pkix.Name{CommonName: "ECC P384 EK Cert"}),
		),
	)
	defer sim.Close()

	certs := sim.EKCerts()
	if got, want := len(certs), 2; got != want {
		t.Fatalf("len(EKCerts()) = %d, want %d", got, want)
	}

	rsaCertDER, err := sim.EKCertAt(tcg.EKCertRSA2048Index)
	if err != nil {
		t.Fatalf("EKCertAt(RSA) failed: %v", err)
	}
	rsaCert, err := x509.ParseCertificate(rsaCertDER)
	if err != nil {
		t.Fatalf("ParseCertificate RSA failed: %v", err)
	}
	if got, want := rsaCert.Subject.CommonName, "RSA EK Cert"; got != want {
		t.Errorf("RSA CommonName = %q, want %q", got, want)
	}

	eccCertDER, err := sim.EKCertAt(tcg.EKCertECCP256Index)
	if err != nil {
		t.Fatalf("EKCertAt(ECC) failed: %v", err)
	}
	eccCert, err := x509.ParseCertificate(eccCertDER)
	if err != nil {
		t.Fatalf("ParseCertificate ECC failed: %v", err)
	}
	if got, want := eccCert.Subject.CommonName, "ECC P384 EK Cert"; got != want {
		t.Errorf("ECC CommonName = %q, want %q", got, want)
	}
}

func TestGCEProfile(t *testing.T) {
	sim := NewT(t, GCEProfile(testGCEInstance)...)
	defer sim.Close()

	cert, err := x509.ParseCertificate(sim.EKCert())
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}

	foundGCEExt := false
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid.CloudComputeInstanceIdentifier) {
			foundGCEExt = true
			break
		}
	}
	if !foundGCEExt {
		t.Errorf("CloudComputeInstanceIdentifier extension not found in GCE EK cert")
	}
}

func TestCustomValidityAndSubject(t *testing.T) {
	notBefore := time.Date(2021, 5, 10, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2028, 5, 10, 0, 0, 0, 0, time.UTC)

	sim := NewT(t, WithEK(
		WithSubject(pkix.Name{Organization: []string{"Test Org"}}),
		WithValidity(notBefore, notAfter),
	))
	defer sim.Close()

	cert, err := x509.ParseCertificate(sim.EKCert())
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}

	if !cert.NotBefore.Equal(notBefore) {
		t.Errorf("NotBefore = %v, want %v", cert.NotBefore, notBefore)
	}
	if !cert.NotAfter.Equal(notAfter) {
		t.Errorf("NotAfter = %v, want %v", cert.NotAfter, notAfter)
	}
	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "Test Org" {
		t.Errorf("Organization = %v, want ['Test Org']", cert.Subject.Organization)
	}
}

func TestWithEKTemplate(t *testing.T) {
	extID := asn1.ObjectIdentifier{1, 2, 3, 99}

	t.Run("HonorsTemplateFields", func(t *testing.T) {
		notBefore := time.Date(2022, 3, 4, 0, 0, 0, 0, time.UTC)
		notAfter := time.Date(2030, 3, 4, 0, 0, 0, 0, time.UTC)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(424242),
			Subject:      pkix.Name{CommonName: "Templated EK"},
			NotBefore:    notBefore,
			NotAfter:     notAfter,
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtraExtensions: []pkix.Extension{
				{Id: extID, Value: []byte("hello")},
			},
		}

		sim := NewT(t, WithEK(WithRSAKey(2048), WithEKTemplate(tmpl)))
		defer sim.Close()

		cert, err := x509.ParseCertificate(sim.EKCert())
		if err != nil {
			t.Fatalf("ParseCertificate failed: %v", err)
		}
		if got, want := cert.SerialNumber.Int64(), int64(424242); got != want {
			t.Errorf("SerialNumber = %d, want %d", got, want)
		}
		if got, want := cert.Subject.CommonName, "Templated EK"; got != want {
			t.Errorf("CommonName = %q, want %q", got, want)
		}
		if !cert.NotBefore.Equal(notBefore) || !cert.NotAfter.Equal(notAfter) {
			t.Errorf("validity = [%v, %v], want [%v, %v]", cert.NotBefore, cert.NotAfter, notBefore, notAfter)
		}
		found := false
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(extID) {
				found = true
			}
		}
		if !found {
			t.Errorf("template ExtraExtensions %v not found in cert", extID)
		}
	})

	t.Run("BackfillsDefaultsForSparseTemplate", func(t *testing.T) {
		tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: "Sparse"}}

		sim := NewT(t, WithEK(WithRSAKey(2048), WithEKTemplate(tmpl)))
		defer sim.Close()

		cert, err := x509.ParseCertificate(sim.EKCert())
		if err != nil {
			t.Fatalf("ParseCertificate failed: %v", err)
		}
		if cert.SerialNumber == nil || cert.SerialNumber.Sign() == 0 {
			t.Errorf("SerialNumber not backfilled: %v", cert.SerialNumber)
		}
		if cert.KeyUsage == 0 {
			t.Error("KeyUsage not backfilled from defaults")
		}
		if !slices.ContainsFunc(cert.UnknownExtKeyUsage, func(id asn1.ObjectIdentifier) bool { return id.Equal(oid.EKCertificate) }) {
			t.Errorf("UnknownExtKeyUsage = %v, want to contain TCG EKCertificate OID (%v)", cert.UnknownExtKeyUsage, oid.EKCertificate)
		}
		if cert.NotBefore.IsZero() || cert.NotAfter.IsZero() {
			t.Errorf("validity not backfilled: [%v, %v]", cert.NotBefore, cert.NotAfter)
		}
	})

	t.Run("DiscreteOptionsOverrideTemplate", func(t *testing.T) {
		tmplNotAfter := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
		overrideNotBefore := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
		overrideNotAfter := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
		tmpl := &x509.Certificate{
			Subject:   pkix.Name{CommonName: "From Template"},
			NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:  tmplNotAfter,
		}

		sim := NewT(t, WithEK(
			WithRSAKey(2048),
			WithEKTemplate(tmpl),
			WithSubject(pkix.Name{CommonName: "From Option"}),
			WithValidity(overrideNotBefore, overrideNotAfter),
		))
		defer sim.Close()

		cert, err := x509.ParseCertificate(sim.EKCert())
		if err != nil {
			t.Fatalf("ParseCertificate failed: %v", err)
		}
		if got, want := cert.Subject.CommonName, "From Option"; got != want {
			t.Errorf("CommonName = %q, want %q (discrete option should win)", got, want)
		}
		if !cert.NotBefore.Equal(overrideNotBefore) || !cert.NotAfter.Equal(overrideNotAfter) {
			t.Errorf("validity = [%v, %v], want [%v, %v] (discrete option should win)", cert.NotBefore, cert.NotAfter, overrideNotBefore, overrideNotAfter)
		}
	})

	t.Run("DoesNotMutateCallerTemplate", func(t *testing.T) {
		tmpl := &x509.Certificate{
			Subject:         pkix.Name{CommonName: "Immutable"},
			ExtraExtensions: []pkix.Extension{{Id: extID, Value: []byte("orig")}},
		}
		wantExts := len(tmpl.ExtraExtensions)

		sim := NewT(t, WithEK(
			WithRSAKey(2048),
			WithEKTemplate(tmpl),
			WithExtension(pkix.Extension{Id: asn1.ObjectIdentifier{1, 2, 3, 100}, Value: []byte("added")}),
		))
		defer sim.Close()

		if got := len(tmpl.ExtraExtensions); got != wantExts {
			t.Errorf("caller template ExtraExtensions mutated: len = %d, want %d", got, wantExts)
		}
		if tmpl.SerialNumber != nil {
			t.Errorf("caller template SerialNumber mutated: %v", tmpl.SerialNumber)
		}
		if !tmpl.NotBefore.IsZero() {
			t.Errorf("caller template NotBefore mutated: %v", tmpl.NotBefore)
		}
	})

	t.Run("NilTemplateReturnsError", func(t *testing.T) {
		_, err := New(WithEK(WithEKTemplate(nil)))
		if err == nil {
			t.Error("WithEKTemplate(nil) should return an error")
		}
	})
}

func TestReusableSigners(t *testing.T) {
	rsaSigner := DefaultTestSigner()
	if rsaSigner.Signer == nil || rsaSigner.Cert == nil || rsaSigner.PublicKey() == nil {
		t.Fatal("DefaultTestSigner() contains nil fields")
	}

	ec256Signer := DefaultECTestSigner()
	if ec256Signer.Signer == nil || ec256Signer.Cert == nil || ec256Signer.PublicKey() == nil {
		t.Fatal("DefaultECTestSigner() contains nil fields")
	}

	sim := NewT(t, WithEK(
		WithTestSigner(rsaSigner),
	))
	defer sim.Close()

	cert, err := x509.ParseCertificate(sim.EKCert())
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}

	if got, want := cert.Issuer.CommonName, rsaSigner.Cert.Subject.CommonName; got != want {
		t.Errorf("Issuer CommonName = %q, want %q", got, want)
	}
}

func TestProfiles(t *testing.T) {
	t.Run("DefaultProfile", func(t *testing.T) {
		sim := NewT(t, DefaultProfile()...)
		defer sim.Close()

		if len(sim.EKCerts()) != 2 {
			t.Errorf("DefaultProfile should provision 2 EK certs (RSA2048 + ECCP256), got %d", len(sim.EKCerts()))
		}
	})

	t.Run("CustomProfileWithOverridingOptions", func(t *testing.T) {
		sim := NewT(t,
			WithEK(StandardEK(WithRSAKey(2048))...),
			WithEK(StandardEK(WithECKey(elliptic.P384()))...),
		)
		defer sim.Close()

		if len(sim.EKCerts()) != 2 {
			t.Errorf("Expected 2 EK certs from CustomProfile, got %d", len(sim.EKCerts()))
		}
	})
}

func TestAdditionalOptions(t *testing.T) {
	customHandle := tpmutil.Handle(0x1c0000f)
	ext1 := pkix.Extension{
		Id:    asn1.ObjectIdentifier{1, 2, 3, 4},
		Value: []byte("ext1"),
	}
	ext2 := pkix.Extension{
		Id:    asn1.ObjectIdentifier{1, 2, 3, 5},
		Value: []byte("ext2"),
	}

	defaultCA := DefaultTestSigner()

	sim := NewT(t,
		WithDefaultSigner(defaultCA.Signer, defaultCA.Cert),
		WithOptions(
			WithEK(
				WithSigner(defaultCA.Signer, defaultCA.Cert),
				WithNVRAMHandle(customHandle),
				WithExtension(ext1),
				WithExtraExtensions([]pkix.Extension{ext2}),
			),
		),
		WithEK(
			WithSignerFunc(func(tmpl *x509.Certificate, pub crypto.PublicKey) ([]byte, error) {
				return x509.CreateCertificate(nil, tmpl, defaultCA.Cert, pub, defaultCA.Signer)
			}),
		),
	)
	defer sim.Close()

	certDER, err := sim.EKCertAt(customHandle)
	if err != nil {
		t.Fatalf("EKCertAt(customHandle) failed: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}

	foundExt1, foundExt2 := false, false
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(ext1.Id) {
			foundExt1 = true
		}
		if ext.Id.Equal(ext2.Id) {
			foundExt2 = true
		}
	}
	if !foundExt1 || !foundExt2 {
		t.Errorf("Expected ext1 (%v) and ext2 (%v) in extensions, got foundExt1=%v, foundExt2=%v", ext1.Id, ext2.Id, foundExt1, foundExt2)
	}
}

// readEKCertFromNVRAMForTest reads a DER-encoded EK certificate directly from the
// simulated TPM's NVRAM at the given handle. This mirrors what the attest
// library does internally via tpm2.NVReadEx.
func readEKCertFromNVRAMForTest(t *testing.T, sim *Simulator, handle tpmutil.Handle) []byte {
	t.Helper()
	data, err := tpm2.NVReadEx(sim.TPM(), handle, handle, "", 0)
	if err != nil {
		t.Fatalf("tpm2.NVReadEx(0x%x) failed: %v", handle, err)
	}
	return data
}

func TestEKCertNVRAMReadback(t *testing.T) {
	t.Run("DefaultRSA", func(t *testing.T) {
		sim := NewT(t)
		defer sim.Close()

		// Verify the cert stored by the Simulator API matches what's in TPM NVRAM.
		wantDER := sim.EKCert()
		gotDER := readEKCertFromNVRAMForTest(t, sim, tcg.EKCertRSA2048Index)

		if !bytes.Equal(gotDER, wantDER) {
			t.Errorf("NVRAM cert at RSA handle (0x%x) does not match EKCert()\n  NVRAM len=%d, EKCert len=%d", tcg.EKCertRSA2048Index, len(gotDER), len(wantDER))
		}

		// Verify the cert is valid and has the expected key type.
		cert, err := x509.ParseCertificate(gotDER)
		if err != nil {
			t.Fatalf("ParseCertificate from NVRAM failed: %v", err)
		}
		if cert.PublicKeyAlgorithm != x509.RSA {
			t.Errorf("PublicKeyAlgorithm = %v, want RSA", cert.PublicKeyAlgorithm)
		}
	})

	t.Run("ECCP256", func(t *testing.T) {
		sim := NewT(t, WithEK(WithECKey(elliptic.P256())))
		defer sim.Close()

		wantDER := sim.EKCert()
		gotDER := readEKCertFromNVRAMForTest(t, sim, tcg.EKCertECCP256Index)

		if !bytes.Equal(gotDER, wantDER) {
			t.Errorf("NVRAM cert at ECC handle (0x%x) does not match EKCert()\n  NVRAM len=%d, EKCert len=%d", tcg.EKCertECCP256Index, len(gotDER), len(wantDER))
		}

		cert, err := x509.ParseCertificate(gotDER)
		if err != nil {
			t.Fatalf("ParseCertificate from NVRAM failed: %v", err)
		}
		if cert.PublicKeyAlgorithm != x509.ECDSA {
			t.Errorf("PublicKeyAlgorithm = %v, want ECDSA", cert.PublicKeyAlgorithm)
		}
		ecPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("PublicKey is not *ecdsa.PublicKey: %T", cert.PublicKey)
		}
		if ecPub.Curve.Params().Name != elliptic.P256().Params().Name {
			t.Errorf("Curve = %s, want P-256", ecPub.Curve.Params().Name)
		}
	})

	t.Run("MultiEK_RSAAndECC", func(t *testing.T) {
		sim := NewT(t,
			WithEK(WithRSAKey(2048)),
			WithEK(WithECKey(elliptic.P256())),
		)
		defer sim.Close()

		// RSA cert at standard RSA handle.
		rsaWant, err := sim.EKCertAt(tcg.EKCertRSA2048Index)
		if err != nil {
			t.Fatalf("EKCertAt(RSA) failed: %v", err)
		}
		rsaGot := readEKCertFromNVRAMForTest(t, sim, tcg.EKCertRSA2048Index)
		if !bytes.Equal(rsaGot, rsaWant) {
			t.Errorf("NVRAM RSA cert does not match EKCertAt(RSA)")
		}
		rsaCert, err := x509.ParseCertificate(rsaGot)
		if err != nil {
			t.Fatalf("ParseCertificate(RSA from NVRAM) failed: %v", err)
		}
		if rsaCert.PublicKeyAlgorithm != x509.RSA {
			t.Errorf("RSA cert PublicKeyAlgorithm = %v, want RSA", rsaCert.PublicKeyAlgorithm)
		}

		// ECC cert at standard ECC handle.
		eccWant, err := sim.EKCertAt(tcg.EKCertECCP256Index)
		if err != nil {
			t.Fatalf("EKCertAt(ECC) failed: %v", err)
		}
		eccGot := readEKCertFromNVRAMForTest(t, sim, tcg.EKCertECCP256Index)
		if !bytes.Equal(eccGot, eccWant) {
			t.Errorf("NVRAM ECC cert does not match EKCertAt(ECC)")
		}
		eccCert, err := x509.ParseCertificate(eccGot)
		if err != nil {
			t.Fatalf("ParseCertificate(ECC from NVRAM) failed: %v", err)
		}
		if eccCert.PublicKeyAlgorithm != x509.ECDSA {
			t.Errorf("ECC cert PublicKeyAlgorithm = %v, want ECDSA", eccCert.PublicKeyAlgorithm)
		}

		// EKCert() should return the RSA cert (standard RSA handle takes priority).
		if !bytes.Equal(sim.EKCert(), rsaWant) {
			t.Error("EKCert() should return the RSA cert when both RSA and ECC are provisioned")
		}
	})

	t.Run("CustomNVRAMHandle", func(t *testing.T) {
		customHandle := tpmutil.Handle(0x1c0000f)
		sim := NewT(t, WithEK(
			WithRSAKey(2048),
			WithNVRAMHandle(customHandle),
		))
		defer sim.Close()

		wantDER, err := sim.EKCertAt(customHandle)
		if err != nil {
			t.Fatalf("EKCertAt(custom) failed: %v", err)
		}
		gotDER := readEKCertFromNVRAMForTest(t, sim, customHandle)
		if !bytes.Equal(gotDER, wantDER) {
			t.Errorf("NVRAM cert at custom handle (0x%x) does not match EKCertAt()", customHandle)
		}
	})

	t.Run("GCEProfile", func(t *testing.T) {
		sim := NewT(t, GCEProfile(testGCEInstance)...)
		defer sim.Close()

		// GCEProfile provisions both RSA and ECC EKs.
		for _, tc := range []struct {
			name    string
			handle  tpmutil.Handle
			wantAlg x509.PublicKeyAlgorithm
		}{
			{"RSA", tcg.EKCertRSA2048Index, x509.RSA},
			{"ECC", tcg.EKCertECCP256Index, x509.ECDSA},
		} {
			t.Run(tc.name, func(t *testing.T) {
				wantDER, err := sim.EKCertAt(tc.handle)
				if err != nil {
					t.Fatalf("EKCertAt(0x%x) failed: %v", tc.handle, err)
				}
				gotDER := readEKCertFromNVRAMForTest(t, sim, tc.handle)
				if !bytes.Equal(gotDER, wantDER) {
					t.Errorf("NVRAM cert at handle 0x%x does not match EKCertAt()", tc.handle)
				}
				cert, err := x509.ParseCertificate(gotDER)
				if err != nil {
					t.Fatalf("ParseCertificate from NVRAM failed: %v", err)
				}
				if cert.PublicKeyAlgorithm != tc.wantAlg {
					t.Errorf("PublicKeyAlgorithm = %v, want %v", cert.PublicKeyAlgorithm, tc.wantAlg)
				}
				// Verify GCE extension is present.
				foundGCE := false
				for _, ext := range cert.Extensions {
					if ext.Id.Equal(oid.CloudComputeInstanceIdentifier) {
						foundGCE = true
						break
					}
				}
				if !foundGCE {
					t.Error("GCE CloudComputeInstanceIdentifier extension not found in NVRAM cert")
				}
			})
		}
	})

	t.Run("DefaultProfile", func(t *testing.T) {
		sim := NewT(t, DefaultProfile()...)
		defer sim.Close()

		if got := len(sim.EKCerts()); got != 2 {
			t.Fatalf("DefaultProfile provisioned %d EKs, want 2", got)
		}

		// Both should be readable from NVRAM.
		for handle, wantDER := range sim.EKCerts() {
			gotDER := readEKCertFromNVRAMForTest(t, sim, handle)
			if !bytes.Equal(gotDER, wantDER) {
				t.Errorf("NVRAM cert at handle 0x%x does not match EKCerts() entry", handle)
			}
		}
	})

	t.Run("WithEKTemplate", func(t *testing.T) {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(999),
			Subject:      pkix.Name{CommonName: "NVRAM Template EK"},
			NotBefore:    time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:     time.Date(2032, 1, 1, 0, 0, 0, 0, time.UTC),
		}

		sim := NewT(t, WithEK(WithRSAKey(2048), WithEKTemplate(tmpl)))
		defer sim.Close()

		gotDER := readEKCertFromNVRAMForTest(t, sim, tcg.EKCertRSA2048Index)
		cert, err := x509.ParseCertificate(gotDER)
		if err != nil {
			t.Fatalf("ParseCertificate from NVRAM failed: %v", err)
		}
		if got, want := cert.SerialNumber.Int64(), int64(999); got != want {
			t.Errorf("SerialNumber = %d, want %d", got, want)
		}
		if got, want := cert.Subject.CommonName, "NVRAM Template EK"; got != want {
			t.Errorf("CommonName = %q, want %q", got, want)
		}
	})
}

func TestEndorsementKeyHandles(t *testing.T) {
	t.Run("RSA_KeyInHandle_0x81010001", func(t *testing.T) {
		sim := NewT(t)
		defer sim.Close()

		// Fetch EK key using tpm_tools client, which targets handle 0x81010001.
		ek, err := client.EndorsementKeyRSA(sim.TPM())
		if err != nil {
			t.Fatalf("client.EndorsementKeyRSA() failed: %v", err)
		}
		defer ek.Close()

		// 1. Verify key parameters (RSA, 2048-bit).
		rsaPub, ok := ek.PublicKey().(*rsa.PublicKey)
		if !ok {
			t.Fatalf("ek.PublicKey() is not *rsa.PublicKey: %T", ek.PublicKey())
		}
		if got, want := rsaPub.N.BitLen(), 2048; got != want {
			t.Errorf("RSA Key BitLen = %d, want %d", got, want)
		}

		// 2. Verify associated certificate attached to Key matches EKCert().
		if ek.Cert() == nil {
			t.Fatal("ek.Cert() is nil, expected certificate to be loaded from NVRAM")
		}
		if !bytes.Equal(ek.Cert().Raw, sim.EKCert()) {
			t.Error("ek.Cert().Raw does not match sim.EKCert()")
		}

		// 3. Read persistent handle directly from TPM to verify handle 0x81010001 is populated.
		pub, _, _, err := tpm2.ReadPublic(sim.TPM(), tcg.EKKeyRSA2048Handle)
		if err != nil {
			t.Fatalf("tpm2.ReadPublic(..., %v) failed: %v", tcg.EKKeyRSA2048Handle, err)
		}
		if pub.Type != tpm2.AlgRSA {
			t.Errorf("ReadPublic Alg = %v, want AlgRSA", pub.Type)
		}
		if pub.RSAParameters == nil || pub.RSAParameters.KeyBits != 2048 {
			t.Errorf("ReadPublic RSAParameters = %v, want KeyBits=2048", pub.RSAParameters)
		}
	})

	t.Run("ECC_KeyInHandle_0x81010002", func(t *testing.T) {
		sim := NewT(t, WithEK(WithECKey(elliptic.P256())))
		defer sim.Close()

		// Fetch EK key using tpm_tools client, which targets handle 0x81010002.
		ek, err := client.EndorsementKeyECC(sim.TPM())
		if err != nil {
			t.Fatalf("client.EndorsementKeyECC() failed: %v", err)
		}
		defer ek.Close()

		// 1. Verify key parameters (ECDSA P-256).
		ecPub, ok := ek.PublicKey().(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("ek.PublicKey() is not *ecdsa.PublicKey: %T", ek.PublicKey())
		}
		if got, want := ecPub.Curve.Params().Name, elliptic.P256().Params().Name; got != want {
			t.Errorf("ECDSA Curve = %s, want %s", got, want)
		}

		// 2. Verify associated certificate attached to Key matches EKCert().
		if ek.Cert() == nil {
			t.Fatal("ek.Cert() is nil, expected certificate to be loaded from NVRAM")
		}
		if !bytes.Equal(ek.Cert().Raw, sim.EKCert()) {
			t.Error("ek.Cert().Raw does not match sim.EKCert()")
		}

		// 3. Read persistent handle directly from TPM to verify handle 0x81010002 is populated.
		pub, _, _, err := tpm2.ReadPublic(sim.TPM(), tcg.EKKeyECCP256Handle)
		if err != nil {
			t.Fatalf("tpm2.ReadPublic(..., %v) failed: %v", tcg.EKKeyECCP256Handle, err)
		}
		if pub.Type != tpm2.AlgECC {
			t.Errorf("ReadPublic Alg = %v, want AlgECC", pub.Type)
		}
		if pub.ECCParameters == nil || pub.ECCParameters.CurveID != tpm2.CurveNISTP256 {
			t.Errorf("ReadPublic ECCParameters = %v, want CurveNISTP256", pub.ECCParameters)
		}
	})

	t.Run("DefaultProfile_BothHandlesPresent", func(t *testing.T) {
		sim := NewT(t, DefaultProfile()...)
		defer sim.Close()

		// 1. RSA EK at handle 0x81010001
		rsaEK, err := client.EndorsementKeyRSA(sim.TPM())
		if err != nil {
			t.Fatalf("client.EndorsementKeyRSA() failed: %v", err)
		}
		defer rsaEK.Close()

		rsaPub, ok := rsaEK.PublicKey().(*rsa.PublicKey)
		if !ok || rsaPub.N.BitLen() != 2048 {
			t.Errorf("RSA Key is invalid or not 2048 bits: %T %v", rsaEK.PublicKey(), rsaPub)
		}
		rsaCertDER, err := sim.EKCertAt(tcg.EKCertRSA2048Index)
		if err != nil {
			t.Fatalf("EKCertAt(RSA) failed: %v", err)
		}
		if rsaEK.Cert() == nil || !bytes.Equal(rsaEK.Cert().Raw, rsaCertDER) {
			t.Error("rsaEK.Cert() does not match NVRAM cert at EKRSACertHandle")
		}

		// 2. ECC EK at handle 0x81010002
		eccEK, err := client.EndorsementKeyECC(sim.TPM())
		if err != nil {
			t.Fatalf("client.EndorsementKeyECC() failed: %v", err)
		}
		defer eccEK.Close()

		ecPub, ok := eccEK.PublicKey().(*ecdsa.PublicKey)
		if !ok || ecPub.Curve.Params().Name != elliptic.P256().Params().Name {
			t.Errorf("ECC Key is invalid or not P-256: %T %v", eccEK.PublicKey(), ecPub)
		}
		eccCertDER, err := sim.EKCertAt(tcg.EKCertECCP256Index)
		if err != nil {
			t.Fatalf("EKCertAt(ECC) failed: %v", err)
		}
		if eccEK.Cert() == nil || !bytes.Equal(eccEK.Cert().Raw, eccCertDER) {
			t.Error("eccEK.Cert() does not match NVRAM cert at EKECCCertHandle")
		}
	})

	t.Run("GCEProfile_BothHandlesPresent", func(t *testing.T) {
		sim := NewT(t, GCEProfile(testGCEInstance)...)
		defer sim.Close()

		// Verify RSA EK (0x81010001)
		rsaEK, err := client.EndorsementKeyRSA(sim.TPM())
		if err != nil {
			t.Fatalf("client.EndorsementKeyRSA() failed: %v", err)
		}
		defer rsaEK.Close()
		if _, ok := rsaEK.PublicKey().(*rsa.PublicKey); !ok {
			t.Errorf("RSA Key is not *rsa.PublicKey: %T", rsaEK.PublicKey())
		}

		// Verify ECC EK (0x81010002)
		eccEK, err := client.EndorsementKeyECC(sim.TPM())
		if err != nil {
			t.Fatalf("client.EndorsementKeyECC() failed: %v", err)
		}
		defer eccEK.Close()
		if _, ok := eccEK.PublicKey().(*ecdsa.PublicKey); !ok {
			t.Errorf("ECC Key is not *ecdsa.PublicKey: %T", eccEK.PublicKey())
		}
	})
}

func TestMultiEKCustomHandles(t *testing.T) {
	// Provision a simulated TPM with 3 EKs and custom key/cert handles.
	// NOTE: The P384 EK is purposely provisioned with non-standard key/cert handles for testing.
	// #0: RSA 2048, Key handle: 0x81010001, Cert handle: 0x01C00002
	// #1: ECDSA -P256: Key handle 0x81010002, Cert handle: 0x01C0000A
	// #2: ECDSA -P384: Key handle 0x81010004, Cert handle: 0x01C00012
	sim := NewT(t,
		WithEK(
			WithRSAKey(2048),
			WithKeyHandle(tcg.EKKeyRSA2048Handle),
			WithCertHandle(tcg.EKCertRSA2048Index),
		),
		WithEK(
			WithECKey(elliptic.P256()),
			WithKeyHandle(tcg.EKKeyECCP256Handle),
			WithCertHandle(tcg.EKCertECCP256Index),
		),
		WithEK(
			WithECKey(elliptic.P384()),
			WithKeyHandle(tcg.EKKeyAltECCP256Handle),
			WithCertHandle(tcg.EKCertAltRSA2048Index),
		),
	)
	defer sim.Close()

	// 1. Verify EKCerts() returns 3 certificates mapped by NVRAM handle.
	certs := sim.EKCerts()
	if got, want := len(certs), 3; got != want {
		t.Fatalf("len(sim.EKCerts()) = %d, want %d", got, want)
	}

	// 2. Verify each expected cert handle exists and can be read from NVRAM.
	expectedCertHandles := []tpmutil.Handle{tcg.EKCertRSA2048Index, tcg.EKCertECCP256Index, tcg.EKCertAltRSA2048Index}
	for _, certHnd := range expectedCertHandles {
		certDER, err := sim.EKCertAt(certHnd)
		if err != nil {
			t.Fatalf("sim.EKCertAt(0x%x) failed: %v", certHnd, err)
		}
		if len(certDER) == 0 {
			t.Errorf("sim.EKCertAt(0x%x) returned empty cert", certHnd)
		}
	}

	// 3. Verify public keys read from TPM at expected key handles.
	// #0 RSA 2048 at EKKeyRSA2048Handle
	pub0, _, _, err := tpm2.ReadPublic(sim.TPM(), tcg.EKKeyRSA2048Handle)
	if err != nil {
		t.Fatalf("tpm2.ReadPublic(..., %v) failed: %v", tcg.EKKeyRSA2048Handle, err)
	}
	if pub0.Type != tpm2.AlgRSA || pub0.RSAParameters == nil || pub0.RSAParameters.KeyBits != 2048 {
		t.Errorf("Handle %v key parameters mismatch: %v", tcg.EKKeyRSA2048Handle, pub0)
	}

	// #1 ECDSA P-256 at EKKeyECCP256Handle
	pub1, _, _, err := tpm2.ReadPublic(sim.TPM(), tcg.EKKeyECCP256Handle)
	if err != nil {
		t.Fatalf("tpm2.ReadPublic(..., %v) failed: %v", tcg.EKKeyECCP256Handle, err)
	}
	if pub1.Type != tpm2.AlgECC || pub1.ECCParameters == nil || pub1.ECCParameters.CurveID != tpm2.CurveNISTP256 {
		t.Errorf("Handle %v key parameters mismatch: %v", tcg.EKKeyECCP256Handle, pub1)
	}

	// #2 ECDSA P-384 at EKKeyAltECCP256Handle
	pub2, _, _, err := tpm2.ReadPublic(sim.TPM(), tcg.EKKeyAltECCP256Handle)
	if err != nil {
		t.Fatalf("tpm2.ReadPublic(..., %v) failed: %v", tcg.EKKeyAltECCP256Handle, err)
	}
	if pub2.Type != tpm2.AlgECC || pub2.ECCParameters == nil || pub2.ECCParameters.CurveID != tpm2.CurveNISTP384 {
		t.Errorf("Handle %v key parameters mismatch: %v", tcg.EKKeyAltECCP256Handle, pub2)
	}
}

func TestWithoutPersistentKey(t *testing.T) {
	t.Run("RSA_CertInNVRAM_NoKeyHandle", func(t *testing.T) {
		sim := NewT(t,
			WithEK(
				WithRSAKey(2048),
				WithoutPersistentKey(),
			),
		)
		defer sim.Close()

		// The EK cert should still be readable from NVRAM.
		certDER := sim.EKCert()
		if len(certDER) == 0 {
			t.Fatal("EKCert() is empty; expected cert in NVRAM even with WithoutPersistentKey")
		}
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatalf("ParseCertificate failed: %v", err)
		}
		if cert.PublicKeyAlgorithm != x509.RSA {
			t.Errorf("EKCert() public key algorithm = %v, want %v", cert.PublicKeyAlgorithm, x509.RSA)
		}

		// The persistent key handle should NOT exist on the TPM.
		if _, _, _, err := tpm2.ReadPublic(sim.TPM(), tcg.EKKeyRSA2048Handle); err == nil {
			t.Errorf("tpm2.ReadPublic(..., %v) = nil, want error", tcg.EKKeyRSA2048Handle)
		}
	})

	t.Run("ECC_CertInNVRAM_NoKeyHandle", func(t *testing.T) {
		sim := NewT(t,
			WithEK(
				WithECKey(elliptic.P256()),
				WithoutPersistentKey(),
			),
		)
		defer sim.Close()

		certDER := sim.EKCert()
		if len(certDER) == 0 {
			t.Fatal("EKCert() is empty; expected cert in NVRAM even with WithoutPersistentKey")
		}
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatalf("ParseCertificate failed: %v", err)
		}
		if cert.PublicKeyAlgorithm != x509.ECDSA {
			t.Errorf("EKCert() public key algorithm = %v, want %v", cert.PublicKeyAlgorithm, x509.ECDSA)
		}

		// The persistent key handle should NOT exist on the TPM.
		if _, _, _, err := tpm2.ReadPublic(sim.TPM(), tcg.EKKeyECCP256Handle); err == nil {
			t.Errorf("tpm2.ReadPublic(..., %v) = nil, want error", tcg.EKKeyECCP256Handle)
		}
	})

	t.Run("Mixed_OnePersistedOneNot", func(t *testing.T) {
		sim := NewT(t,
			WithEK(WithRSAKey(2048)),                                   // persisted at 0x81010001
			WithEK(WithECKey(elliptic.P256()), WithoutPersistentKey()), // cert only, no key handle
		)
		defer sim.Close()

		// Both certs should be in NVRAM.
		certs := sim.EKCerts()
		if got, want := len(certs), 2; got != want {
			t.Fatalf("len(EKCerts()) = %d, want %d", got, want)
		}

		// RSA key handle should exist.
		if _, _, _, err := tpm2.ReadPublic(sim.TPM(), tcg.EKKeyRSA2048Handle); err != nil {
			t.Errorf("tpm2.ReadPublic(..., %v) failed: %v", tcg.EKKeyRSA2048Handle, err)
		}

		// ECC key handle should NOT exist.
		if _, _, _, err := tpm2.ReadPublic(sim.TPM(), tcg.EKKeyECCP256Handle); err == nil {
			t.Errorf("tpm2.ReadPublic(..., %v) = nil, want error", tcg.EKKeyECCP256Handle)
		}
	})
}
