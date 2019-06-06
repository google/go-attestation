package verifier

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/certificate-transparency-go/x509"

	pb "github.com/google/go-attestation/verifier/proto"
)

var (
	// brokenCerts are a blacklist of certificate filenames which fail to parse
	// due to being malformed. These certs are not processed and hence cannot
	// form part of a trusted chain.
	brokenCerts = map[string]bool{
		// A number of ST Microelectronics certificates have malformed
		// serial number fields.
		"STM_TPM_ECC_Intermediate_CA_01.crt": true,
		"STM_TPM_EK_Intermediate_CA_01.crt":  true,
		"STM_TPM_EK_Intermediate_CA_02.crt":  true,
		"STM_TPM_EK_Intermediate_CA_03.crt":  true,
		"STM_TPM_EK_Intermediate_CA_04.crt":  true,
		"STM_TPM_EK_Intermediate_CA_05.crt":  true,
	}
)

// EKVerifier verifies x509 EK certificates based on a pool of allowed
// parent certificates.
type EKVerifier struct {
	roots, intermediates *x509.CertPool
}

// VerifyEKCert verifies the properties and provenance of a given EK certificate.
func (v *EKVerifier) VerifyEKCert(certBytes []byte) (*pb.EkcertVerificationResults, error) {
	c, err := x509.ParseCertificate(certBytes)
	c.UnhandledCriticalExtensions = nil
	if err != nil && x509.IsFatal(err) {
		return nil, err
	}

	chains, verificationErr := c.Verify(x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: v.intermediates,

		// Disable checking extensions & key usages, as their application
		// appears to be inconsistent, and we only use the certificate
		// chains as a means to determine provenance.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})

	out := &pb.EkcertVerificationResults{
		Succeeded:     verificationErr == nil,
		ChainVerified: verificationErr == nil,
	}
	if verificationErr != nil {
		out.VerificationError = verificationErr.Error()
	} else {
		for _, cert := range chains[0] {
			out.Chain = append(out.Chain, &pb.EkcertVerificationResults_CertSummary{
				IssuerCn:  cert.Issuer.CommonName,
				IssuerOrg: strings.Join(cert.Issuer.Organization, " "),
				Serial:    cert.SerialNumber.String(),
			})
		}
	}

	return out, nil
}

// NewEKVerifier returns an EKVerifier initialized using the certificates in the specified
// directory. Directories are resolved recursively.
// The specified directory should be structured in the forms:
// <XXXX>/RootCA/<cert>.{der,cer,crt)
// <XXXX>/IntermediateCA/<cert>.{der,cer,crt)
func NewEKVerifier(certsPath string) (*EKVerifier, error) {
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	root, err := ioutil.ReadDir(certsPath)
	if err != nil {
		return nil, err
	}
	for _, f := range root {
		if !f.IsDir() {
			continue
		}
		if err := readCertificates(filepath.Join(certsPath, f.Name()), roots, intermediates); err != nil {
			return nil, err
		}
	}

	return &EKVerifier{
		roots:         roots,
		intermediates: intermediates,
	}, nil
}

func readCertificates(dir string, roots, intermediates *x509.CertPool) error {
	rootFiles, err := ioutil.ReadDir(filepath.Join(dir, "RootCA"))
	if err != nil {
		return err
	}
	if err := parseCertsToPool(filepath.Join(dir, "RootCA"), rootFiles, roots); err != nil {
		return err
	}
	intermediateFiles, err := ioutil.ReadDir(filepath.Join(dir, "IntermediateCA"))
	if err != nil {
		if os.IsNotExist(err) {
			// Not all manufacturers use intermediates certificates.
			return nil
		}
		return err
	}
	return parseCertsToPool(filepath.Join(dir, "IntermediateCA"), intermediateFiles, intermediates)
}

func parseCertsToPool(path string, files []os.FileInfo, pool *x509.CertPool) error {
	for _, info := range files {
		if info.IsDir() {
			continue
		}

		path := filepath.Join(path, info.Name())
		switch filepath.Ext(info.Name()) {
		case ".der":
			d, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}
			c, err := x509.ParseCertificate(d)
			if err != nil && x509.IsFatal(err) {
				if isBrokenCert(info.Name()) {
					continue
				}
				return fmt.Errorf("%s parse failed: %v", info.Name(), err)
			}
			pool.AddCert(c)

		case ".crt", ".cer":
			// Either DER or PEM.
			d, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}
			c, err := x509.ParseCertificate(d)
			if err != nil && x509.IsFatal(err) && !pool.AppendCertsFromPEM(d) {
				if isBrokenCert(info.Name()) {
					continue
				}
				return fmt.Errorf("%s parse failed: %v", info.Name(), err)
			}
			if err == nil {
				pool.AddCert(c)
			}
		}
	}
	return nil
}

func isBrokenCert(fname string) bool {
	return brokenCerts[fname]
}
