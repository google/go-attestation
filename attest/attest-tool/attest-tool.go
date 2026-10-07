// Binary attest-tool performs attestation operations on the local system.
package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-attestation/attest/attest-tool/internal"
	"go.uber.org/multierr"
)

var (
	keyPath     = flag.String("key", "ak.json", "Path to the key file")
	nonceHex    = flag.String("nonce", "", "Hex string to use as nonce when quoting")
	randomNonce = flag.Bool("random-nonce", false, "Generate a random nonce instead of using one provided")
	useSHA256   = flag.Bool("sha256", false, "Use SHA256 for quote operations")
)

func main() {
	flag.Parse()

	if *randomNonce {
		n := make([]byte, 8)
		rand.Read(n)
		*nonceHex = hex.EncodeToString(n)
	}

	tpm, err := attest.OpenTPM(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening the TPM: %v\n", err)
		os.Exit(1)
	}

	err = runCommand(tpm)
	tpm.Close()

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func selftestCredentialActivation(tpm *attest.TPM, ak *attest.AK) error {
	eks, err := tpm.EKs()
	if err != nil {
		return fmt.Errorf("EKs() failed: %v", err)
	}
	if len(eks) == 0 {
		return errors.New("no EK present")
	}
	ek := eks[0].Public

	// Test credential activation.
	ap := attest.ActivationParameters{
		EK: ek,
		AK: ak.AttestationParameters(),
	}
	secret, ec, err := ap.Generate()
	if err != nil {
		return fmt.Errorf("failed to generate activation challenge: %v", err)
	}
	decryptedSecret, err := ak.ActivateCredential(tpm, *ec)
	if err != nil {
		return fmt.Errorf("failed to generate activate credential: %v", err)
	}
	if !bytes.Equal(secret, decryptedSecret) {
		return errors.New("credential activation produced incorrect secret")
	}
	return nil
}

func selftestCredentialActivationWithEK(tpm *attest.TPM, ak *attest.AK) error {
	eks, err := tpm.EKCertificates()
	if err != nil {
		return fmt.Errorf("EKs() failed: %v", err)
	}
	if len(eks) == 0 {
		return errors.New("no valid EK available")
	}
	var allErrors error
	for i, ek := range eks {
		if ek.Public == nil {
			continue
		}
		cert := ek.Certificate
		if cert == nil {
			// No EK certificate available.
			continue
		}

		// Test credential activation.
		ap := attest.ActivationParameters{
			EK: ek.Public,
			AK: ak.AttestationParameters(),
		}
		secret, ec, err := ap.Generate()
		if err != nil {
			allErrors = multierr.Append(allErrors, fmt.Errorf("EK #%d: failed to generate activation challenge: %w", i, err))
			continue
		}
		decryptedSecret, err := ak.ActivateCredentialWithEK(tpm, *ec, ek)
		if err != nil {
			allErrors = multierr.Append(allErrors, fmt.Errorf("EK #%d: failed to activate credential: %w", i, err))
			continue
		}
		if !bytes.Equal(secret, decryptedSecret) {
			allErrors = multierr.Append(allErrors, fmt.Errorf("EK #%d: credential activation produced incorrect secret", i))
			continue
		}
	}

	if allErrors != nil {
		return allErrors
	}
	return nil
}

func selftestCredentialActivationWithEkAttestation(tpm *attest.TPM, ak *attest.AK) error {
	eks, err := tpm.EKCertificates()
	if err != nil {
		return fmt.Errorf("EKs() failed: %v", err)
	}
	if len(eks) == 0 {
		return errors.New("no valid EK available")
	}
	var allErrors error
	for i, ek := range eks {
		if ek.Public == nil {
			continue
		}
		cert := ek.Certificate
		if cert == nil {
			// No EK certificate available.
			continue
		}

		challenge, hmacKey, err := attest.GenerateEkChallenge(ek.Public)
		if err != nil {
			allErrors = multierr.Append(allErrors, fmt.Errorf("EK #%d: failed to generate EK challenge: %w", i, err))
			continue
		}
		certParams, err := ak.CertifyWithDecryptionEk(tpm, &ek, *challenge)
		if err != nil {
			allErrors = multierr.Append(allErrors, fmt.Errorf("EK #%d: failed to certify with decryption EK: %w", i, err))
			continue
		}
		if err := attest.VerifySolvedDecryptionEkChallenge(ak.AttestationParameters().Public, certParams, *hmacKey); err != nil {
			allErrors = multierr.Append(allErrors, fmt.Errorf("EK #%d: failed to verify solved EK decryption challenge: %w", i, err))
			continue
		}
	}

	return allErrors
}

func selftestAttest(tpm *attest.TPM, ak *attest.AK) error {
	// This nonce is used in generating the quote. As this is a selftest,
	// it's set to an arbitrary value.
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8}

	pub, err := attest.ParseAKPublic(ak.AttestationParameters().Public)
	if err != nil {
		return fmt.Errorf("failed to parse ak public: %v", err)
	}

	if _, err := tpm.MeasurementLog(); err != nil {
		return fmt.Errorf("no event log available: %v", err)
	}
	attestation, err := tpm.AttestPlatform(ak, nonce, nil)
	if err != nil {
		return fmt.Errorf("failed to attest: %v", err)
	}

	for i, quote := range attestation.Quotes {
		if err := pub.Verify(quote, attestation.PCRs, nonce); err != nil {
			return fmt.Errorf("failed to verify quote[%d]: %v", i, err)
		}
	}

	el, err := attest.ParseEventLog(attestation.EventLog)
	if err != nil {
		return fmt.Errorf("failed to parse event log: %v", err)
	}

	if _, err := el.Verify(attestation.PCRs); err != nil {
		return fmt.Errorf("event log failed to verify: %v", err)
	}
	return nil
}

func selftest(tpm *attest.TPM) error {
	ak, err := tpm.NewAK(nil)
	if err != nil {
		return fmt.Errorf("NewAK() failed: %v", err)
	}
	defer ak.Close(tpm)

	var allErrors error
	if err := selftestCredentialActivation(tpm, ak); err != nil {
		allErrors = multierr.Append(allErrors, fmt.Errorf("credential activation failed: %v", err))
	}
	if err := selftestCredentialActivationWithEK(tpm, ak); err != nil {
		allErrors = multierr.Append(allErrors, fmt.Errorf("selftest of credential activation failed: %v", err))
	}
	if err := selftestCredentialActivationWithEkAttestation(tpm, ak); err != nil {
		allErrors = multierr.Append(allErrors, fmt.Errorf("selftest of credential activation with EK attestation failed: %v", err))
	}

	if err := selftestAttest(tpm, ak); err != nil {
		allErrors = multierr.Append(allErrors, fmt.Errorf("state attestation failed: %v", err))
	}
	return allErrors
}

func signRSA(tpm *attest.TPM, ak *attest.AK) error {
	k, err := tpm.NewKey(ak, &attest.KeyConfig{
		Algorithm: attest.RSA,
		Size:      2048,
	})
	if err != nil {
		return fmt.Errorf("NewKey() failed: %v", err)
	}
	defer k.Close()
	fmt.Println("RSA key created successfully")

	rsaPub, ok := k.Public().(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not RSA: %T", k.Public())
	}

	priv, err := k.Private(k.Public())
	if err != nil {
		return fmt.Errorf("failed to get private key: %w", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return fmt.Errorf("private key does not implement crypto.Signer")
	}

	testPattern := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
		0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}

	// Sign a simple pattern with the RSA signing key using PSS.
	// We use PSSSaltLengthAuto to allow the library to choose (usually matches digest length).
	sig, err := signer.Sign(nil, testPattern, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		return fmt.Errorf("failed to sign with RSA signing key: %w", err)
	}

	// Try to verify using every possible salt length.
	err = rsa.VerifyPSS(rsaPub, crypto.SHA256, testPattern, sig, &rsa.PSSOptions{
		SaltLength: 32,
	})
	if err != nil {
		return fmt.Errorf("failed to verify with RSA signing key: %w", err)
	}
	return nil
}

func signECDSA(tpm *attest.TPM, ak *attest.AK) error {
	k, err := tpm.NewKey(ak, &attest.KeyConfig{
		Algorithm: attest.ECDSA,
		Size:      256,
	})
	if err != nil {
		return fmt.Errorf("NewKey() failed: %v", err)
	}
	defer k.Close()

	ecdsaPub, ok := k.Public().(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not ECDSA: %T", k.Public())
	}

	priv, err := k.Private(k.Public())
	if err != nil {
		return fmt.Errorf("failed to get private key: %w", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return fmt.Errorf("private key does not implement crypto.Signer")
	}

	testPattern := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
		0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}

	sig, err := signer.Sign(nil, testPattern, crypto.SHA256)
	if err != nil {
		return fmt.Errorf("failed to sign with ECDSA signing key: %w", err)
	}

	if !ecdsa.VerifyASN1(ecdsaPub, testPattern, sig) {
		return fmt.Errorf("failed to verify with ECDSA signing key")
	}
	fmt.Println("ECDSA key verified successfully")
	return nil
}

func sign(tpm *attest.TPM) error {
	ak, err := tpm.NewAK(nil)
	if err != nil {
		return fmt.Errorf("NewAK() failed: %v", err)
	}
	defer ak.Close(tpm)

	if err := signRSA(tpm, ak); err != nil {
		return err
	}
	return signECDSA(tpm, ak)
}

func runCommand(tpm *attest.TPM) error {
	switch flag.Arg(0) {
	case "info":
		info, err := tpm.Info()
		if err != nil {
			return err
		}
		fmt.Printf("Interface: %d\n", info.Interface)
		fmt.Printf("VendorInfo: %x\n", info.VendorInfo)
		fmt.Printf("Manufacturer: %v\n", info.Manufacturer)

	case "make-ak", "make-aik":
		k, err := tpm.NewAK(nil)
		if err != nil {
			return fmt.Errorf("failed to mint an AK: %v", err)
		}
		defer k.Close(tpm)
		b, err := k.Marshal()
		if err != nil {
			return err
		}
		return os.WriteFile(*keyPath, b, 0644)

	case "quote":
		b, err := os.ReadFile(*keyPath)
		if err != nil {
			return err
		}
		k, err := tpm.LoadAK(b)
		if err != nil {
			return fmt.Errorf("failed to load AK: %v", err)
		}
		defer k.Close(tpm)

		nonce, err := hex.DecodeString(*nonceHex)
		if err != nil {
			return err
		}
		alg := attest.HashSHA1
		if *useSHA256 {
			alg = attest.HashSHA256
		}

		q, err := k.Quote(tpm, nonce, alg)
		if err != nil {
			return fmt.Errorf("failed to generate quote: %v", err)
		}
		fmt.Printf("Quote: %x\n", q.Quote)
		fmt.Printf("Signature: %x\n", q.Signature)

	case "list-eks":
		eks, err := tpm.EKs()
		if err != nil {
			return fmt.Errorf("failed to read EKs: %v", err)
		}
		for _, ek := range eks {
			data, err := encodeEK(ek)
			if err != nil {
				return fmt.Errorf("encoding ek: %v", err)
			}
			fmt.Printf("%s\n", data)
		}

	case "list-pcrs":
		alg := attest.HashSHA1
		if *useSHA256 {
			alg = attest.HashSHA256
		}
		pcrs, err := tpm.PCRs(alg)
		if err != nil {
			return fmt.Errorf("failed to read PCRs: %v", err)
		}
		for _, pcr := range pcrs {
			fmt.Printf("PCR[%d]: %x\n", pcr.Index, pcr.Digest)
		}

	case "measurement-log":
		b, err := tpm.MeasurementLog()
		if err != nil {
			return fmt.Errorf("failed to read the measurement log: %v", err)
		}
		fmt.Printf("%x\n", b)

	case "dump":
		dumpData, err := runDump(tpm)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(dumpData)

	case "self-test":
		err := selftest(tpm)
		if err != nil {
			fmt.Println("FAIL")
			return err
		}
		fmt.Println("PASS")

	case "sign":
		err := sign(tpm)
		if err != nil {
			fmt.Println("FAIL")
			return err
		}
		fmt.Println("PASS")
	default:
		return fmt.Errorf("no such command %q", flag.Arg(0))
	}
	return nil
}

func encodeEK(ek attest.EK) ([]byte, error) {
	if ek.Certificate != nil {
		return pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: ek.Certificate.Raw,
		}), nil
	}
	switch pub := ek.Public.(type) {
	case *ecdsa.PublicKey:
		data, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil, fmt.Errorf("marshaling ec public key: %v", err)
		}
		return pem.EncodeToMemory(&pem.Block{
			Type:  "EC PUBLIC KEY",
			Bytes: data,
		}), nil
	case *rsa.PublicKey:
		return pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(pub),
		}), nil
	default:
		return nil, fmt.Errorf("unsupported public key type %T", pub)
	}
}

func runDump(tpm *attest.TPM) (*internal.Dump, error) {
	var (
		out internal.Dump
		err error
	)

	if out.Static.EKPem, err = rsaEKPEM(tpm); err != nil {
		return nil, err
	}

	k, err := tpm.NewAK(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to mint an AK: %v", err)
	}
	defer k.Close(tpm)
	out.AK = k.AttestationParameters()

	// Get a quote.
	if out.Quote.Nonce, err = hex.DecodeString(*nonceHex); err != nil {
		return nil, fmt.Errorf("failed decoding nonce hex: %v", err)
	}
	out.Quote.Alg = attest.HashSHA1
	if *useSHA256 {
		out.Quote.Alg = attest.HashSHA256
	}
	q, err := k.Quote(tpm, out.Quote.Nonce, out.Quote.Alg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate quote: %v", err)
	}
	out.Quote.Quote = q.Quote
	out.Quote.Signature = q.Signature

	// Get log information.
	if out.Log.Raw, err = tpm.MeasurementLog(); err != nil {
		return nil, fmt.Errorf("failed to read measurement log: %v", err)
	}
	// Get PCR values.
	if out.Log.PCRs, err = tpm.PCRs(out.Quote.Alg); err != nil {
		return nil, fmt.Errorf("failed to read PCRs: %v", err)
	}

	return &out, nil
}

func rsaEKPEM(tpm *attest.TPM) ([]byte, error) {
	eks, err := tpm.EKs()
	if err != nil {
		return nil, fmt.Errorf("failed to read EKs: %v", err)
	}

	var (
		pk  *rsa.PublicKey
		buf bytes.Buffer
	)
	for _, ek := range eks {
		if pub, ok := ek.Public.(*rsa.PublicKey); ok {
			pk = pub
			break
		}
	}

	if pk == nil {
		return nil, errors.New("no EK available")
	}

	if err := pem.Encode(&buf, &pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(pk)}); err != nil {
		return nil, fmt.Errorf("failed to PEM encode: %v", err)
	}
	return buf.Bytes(), nil
}
