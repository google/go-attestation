package attest_test

import (
	"crypto/subtle"
	"flag"
	"log"
	"testing"

	"github.com/google/go-attestation/attest"
)

var (
	testExamples = flag.Bool("test-examples", false, "Enable tests for examples.")
)

func ExampleAK() {
	tpm, err := attest.OpenTPM(nil)
	if err != nil {
		log.Fatalf("Failed to open the TPM: %v", err)
	}
	defer tpm.Close()

	// Create a new AK.
	ak, err := tpm.NewAK(nil)
	if err != nil {
		log.Fatalf("Failed to create AK: %v", err)
	}
	// Save a re-loadable representation to blob.
	blob, err := ak.Marshal()
	if err != nil {
		log.Fatalf("Failed to marshal AK: %v", err)
	}
	// Close our handle to the AK.
	if err := ak.Close(tpm); err != nil {
		log.Fatalf("Failed to close AK: %v", err)
	}

	// Re-load the created AK from the blob.
	ak, err = tpm.LoadAK(blob)
	if err != nil {
		log.Fatalf("Failed to load AK: %v", err)
	}
	if err := ak.Close(tpm); err != nil {
		log.Fatalf("Failed to close AK: %v", err)
	}
}

func ExampleAK_credentialActivation() {
	tpm, err := attest.OpenTPM(nil)
	if err != nil {
		log.Fatalf("Failed to open TPM: %v", err)
	}
	defer tpm.Close()

	// Create a new AK.
	ak, err := tpm.NewAK(nil)
	if err != nil {
		log.Fatalf("Failed to create AK: %v", err)
	}
	defer ak.Close(tpm)

	// Read the EK.
	ek, err := tpm.EKs()
	if err != nil {
		log.Fatalf("Failed to enumerate EKs: %v", err)
	}

	// Read parameters necessary to generate a challenge.
	ap := ak.AttestationParameters()

	// Generate a credential activation challenge (usually done on the server).
	activation := attest.ActivationParameters{
		EK: ek[0].Public,
		AK: ap,
	}
	secret, challenge, err := activation.Generate()
	if err != nil {
		log.Fatalf("Failed to generate activation challenge: %v", err)
	}

	// Challenge the AK & EK properties to recieve the decrypted secret.
	decrypted, err := ak.ActivateCredential(tpm, *challenge)
	if err != nil {
		log.Fatalf("Failed to activate credential: %v", err)
	}

	// Check that the AK completed the challenge (usually done on the server).
	if subtle.ConstantTimeCompare(secret, decrypted) == 0 {
		log.Fatal("Activation response did not match secret")
	}
}

func ExampleAK_credentialActivationWithEK() {
	tpm, err := attest.OpenTPM(nil)
	if err != nil {
		log.Fatalf("Failed to open TPM: %v", err)
	}
	defer tpm.Close()

	// Create a new AK.
	ak, err := tpm.NewAK(nil)
	if err != nil {
		log.Fatalf("Failed to create AK: %v", err)
	}
	defer ak.Close(tpm)

	// Read the EK certificates.
	ekCerts, err := tpm.EKCertificates()
	if err != nil {
		log.Fatalf("Failed to enumerate EKs: %v", err)
	}

	// Read parameters necessary to generate a challenge.
	ap := ak.AttestationParameters()

	// Try activating with each EK certificate.
	for _, ek := range ekCerts {
		// Generate a credential activation challenge (usually done on the server).
		activation := attest.ActivationParameters{
			EK: ek.Public,
			AK: ap,
		}
		secret, challenge, err := activation.Generate()
		if err != nil {
			log.Fatalf("Failed to generate activation challenge: %v", err)
		}

		// Challenge the AK & EK properties to recieve the decrypted secret.
		decrypted, err := ak.ActivateCredentialWithEK(tpm, *challenge, ek)
		if err != nil {
			log.Fatalf("Failed to activate credential: %v", err)
		}

		// Check that the AK completed the challenge (usually done on the server).
		if subtle.ConstantTimeCompare(secret, decrypted) == 0 {
			log.Fatal("Activation response did not match secret")
		}
	}
}

func TestExampleAK(t *testing.T) {
	if !*testExamples {
		t.SkipNow()
	}
	ExampleAK()
	ExampleAK_credentialActivation()
	ExampleAK_credentialActivationWithEK()
}

func TestExampleTPM(t *testing.T) {
	if !*testExamples {
		t.SkipNow()
	}
	ExampleTPM_AttestPlatform()
}

func ExampleTPM_AttestPlatform() {
	tpm, err := attest.OpenTPM(nil)
	if err != nil {
		log.Fatalf("Failed to open TPM: %v", err)
	}
	defer tpm.Close()

	// Create a new AK.
	ak, err := tpm.NewAK(nil)
	if err != nil {
		log.Fatalf("Failed to create AK: %v", err)
	}
	defer ak.Close(tpm)

	// The nonce would typically be provided by the server.
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	// Perform an attestation against the state of the plaform. Usually, you
	// would pass a nil config, and the event log would be read from the
	// platform. To ensure this example runs on platforms without event logs,
	// we pass a fake EventLog value.
	att, err := tpm.AttestPlatform(ak, nonce, &attest.PlatformAttestConfig{
		EventLog: []byte{0},
	})
	if err != nil {
		log.Fatalf("Failed to attest the platform state: %v", err)
	}

	// Construct an AKPublic struct from the parameters of the key. This
	// will be used to  verify the quote signatures.
	pub, err := attest.ParseAKPublic(ak.AttestationParameters().Public)
	if err != nil {
		log.Fatalf("Failed to parse AK public: %v", err)
	}

	for i, q := range att.Quotes {
		if err := pub.Verify(q, att.PCRs, nonce); err != nil {
			log.Fatalf("quote[%d] verification failed: %v", i, err)
		}
	}
}
