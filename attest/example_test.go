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

func ExampleAIK() {
	tpm, err := attest.OpenTPM(nil)
	if err != nil {
		log.Fatalf("Failed to open the TPM: %v", err)
	}
	defer tpm.Close()

	// Create a new AIK.
	aik, err := tpm.MintAIK(nil)
	if err != nil {
		log.Fatalf("Failed to create AIK: %v", err)
	}
	// Save a re-loadable representation to blob.
	blob, err := aik.Marshal()
	if err != nil {
		log.Fatalf("Failed to marshal AIK: %v", err)
	}
	// Close our handle to the AIK.
	if err := aik.Close(tpm); err != nil {
		log.Fatalf("Failed to close AIK: %v", err)
	}

	// Re-load the created AIK from the blob.
	aik, err = tpm.LoadAIK(blob)
	if err != nil {
		log.Fatalf("Failed to load AIK: %v", err)
	}
	if err := aik.Close(tpm); err != nil {
		log.Fatalf("Failed to close AIK: %v", err)
	}
}

func Example_credentialActivation() {
	tpm, err := attest.OpenTPM(nil)
	if err != nil {
		log.Fatalf("Failed to open TPM: %v", err)
	}
	defer tpm.Close()

	// Create a new AIK.
	aik, err := tpm.MintAIK(nil)
	if err != nil {
		log.Fatalf("Failed to create AIK: %v", err)
	}
	defer aik.Close(tpm)

	// Read the EK.
	ek, err := tpm.EKs()
	if err != nil {
		log.Fatalf("Failed to enumerate EKs: %v", err)
	}

	// Read parameters necessary to generate a challenge.
	ap := aik.AttestationParameters()

	// Generate a credential activation challenge (usually done on the server).
	activation := attest.ActivationParameters{
		TPMVersion: tpm.Version(),
		EK:         ek[0].Public,
		AIK:        ap,
	}
	secret, challenge, err := activation.Generate()
	if err != nil {
		log.Fatalf("Failed to generate activation challenge: %v", err)
	}

	// Challenge the AIK & EK properties to recieve the decrypted secret.
	decrypted, err := aik.ActivateCredential(tpm, *challenge)
	if err != nil {
		log.Fatalf("Failed to activate credential: %v", err)
	}

	// Check that the AIK completed the challenge (usually done on the server).
	if subtle.ConstantTimeCompare(secret, decrypted) == 0 {
		log.Fatal("Activation response did not match secret")
	}
}

func TestExampleAIK(t *testing.T) {
	if !*testExamples {
		t.SkipNow()
	}
	ExampleAIK()
	Example_credentialActivation()
}
