// Package internal contains marshalling structures for attest-tool and tests.
package internal

import (
	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/tpm2"
)

// Dump describes the layout of serialized information from the dump command.
type Dump struct {
	Static struct {
		TPMVersion attest.TPMVersion
		EKPem      []byte
	}

	AIK attest.AttestationParameters

	Quote struct {
		Nonce     []byte
		Alg       attest.HashAlg
		Quote     []byte
		Signature []byte
	}

	Log struct {
		PCRs   []attest.PCR
		PCRAlg tpm2.Algorithm
		Raw    []byte // The measured boot log in binary form.
	}
}
