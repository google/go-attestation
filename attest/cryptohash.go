package attest

import (
	"crypto"
	"fmt"
	"github.com/google/go-tpm/tpm2"
)

func cryptoHash(h tpm2.Algorithm) (crypto.Hash, error) {
	switch h {
	case tpm2.AlgSHA1:
		return crypto.SHA1, nil
	case tpm2.AlgSHA256:
		return crypto.SHA256, nil
	case tpm2.AlgSHA384:
		return crypto.SHA384, nil
	case tpm2.AlgSHA512:
		return crypto.SHA512, nil
	default:
		return crypto.Hash(0), fmt.Errorf("unsupported signature digest: %v", h)
	}
}
