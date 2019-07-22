package activation

import (
	"encoding/base64"
	"testing"

	"github.com/google/go-attestation/attest"
)

func decodeBase64(in string, t *testing.T) []byte {
	out, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestActivationParametersCheckTPM20(t *testing.T) {
	params := Parameters{
		TPMVersion: attest.TPMVersion20,
		AIK: attest.AIKParameters{
			Public:            decodeBase64("AAEACwAFBHIAIJ3/y/NsODrmmfuYaNxty4nXFTiEvigDkiwSQVi/rSKuABAAFAAECAAAAAAAAQC/08gj/04z4xGMIVTmr02lzhI5epufXgU831xEpf2qpXfvtNGUfqTcgWF2EUux2HDPqgcj59dtXRobQdlr4uCGNzfZIGAej4JusLa4MjpG6W2DtJPot6F1Mry63talzJ36U47niy9Iesd34CO2p9Xk3+86ZmBnQ6PQ2roUNK3l7bKz6cFLM9drOLwCqU0AUl6pHvzYPPz+xXsPl3iaA2cM97oneUiJNmJM7wtR9OcaKyIA4wVlX5TndB9NwWq5Iuj8q2Sp40Dg0noXXGSPliAtVD8flkXtAcuI9UHkQbzu9cGPRdSJPMn743GONg3bYalFtcgh2VpACXkPbXB32J7B", t),
			CreateData:        decodeBase64("AAAAAAAg47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFUBAAsAIgALWI9hwDRB3zYSkannqM5z0J1coQNA1Jz/oCRxJQwTaNwAIgALmyFYBhHeIU3FUKIAPgXFD3NXyasP3siQviDEyH7avu4AAA==", t),
			CreateAttestation: decodeBase64("/1RDR4AaACIAC41+jhmEOue1MZhJjIk79ENar6i15rBvamXLpQnGTBCOAAAAAAAAD3GRNfU4syzJ1jQGATDCDteFC5C4ACIAC3ToMYGy9GXxcf8A0HvOuLOHbU7HPEppM47C7CMcU8TtACBDmJFUFO1f5+BYevaYdd3VtfMCsxIuHhoTZJczzLP2BA==", t),
			CreateSignature:   decodeBase64("ABQABAEALVzJSnKRJU39gHjETaI89/sM1L6HwBPGNekw6NojSW8bwD5/W1cLRDakCsYKUQu68mmbjs8xaIVBRvVM2YWP10tbTWNB0iJc9b8rERhkk3QIIFm/XsiVZsb0mysTxfeh8zygaAKQ/50sYyzp+raD0Ho0mYIRKJOEdQ6chsBflM3eB8mCXGTugUfrET80q3iu0gncaKWbfxQaQUb9ZTPSJrTN64HQ9tlOfnGT+8++WA3hV0NqKMnoAqiI9GZnI5MPXs6XxEncu/GJLJpAYZakBiS74Jvlr34Pur32B4xjm1M25AUGHEIgb6r49S0sV+hzaKu45858lQRMXj01GcyBhw==", t),
		},
	}

	_, _, err := params.Generate()
	if err != nil {
		t.Fatalf("VerifyAIK() returned err: %v", err)
	}
}
