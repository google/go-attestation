package verifier

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"testing"

	tpb "github.com/google/go-attestation/proto"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

func decodeBase64(in string, t *testing.T) []byte {
	out, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestVerifyAIK(t *testing.T) {
	pub := decodeBase64("AAEACwAFBHIAIJ3/y/NsODrmmfuYaNxty4nXFTiEvigDkiwSQVi/rSKuABAAFAAECAAAAAAAAQC/08gj/04z4xGMIVTmr02lzhI5epufXgU831xEpf2qpXfvtNGUfqTcgWF2EUux2HDPqgcj59dtXRobQdlr4uCGNzfZIGAej4JusLa4MjpG6W2DtJPot6F1Mry63talzJ36U47niy9Iesd34CO2p9Xk3+86ZmBnQ6PQ2roUNK3l7bKz6cFLM9drOLwCqU0AUl6pHvzYPPz+xXsPl3iaA2cM97oneUiJNmJM7wtR9OcaKyIA4wVlX5TndB9NwWq5Iuj8q2Sp40Dg0noXXGSPliAtVD8flkXtAcuI9UHkQbzu9cGPRdSJPMn743GONg3bYalFtcgh2VpACXkPbXB32J7B", t)
	creation := decodeBase64("AAAAAAAg47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFUBAAsAIgALWI9hwDRB3zYSkannqM5z0J1coQNA1Jz/oCRxJQwTaNwAIgALmyFYBhHeIU3FUKIAPgXFD3NXyasP3siQviDEyH7avu4AAA==", t)
	attest := decodeBase64("/1RDR4AaACIAC41+jhmEOue1MZhJjIk79ENar6i15rBvamXLpQnGTBCOAAAAAAAAD3GRNfU4syzJ1jQGATDCDteFC5C4ACIAC3ToMYGy9GXxcf8A0HvOuLOHbU7HPEppM47C7CMcU8TtACBDmJFUFO1f5+BYevaYdd3VtfMCsxIuHhoTZJczzLP2BA==", t)
	sig := decodeBase64("ABQABAEALVzJSnKRJU39gHjETaI89/sM1L6HwBPGNekw6NojSW8bwD5/W1cLRDakCsYKUQu68mmbjs8xaIVBRvVM2YWP10tbTWNB0iJc9b8rERhkk3QIIFm/XsiVZsb0mysTxfeh8zygaAKQ/50sYyzp+raD0Ho0mYIRKJOEdQ6chsBflM3eB8mCXGTugUfrET80q3iu0gncaKWbfxQaQUb9ZTPSJrTN64HQ9tlOfnGT+8++WA3hV0NqKMnoAqiI9GZnI5MPXs6XxEncu/GJLJpAYZakBiS74Jvlr34Pur32B4xjm1M25AUGHEIgb6r49S0sV+hzaKu45858lQRMXj01GcyBhw==", t)

	verificationResults, err := VerifyAIK(2, &tpb.AikInfo{
		TpmAikInfo: &tpb.AikInfo_Tpm20{
			Tpm20: &tpb.Tpm20AikInfo{
				PublicBlob:      pub,
				CreationData:    creation,
				AttestationData: attest,
				SignatureData:   sig,
			},
		},
	})
	if err != nil {
		t.Fatalf("VerifyAIK() returned err: %v", err)
	}
	if !verificationResults.GetSucceeded() {
		t.Errorf("verification.Succeeded = %v, want true", verificationResults.GetSucceeded())
	}
}

func setupSimulatedTPM(t *testing.T) *simulator.Simulator {
	t.Helper()
	tpm, err := simulator.Get()
	if err != nil {
		t.Fatal(err)
	}
	return tpm
}

func allPCRs(tpm io.ReadWriter, hash tpm2.Algorithm) (map[uint32][]byte, error) {
	numPCRs := 24
	out := map[uint32][]byte{}

	// The TPM 2.0 spec says that the TPM can partially fulfill the
	// request. As such, we repeat the command up to 8 times to get all
	// 24 PCRs.
	for i := 0; i < numPCRs; i++ {
		// Build a selection structure, specifying all PCRs we do
		// not have the value for.
		sel := tpm2.PCRSelection{Hash: hash}
		for pcr := 0; pcr < numPCRs; pcr++ {
			if _, present := out[uint32(pcr)]; !present {
				sel.PCRs = append(sel.PCRs, pcr)
			}
		}

		// Ask the TPM for those PCR values.
		ret, err := tpm2.ReadPCRs(tpm, sel)
		if err != nil {
			return nil, fmt.Errorf("tpm2.ReadPCRs(%+v) failed with err: %v", sel, err)
		}
		// Keep track of the PCRs we were actually given.
		for pcr, digest := range ret {
			out[uint32(pcr)] = digest
		}
		if len(out) == numPCRs {
			break
		}
	}

	if len(out) != numPCRs {
		return nil, fmt.Errorf("failed to read all PCRs, only read %d", len(out))
	}

	return out, nil
}

func TestVerifyQuoteTPM20(t *testing.T) {
	tpm := setupSimulatedTPM(t)
	defer tpm.Close()
	if err := tpm.ManufactureReset(); err != nil {
		t.Fatalf("Failed to reset TPM: %v", err)
	}

	// Create the attestation key.
	keyHandle, pub, _, _, _, _, err := tpm2.CreatePrimaryEx(tpm, tpm2.HandleEndorsement, tpm2.PCRSelection{}, "", "", tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagSignerDefault | tpm2.FlagNoDA,
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
			Modulus: big.NewInt(0),
		},
	})
	if err != nil {
		t.Fatalf("CreatePrimaryEx() failed: %v", err)
	}
	defer tpm2.FlushContext(tpm, keyHandle)

	for _, alg := range []tpm2.Algorithm{tpm2.AlgSHA1, tpm2.AlgSHA256} {
		t.Run(fmt.Sprintf("Alg %x", alg), func(t *testing.T) {
			// Generate the quote.
			sel := tpm2.PCRSelection{Hash: alg}
			numPCRs := 24
			for pcr := 0; pcr < numPCRs; pcr++ {
				sel.PCRs = append(sel.PCRs, pcr)
			}
			nonce := []byte{1, 2, 3, 4}
			quote, qSig, err := tpm2.Quote(tpm, keyHandle, "", "", nonce, sel, tpm2.AlgNull)
			if err != nil {
				t.Fatalf("tpm2.Quote() failed: %v", err)
			}
			sig, err := tpmutil.Pack(qSig.Alg, qSig.RSA.HashAlg, qSig.RSA.Signature)
			if err != nil {
				t.Fatalf("tpmutil.Pack() failed: %v", err)
			}

			PCRs, err := allPCRs(tpm, alg)
			if err != nil {
				t.Fatalf("allPCRs() failed: %v", err)
			}

			verificationResults, err := VerifyQuote(2, pub, quote, sig, PCRs, nonce)
			if err != nil {
				t.Errorf("VerifyQuote failed: %v", err)
			}
			if !verificationResults.Succeeded {
				t.Logf("Verification results: %+v", verificationResults)
				t.Errorf("verificationResults.succeeded = %v, expected true", verificationResults.Succeeded)
			}
		})
	}
}

func TestRoca(t *testing.T) {
	key := &rsa.PublicKey{N: &big.Int{}}
	key.N.SetString("944e13208a280c37efc31c3114485e590192adbb8e11c87cad60cdef0037ce99278330d3f471a2538fa667802ed2a3c44a8b7dea826e888d0aa341fd664f7fa7", 16)

	if !ROCAVulnerableKey(key) {
		t.Errorf("ROCAVulnerableKey() = %v, wanted true", ROCAVulnerableKey(key))
	}
}

func TestVerifyQuoteTPM12(t *testing.T) {
	tcs := []struct {
		PublicHex    string
		QuoteHex     string
		SignatureHex string
		Nonce        []byte
		PCRs         map[int]string
	}{
		{
			PublicHex:    "00000001000100020000000c00000800000000020000000000000100be855eadb504443ec1a85f5894cf9ae6b97fe75c39debe2376d13e49632ea34dc917c99f0ea29c52349eba9b1abfd2a92e814057568338ea68a32a45f92ae23944d0765805489414f9c588778220a3f384b7b2c4be8132515e276eefde7cb807303f7a7d57900f94dda27e6abe5e411026b8be7637483747073fa731643807e4c3d7e6fdad0ea297beaaeb208465aa4906447fcddf1955f5ac0a439295f7b43fbe38d018009456c17426e4ebf1581c99e3a97ff151a0c649335a46ec8189849b4efe932cb3a7d57e2ee45e67a7fcb64da5041604f24fd6153898fbe5d8432d95b2ad5d4b89088f6306f6b1a7d8c55c748838a96d106efc39ce119b11ac51211b",
			QuoteHex:     "0101000051554f54d45a9b15807eac8d85cd467ec0060815cc687c18a8b93257fea90bba13ede78f0db2d81ae4173c19",
			SignatureHex: "33a4260f049c64f7539ab5a5f5adf1c87fc31d9ae5165340636ba96c88b82eb402b46902315c65d0d8b7a861ec8cd3f0d1bb7d264420cb7dca8e3d5862c5ecf5114f3bde50890cbf8c05b95fb0f2c70c816f9e86f247c4377aa58e84f24e6a910ea414664b9cdd1ff4a3522994ec1e1f419a2e1e3f503689e4eb0606c0b3e9a42f4f7b74c937d4d061161390e1790b6561b0d288e3534fd1b62af6a8c232174e1cb1586b863bd20e95e73e52e27a0781c7160672257831eb9b1d5192098495ad2170490c5e52693385e43aeab95069eecdd3f80529fdcc7ff2ef6086c24c06576e53b77e2f88eafb3e9b9fd40d954a7e0ab4c01e5b9a73d5d1841c49924beb64",
			Nonce:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			PCRs: map[int]string{
				0:  "b777654263752ed0bfe13b369cf512b4661eee04",
				1:  "c2b93db7e6f705f98419a35cc6e46deb639c6a28",
				2:  "b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236",
				3:  "b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236",
				4:  "8f3fe5e128e3f2186bfca0b804900ec9ded96e39",
				5:  "45a323382bd933f08e7f0e256bc8249e4095b1ec",
				6:  "ee1b0f997d7517b286bc9d73a4cf742c65a769be",
				7:  "9d42f8fe8bfd73fba0274c7db891d91fb7861562",
				8:  "0000000000000000000000000000000000000000",
				9:  "0000000000000000000000000000000000000000",
				10: "0000000000000000000000000000000000000000",
				11: "ebb98df76613280f20dc38221143a9e727399486",
				12: "575e12d9ec16d6512648f25b65d38b4eb27a2d6d",
				13: "a9f1781a95d2e37970d1d73c463157fa016d9858",
				14: "fc76feaf714c844cc888ea454ddf97c0ed220b61",
				15: "0000000000000000000000000000000000000000",
				16: "0000000000000000000000000000000000000000",
				17: "ffffffffffffffffffffffffffffffffffffffff",
				18: "ffffffffffffffffffffffffffffffffffffffff",
				19: "ffffffffffffffffffffffffffffffffffffffff",
				20: "ffffffffffffffffffffffffffffffffffffffff",
				21: "ffffffffffffffffffffffffffffffffffffffff",
				22: "ffffffffffffffffffffffffffffffffffffffff",
				23: "0000000000000000000000000000000000000000",
			},
		},
	}

	for i, testcase := range tcs {
		tc := testcase
		t.Run(fmt.Sprintf("case %d", i), func(t *testing.T) {
			pub, err := hex.DecodeString(tc.PublicHex)
			if err != nil {
				t.Fatal(err)
			}
			quote, err := hex.DecodeString(tc.QuoteHex)
			if err != nil {
				t.Fatal(err)
			}
			sig, err := hex.DecodeString(tc.SignatureHex)
			if err != nil {
				t.Fatal(err)
			}

			pcrs := make(map[uint32][]byte)
			for idx, h := range tc.PCRs {
				pcrs[uint32(idx)], err = hex.DecodeString(h)
				if err != nil {
					t.Fatal(err)
				}
			}

			verificationResults, err := VerifyQuote(1, pub, quote, sig, pcrs, tc.Nonce)
			if err != nil {
				t.Errorf("VerifyQuote failed: %v", err)
			}
			if !verificationResults.Succeeded {
				t.Errorf("verificationResults.Succeeded = %v, want %v", verificationResults.Succeeded, true)
			}
		})
	}
}
