package attest

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"math/rand"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func decodeBase10(base10 string, t *testing.T) *big.Int {
	i, ok := new(big.Int).SetString(base10, 10)
	if !ok {
		t.Fatalf("failed decode of base10: %q", base10)
	}
	return i
}

func decodeBase64(in string, t *testing.T) []byte {
	out, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func ekCertSigner(t *testing.T) *rsa.PrivateKey {
	return &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: decodeBase10("14314132931241006650998084889274020608918049032671858325988396851334124245188214251956198731333464217832226406088020736932173064754214329009979944037640912127943488972644697423190955557435910767690712778463524983667852819010259499695177313115447116110358524558307947613422897787329221478860907963827160223559690523660574329011927531289655711860504630573766609239332569210831325633840174683944553667352219670930408593321661375473885147973879086994006440025257225431977751512374815915392249179976902953721486040787792801849818254465486633791826766873076617116727073077821584676715609985777563958286637185868165868520557", t),
			E: 3,
		},
		D: decodeBase10("9542755287494004433998723259516013739278699355114572217325597900889416163458809501304132487555642811888150937392013824621448709836142886006653296025093941418628992648429798282127303704957273845127141852309016655778568546006839666463451542076964744073572349705538631742281931858219480985907271975884773482372966847639853897890615456605598071088189838676728836833012254065983259638538107719766738032720239892094196108713378822882383694456030043492571063441943847195939549773271694647657549658603365629458610273821292232646334717612674519997533901052790334279661754176490593041941863932308687197618671528035670452762731", t),
		Primes: []*big.Int{
			decodeBase10("130903255182996722426771613606077755295583329135067340152947172868415809027537376306193179624298874215608270802054347609836776473930072411958753044562214537013874103802006369634761074377213995983876788718033850153719421695468704276694983032644416930879093914927146648402139231293035971427838068945045019075433", t),
			decodeBase10("109348945610485453577574767652527472924289229538286649661240938988020367005475727988253438647560958573506159449538793540472829815903949343191091817779240101054552748665267574271163617694640513549693841337820602726596756351006149518830932261246698766355347898158548465400674856021497190430791824869615170301029", t),
		},
	}
}

func TestActivationTPM20(t *testing.T) {
	priv := ekCertSigner(t)
	rand := rand.New(rand.NewSource(123456))

	// These parameters represent an AK generated on a real-world, infineon TPM.
	params := ActivationParameters{
		TPMVersion: TPMVersion20,
		AK: AttestationParameters{
			Public:            decodeBase64("AAEACwAFBHIAIJ3/y/NsODrmmfuYaNxty4nXFTiEvigDkiwSQVi/rSKuABAAFAAECAAAAAAAAQC/08gj/04z4xGMIVTmr02lzhI5epufXgU831xEpf2qpXfvtNGUfqTcgWF2EUux2HDPqgcj59dtXRobQdlr4uCGNzfZIGAej4JusLa4MjpG6W2DtJPot6F1Mry63talzJ36U47niy9Iesd34CO2p9Xk3+86ZmBnQ6PQ2roUNK3l7bKz6cFLM9drOLwCqU0AUl6pHvzYPPz+xXsPl3iaA2cM97oneUiJNmJM7wtR9OcaKyIA4wVlX5TndB9NwWq5Iuj8q2Sp40Dg0noXXGSPliAtVD8flkXtAcuI9UHkQbzu9cGPRdSJPMn743GONg3bYalFtcgh2VpACXkPbXB32J7B", t),
			CreateData:        decodeBase64("AAAAAAAg47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFUBAAsAIgALWI9hwDRB3zYSkannqM5z0J1coQNA1Jz/oCRxJQwTaNwAIgALmyFYBhHeIU3FUKIAPgXFD3NXyasP3siQviDEyH7avu4AAA==", t),
			CertifyingKey:     decodeBase64("AAEACwAFBHIAIJ3/y/NsODrmmfuYaNxty4nXFTiEvigDkiwSQVi/rSKuABAAFAAECAAAAAAAAQC/08gj/04z4xGMIVTmr02lzhI5epufXgU831xEpf2qpXfvtNGUfqTcgWF2EUux2HDPqgcj59dtXRobQdlr4uCGNzfZIGAej4JusLa4MjpG6W2DtJPot6F1Mry63talzJ36U47niy9Iesd34CO2p9Xk3+86ZmBnQ6PQ2roUNK3l7bKz6cFLM9drOLwCqU0AUl6pHvzYPPz+xXsPl3iaA2cM97oneUiJNmJM7wtR9OcaKyIA4wVlX5TndB9NwWq5Iuj8q2Sp40Dg0noXXGSPliAtVD8flkXtAcuI9UHkQbzu9cGPRdSJPMn743GONg3bYalFtcgh2VpACXkPbXB32J7B", t),
			CreateAttestation: decodeBase64("/1RDR4AaACIAC41+jhmEOue1MZhJjIk79ENar6i15rBvamXLpQnGTBCOAAAAAAAAD3GRNfU4syzJ1jQGATDCDteFC5C4ACIAC3ToMYGy9GXxcf8A0HvOuLOHbU7HPEppM47C7CMcU8TtACBDmJFUFO1f5+BYevaYdd3VtfMCsxIuHhoTZJczzLP2BA==", t),
			CreateSignature:   decodeBase64("ABQABAEALVzJSnKRJU39gHjETaI89/sM1L6HwBPGNekw6NojSW8bwD5/W1cLRDakCsYKUQu68mmbjs8xaIVBRvVM2YWP10tbTWNB0iJc9b8rERhkk3QIIFm/XsiVZsb0mysTxfeh8zygaAKQ/50sYyzp+raD0Ho0mYIRKJOEdQ6chsBflM3eB8mCXGTugUfrET80q3iu0gncaKWbfxQaQUb9ZTPSJrTN64HQ9tlOfnGT+8++WA3hV0NqKMnoAqiI9GZnI5MPXs6XxEncu/GJLJpAYZakBiS74Jvlr34Pur32B4xjm1M25AUGHEIgb6r49S0sV+hzaKu45858lQRMXj01GcyBhw==", t),
		},
		EK: &rsa.PublicKey{
			E: priv.E,
			N: priv.N,
		},
		Rand: rand,
	}

	secret, _, err := params.Generate()
	if err != nil {
		t.Fatalf("Generate() returned err: %v", err)
	}
	if got, want := secret, decodeBase64("0vhS7HtORX9uf/iyQ8Sf9WkpJuoJ1olCfTjSZuyNNxY=", t); !bytes.Equal(got, want) {
		t.Fatalf("secret = %v, want %v", got, want)
	}
}

func TestAttestationParametersTPM20(t *testing.T) {
	s, tpm := setupSimulatedTPM(t)
	defer s.Close()

	ak, err := tpm.NewAK(nil)
	if err != nil {
		t.Fatal(err)
	}
	akParams := ak.AttestationParameters()

	sk, err := tpm.NewSK(ak, nil)
	if err != nil {
		t.Fatal(err)
	}
	skParams := sk.AttestationParameters()

	for _, test := range []struct {
		name string
		p    *AttestationParameters
		opts VerifyOpts
		err  error
	}{
		{
			name: "AK OK",
			p:    &akParams,
			opts: VerifyOpts{
				SelfAttested: true,
				Restricted:   true,
			},
			err: nil,
		},
		{
			name: "SK OK",
			p:    &skParams,
			opts: VerifyOpts{
				SelfAttested: false,
				Restricted:   false,
			},
			err: nil,
		},
		{
			name: "not self-attested AK",
			p:    &akParams,
			opts: VerifyOpts{
				SelfAttested: false,
				Restricted:   true,
			},
			err: cmpopts.AnyError,
		},
		{
			name: "not restricted AK",
			p:    &akParams,
			opts: VerifyOpts{
				SelfAttested: true,
				Restricted:   false,
			},
			err: cmpopts.AnyError,
		},
		{
			name: "self-attested SK",
			p:    &skParams,
			opts: VerifyOpts{
				SelfAttested: true,
				Restricted:   false,
			},
			err: cmpopts.AnyError,
		},
		{
			name: "restricted SK",
			p:    &skParams,
			opts: VerifyOpts{
				SelfAttested: false,
				Restricted:   true,
			},
			err: cmpopts.AnyError,
		},
		{
			name: "modified Public",
			p: &AttestationParameters{
				Public:            skParams.Public,
				CertifyingKey:     akParams.CertifyingKey,
				CreateData:        akParams.CreateData,
				CreateAttestation: akParams.CreateAttestation,
				CreateSignature:   akParams.CreateSignature,
			},
			opts: VerifyOpts{
				SelfAttested: true,
				Restricted:   true,
			},
			err: cmpopts.AnyError,
		},
		{
			name: "modified CertifyingKey",
			p: &AttestationParameters{
				Public:            akParams.Public,
				CertifyingKey:     skParams.Public,
				CreateData:        akParams.CreateData,
				CreateAttestation: akParams.CreateAttestation,
				CreateSignature:   akParams.CreateSignature,
			},
			opts: VerifyOpts{
				SelfAttested: true,
				Restricted:   true,
			},
			err: cmpopts.AnyError,
		},
		{
			name: "modified CreateData",
			p: &AttestationParameters{
				Public:            akParams.Public,
				CertifyingKey:     akParams.CertifyingKey,
				CreateData:        []byte("unparsable"),
				CreateAttestation: akParams.CreateAttestation,
				CreateSignature:   akParams.CreateSignature,
			},
			opts: VerifyOpts{
				SelfAttested: true,
				Restricted:   true,
			},
			err: cmpopts.AnyError,
		},
		{
			name: "modified CreateAttestation",
			p: &AttestationParameters{
				Public:            akParams.Public,
				CertifyingKey:     akParams.CertifyingKey,
				CreateData:        akParams.CreateData,
				CreateAttestation: skParams.CreateAttestation,
				CreateSignature:   akParams.CreateSignature,
			},
			opts: VerifyOpts{
				SelfAttested: true,
				Restricted:   true,
			},
			err: cmpopts.AnyError,
		},
		{
			name: "modified CreateSignature",
			p: &AttestationParameters{
				Public:            akParams.Public,
				CertifyingKey:     akParams.CertifyingKey,
				CreateData:        akParams.CreateData,
				CreateAttestation: akParams.CreateAttestation,
				CreateSignature:   skParams.CreateSignature,
			},
			opts: VerifyOpts{
				SelfAttested: true,
				Restricted:   true,
			},
			err: cmpopts.AnyError,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.p.Verify(test.opts)
			if test.err == nil && err == nil {
				return
			}
			if got, want := err, test.err; !cmp.Equal(got, want, cmpopts.EquateErrors()) {
				t.Errorf("p.Verify() err = %v, want = %v", got, want)
			}
		})
	}
}
