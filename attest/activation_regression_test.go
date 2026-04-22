package attest

import (
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

func TestCheckAKParametersRejectsECCPublicKeyParseFailures(t *testing.T) {
	t.Parallel()

	pub := testECCAKPublic(t, tpm2.CurveBNP256)
	params := testActivationParameters(t, pub, testGarbageSignatureBytes())

	if err := params.CheckAKParameters(); err == nil {
		t.Fatal("CheckAKParameters() unexpectedly accepted an ECC AK when pub.Key() failed")
	}
}

func TestCheckAKParametersRejectsInvalidECDSASignature(t *testing.T) {
	t.Parallel()

	pub := testECCAKPublic(t, tpm2.CurveNISTP256)
	params := testActivationParameters(t, pub, testInvalidECDSASignature(t))

	if err := params.CheckAKParameters(); err == nil {
		t.Fatal("CheckAKParameters() unexpectedly accepted an invalid ECDSA signature")
	}
}

func testActivationParameters(t *testing.T, pub tpm2.Public, createSignature []byte) *ActivationParameters {
	t.Helper()

	publicBlob, err := pub.Encode()
	if err != nil {
		t.Fatalf("pub.Encode(): %v", err)
	}

	createData := testCreationData(t)
	createAttestation := testCreationAttestation(t, pub, createData)

	return &ActivationParameters{
		AK: AttestationParameters{
			Public:            publicBlob,
			CreateData:        createData,
			CreateAttestation: createAttestation,
			CreateSignature:   createSignature,
		},
	}
}

func testECCAKPublic(t *testing.T, curveID tpm2.EllipticCurve) tpm2.Public {
	t.Helper()

	xy := make([]byte, 32)
	xy[len(xy)-1] = 1

	return tpm2.Public{
		Type:       tpm2.AlgECC,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagSignerDefault,
		ECCParameters: &tpm2.ECCParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgECDSA,
				Hash: tpm2.AlgSHA256,
			},
			CurveID: curveID,
			Point: tpm2.ECPoint{
				XRaw: tpmutil.U16Bytes(xy),
				YRaw: tpmutil.U16Bytes(xy),
			},
		},
	}
}

func testCreationData(t *testing.T) []byte {
	t.Helper()

	createData := tpm2.CreationData{
		PCRSelection: tpm2.PCRSelection{
			Hash: tpm2.AlgSHA256,
			PCRs: nil,
		},
		PCRDigest:           nil,
		Locality:            0,
		ParentNameAlg:       tpm2.AlgSHA256,
		ParentName:          tpm2.Name{},
		ParentQualifiedName: tpm2.Name{},
		OutsideInfo:         nil,
	}
	encoded, err := createData.EncodeCreationData()
	if err != nil {
		t.Fatalf("EncodeCreationData(): %v", err)
	}
	return encoded
}

func testCreationAttestation(t *testing.T, pub tpm2.Public, createData []byte) []byte {
	t.Helper()

	name, err := pub.Name()
	if err != nil {
		t.Fatalf("pub.Name(): %v", err)
	}

	digest := sha256.Sum256(createData)
	attestation, err := (tpm2.AttestationData{
		Magic:           0xff544347,
		Type:            tpm2.TagAttestCreation,
		QualifiedSigner: tpm2.Name{},
		ExtraData:       nil,
		ClockInfo:       tpm2.ClockInfo{},
		FirmwareVersion: 0,
		AttestedCreationInfo: &tpm2.CreationInfo{
			Name:         name,
			OpaqueDigest: tpmutil.U16Bytes(digest[:]),
		},
	}).Encode()
	if err != nil {
		t.Fatalf("AttestationData.Encode(): %v", err)
	}
	return attestation
}

func testGarbageSignatureBytes() []byte {
	return []byte{0, 0, 0, 0, 0, 0, 0, 0}
}

func testInvalidECDSASignature(t *testing.T) []byte {
	t.Helper()

	signature, err := (tpm2.Signature{
		Alg: tpm2.AlgECDSA,
		ECC: &tpm2.SignatureECC{
			HashAlg: tpm2.AlgSHA256,
			R:       big.NewInt(1),
			S:       big.NewInt(1),
		},
	}).Encode()
	if err != nil {
		t.Fatalf("Signature.Encode(): %v", err)
	}
	if len(signature) < 8 {
		t.Fatalf("unexpected signature size: %d", len(signature))
	}
	return signature
}
