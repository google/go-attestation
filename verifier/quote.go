package verifier

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"fmt"
	"sort"

	tpb "github.com/google/go-attestation/proto"
	pb "github.com/google/go-attestation/verifier/proto"
	tpm1 "github.com/google/go-tpm/tpm"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
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

// VerifyQuote returns information about the validity of a quote & signature.
func VerifyQuote(tpmVersion tpb.TpmVersion, public, attestationData, signature []byte, pcrs map[uint32][]byte, nonce []byte) (*pb.QuoteVerificationResults, error) {
	var (
		pcrDigestMatched bool
		nonceMatched     bool
		verifyErr        error
		digest           []byte
	)
	if len(signature) < 8 {
		return nil, fmt.Errorf("signature is too short to be valid: only %d bytes", len(signature))
	}

	switch tpmVersion {
	case tpb.TpmVersion_TPM_20:
		var compositeHash crypto.Hash
		var verifyHash crypto.Hash
		pub, err := tpm2.DecodePublic(public)
		if err != nil {
			return nil, err
		}

		att, err := tpm2.DecodeAttestationData(attestationData)
		if err != nil {
			return nil, err
		}
		if att.Type != tpm2.TagAttestQuote {
			return nil, fmt.Errorf("attestation is tagged %x, want TagAttestQuote", att.Type)
		}
		digest = att.AttestedQuoteInfo.PCRDigest

		// Compute the digest of PCR values based on the provided individual PCR values.
		compositeHash, err = cryptoHash(pub.RSAParameters.Sign.Hash)
		if err != nil {
			return nil, err
		}

		var compositeData []byte
		for _, pcr := range att.AttestedQuoteInfo.PCRSelection.PCRs {
			digest, ok := pcrs[uint32(pcr)]
			if !ok {
				return nil, fmt.Errorf("PCR %d missing but used to compute PCR digest", pcr)
			}
			compositeData = append(compositeData, digest...)
		}
		compositeDigest := compositeHash.New()
		compositeDigest.Write(compositeData)
		pcrDigestMatched = bytes.Equal(compositeDigest.Sum(nil), digest)

		// Check the signature over the attestation data verifies correctly.
		p := rsa.PublicKey{E: int(pub.RSAParameters.Exponent()), N: pub.RSAParameters.Modulus()}
		signHashConstructor, err := pub.RSAParameters.Sign.Hash.HashConstructor()
		if err != nil {
			return nil, err
		}
		hsh := signHashConstructor()
		hsh.Write(attestationData)

		verifyHash, err = cryptoHash(pub.RSAParameters.Sign.Hash)
		if err != nil {
			return nil, err
		}

		nonceMatched = bytes.Equal(att.ExtraData, nonce)

		//TODO(jsonp): Decode to tpm2.Signature & use that, once PR to expose DecodeSignature() is in.
		verifyErr = rsa.VerifyPKCS1v15(&p, verifyHash, hsh.Sum(nil), signature[6:])
	case tpb.TpmVersion_TPM_12:
		p, err := tpm1.UnmarshalPubRSAPublicKey(public)
		if err != nil {
			return nil, err
		}
		digest = attestationData
		pcrNums := sortPCRs(pcrs)
		compositeData := []byte{}
		for _, pcr := range pcrNums {
			compositeData = append(compositeData, pcrs[uint32(pcr)]...)
		}
		composite, err := tpmutil.Pack(&struct {
			Mask tpmutil.U16Bytes
			Data tpmutil.U32Bytes
		}{
			Mask: []byte{0xff, 0xff, 0xff},
			Data: compositeData,
		})

		info := struct {
			Version [4]byte
			QUOT    [4]byte
			Digest  [20]byte
			Nonce   [20]byte
		}{}
		if _, err = tpmutil.Unpack(attestationData, &info); err != nil {
			return nil, err
		}
		pcrDigestMatched = sha1.Sum(composite) == info.Digest
		nonceMatched = sha1.Sum(nonce) == info.Nonce

		verifyErr = tpm1.VerifyQuote(p, nonce, signature, pcrNums, compositeData)
	default:
		return nil, fmt.Errorf("TPM version %d not supported", tpmVersion)
	}
	return &pb.QuoteVerificationResults{
		SignatureMismatch: verifyErr != nil,
		Succeeded:         verifyErr == nil && pcrDigestMatched && nonceMatched,
		PcrDigest:         digest,
		PcrDigestMismatch: !pcrDigestMatched,
		NonceMismatch:     !nonceMatched,
	}, nil
}

func sortPCRs(pcrs map[uint32][]byte) []int {
	pcrNums := []int{}
	for pcr := range pcrs {
		pcrNums = append(pcrNums, int(pcr))
	}
	sort.Slice(pcrNums, func(i int, j int) bool {
		return pcrNums[i] < pcrNums[j]
	})
	return pcrNums
}
