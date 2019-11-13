package attest

import (
	"crypto"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var tpm2HashFuncMap = map[crypto.Hash]tpm2.Algorithm{
	crypto.SHA1:   tpm2.AlgSHA1,
	crypto.SHA256: tpm2.AlgSHA256,
	crypto.SHA384: tpm2.AlgSHA384,
	crypto.SHA512: tpm2.AlgSHA512,
}

func tpm2HashFunc(h crypto.Hash) (tpm2.Algorithm, error) {
	if a, ok := tpm2HashFuncMap[h]; ok {
		return a, nil
	}
	return 0, fmt.Errorf("unsupported hash algorithm 0x%x", h)
}

type ec20Key struct {
	tpm    io.ReadWriter
	handle tpmutil.Handle
	pub    crypto.PublicKey
}

type ecdsaSignature struct {
	R, S *big.Int
}

func (k *ec20Key) Public() crypto.PublicKey {
	return k.pub
}

func (k *ec20Key) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hash, err := tpm2HashFunc(opts.HashFunc())
	if err != nil {
		return nil, err
	}
	scheme := &tpm2.SigScheme{Hash: hash, Alg: tpm2.AlgECDSA}
	sig, err := tpm2.Sign(k.tpm, k.handle, akDefaultOwnerPassword, digest, scheme)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %v", err)
	}
	if sig.ECC == nil {
		return nil, fmt.Errorf("signing operation didn't return a signature")
	}
	// See: https://golang.org/src/crypto/ecdsa/ecdsa.go
	return asn1.Marshal(ecdsaSignature{sig.ECC.R, sig.ECC.S})
}

type rsa20Key struct {
	tpm    io.ReadWriter
	handle tpmutil.Handle
	pub    crypto.PublicKey
}

func (k *rsa20Key) Public() crypto.PublicKey {
	return k.pub
}

type sigErr struct {
	scheme *tpm2.SigScheme
	err    error
}

func (s *sigErr) Error() string {
	return fmt.Sprintf("signing with scheme %#v failed: %v", s.scheme, s.err)
}

func (k *rsa20Key) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hash, err := tpm2HashFunc(opts.HashFunc())
	if err != nil {
		return nil, err
	}
	// TODO(ericchiang): support PSS
	scheme := &tpm2.SigScheme{Hash: hash, Alg: tpm2.AlgRSASSA}
	sig, err := tpm2.Sign(k.tpm, k.handle, akDefaultOwnerPassword, digest, scheme)
	if err != nil {
		return nil, &sigErr{scheme, err}
	}
	if sig.RSA == nil {
		return nil, &sigErr{scheme, fmt.Errorf("tpm sign command didn't return a signature")}
	}
	return []byte(sig.RSA.Signature), nil
}

func (k *rsa20Key) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	var alg tpm2.Algorithm
	label := ""
	switch opts := opts.(type) {
	case *rsa.OAEPOptions:
		alg = tpm2.AlgOAEP
		label = string(opts.Label)
	case nil:
		alg = tpm2.AlgOAEP
	case *rsa.PKCS1v15DecryptOptions:
		alg = tpm2.AlgRSAES
	default:
		return nil, fmt.Errorf("unsupported decryption options: %T", opts)
	}
	scheme := &tpm2.AsymScheme{Alg: alg}
	return tpm2.RSADecrypt(k.tpm, k.handle, akDefaultOwnerPassword, msg, scheme, label)
}

type rsa12Key struct {
	pub crypto.PublicKey
}

func (k *rsa12Key) Public() crypto.PublicKey {
	return k.pub
}

func (k *rsa12Key) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, fmt.Errorf("signing not supported for tpm 1.2")
}

func (k *rsa12Key) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	return nil, fmt.Errorf("decrypt not supported for tpm 1.2")
}
