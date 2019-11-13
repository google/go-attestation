package attest

import "crypto"

var (
	_ = (crypto.Decrypter)(&rsa20Key{})
	_ = (crypto.Signer)(&rsa20Key{})
	_ = (crypto.Signer)(&ec20Key{})
)
