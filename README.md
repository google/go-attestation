Go-Attestation
==============

[![GoDoc](https://godoc.org/github.com/google/go-attestation/attest?status.svg)](https://godoc.org/github.com/google/go-attestation/attest)

Go-Attestation abstracts remote attestation operations across a variety of platforms
and TPMs, enabling remote validation of machine identity and state. This project
attempts to provide high level primitives for both client and server logic.

Talks on this project:

* _"Making Device Identity Trustworthy"_ - Open Source Summit Europe - October 2019 - ([Slides](https://static.sched.com/hosted_files/osseu19/ec/Device%20Identity.pdf))
* _"Using TPMs to Cryptographically Verify Devices at Scale"_ - Open Source Summit North America - September 2019 - ([Video](https://www.youtube.com/watch?v=EmEymlA5Q5Q) 39min)
* _"Making Remote Attestation Useful on Linux"_ - Linux Security Summit - September 2019 - ([Video](https://www.youtube.com/watch?v=TKva_h66Ptc) 26min)

## Status

Go-Attestation is under active development. Expect
API changes at any time.

Please note that this is not an official Google product.

TPM 1.2 support is best effort, meaning we will accept fixes for TPM 1.2, but
testing is not covered by CI.

## Installation

The go-attestation package is installable using go get: `go get github.com/google/go-attestation/attest`

### TPM1.2
By default, go-attestation does not build in TPM1.2 support on Linux.
Linux users must install [`libtspi`](http://trousers.sourceforge.net/) and its headers if they need TPM 1.2 support. This can be installed on debian-based systems using: `sudo apt-get install libtspi-dev`.
Then, build go-attestation with the `tspi` [build tag](https://pkg.go.dev/go/build#hdr-Build_Constraints) `go build --tags=tspi`.

Windows users can use go-attestation with TPM1.2 by default.

## Example: device identity

TPMs can be used to identify a device remotely and provision unique per-device
hardware-bound keys.

TPMs are provisioned with a set of Endorsement Keys (EKs) by the manufacturer.
These optionally include a certificate signed by the manufacturer and act as a
TPM's identity. For privacy reasons the EK can't be used to sign or encrypt data
directly, and is instead used to attest to the presence of a signing key, an
Attestation Key (AK), on the same TPM. (Newer versions of the spec may allow the
EK to sign directly.)

During attestation, a TPM generates an AK and proves to a certificate authority
that the AK is on the same TPM as a EK. If the certificate authority trusts the
EK, it can transitively trust the AK, for example by issuing a certificate for
the AK.

To perform attestation, the client generates an AK and sends the EK and AK
parameters to the server:

```go
// Client generates an AK and sends it to the server

config := &attest.OpenConfig{}
tpm, err := attest.OpenTPM(config)
if err != nil {
    // handle error
}

eks, err := tpm.EKs()
if err != nil {
    // handle error
}
ek := eks[0]

akConfig := &attest.AKConfig{}
ak, err := tpm.NewAK(akConfig)
if err != nil {
    // handle error
}
attestParams := ak.AttestationParameters()

akBytes, err := ak.Marshal()
if err != nil {
    // handle error
}

if err := os.WriteFile("encrypted_aik.json", akBytes, 0600); err != nil {
    // handle error
}

// send TPM version, EK, and attestParams to the server
```

The server uses the EK and AK parameters to generate a challenge encrypted to
the EK, returning the challenge to the client. During this phase, the server
determines if it trusts the EK, either by chaining its certificate to a known
manufacturer and/or querying an inventory system.

```go
// Server validates EK and/or EK certificate

params := attest.ActivationParameters{
    TPMVersion: tpmVersion,
    EK:         ek.Public,
    AK:         attestParams,
}
secret, encryptedCredentials, err := params.Generate()
if err != nil {
    // handle error
}

// return encrypted credentials to client
```

The client proves possession of the AK by decrypting the challenge and
returning the same secret to the server.

```go
// Client decrypts the credential

akBytes, err := os.ReadFile("encrypted_aik.json")
if err != nil {
    // handle error
}
ak, err := tpm.LoadAK(akBytes)
if err != nil {
    // handle error
}
secret, err := ak.ActivateCredential(tpm, encryptedCredentials)
if err != nil {
    // handle error
}

// return secret to server
```

At this point, the server records the AK and EK association and allows the client
to use its AK as a credential (e.g. by issuing it a client certificate).
