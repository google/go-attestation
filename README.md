Go-Attestation
==============

[![GoDoc](https://godoc.org/github.com/google/go-attestation/attest?status.svg)](https://godoc.org/github.com/google/go-attestation/attest)

Go-Attestation abstracts remote attestation operations across a variety of platforms
and TPMs.


## Installation

The go-attestation package is installable using go get: `go get github.com/google/go-attestation/attest`

Linux users must install `libtspi` and its headers. This can be installed on debian-based systems using: `sudo apt-get install libtspi-dev`.

## Status

Go-Attestation is under active development and **is not** ready for production use. Expect
API changes at any time.

Please note that this is not an official Google product.
