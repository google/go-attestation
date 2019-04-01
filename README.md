Go-Attestation
==============

Go-Attestation abstracts remote attestation operations across a variety of platforms
and TPMs.

## Status

Go-Attestation is under active development and **is not** ready for production use. Expect
API changes at any time.

Please note that this is not an official Google product.

## Build tags on tests

 * `localtest` - Runs tests against TPM hardware of the local system.
 * `tpm12` - Runs TPM 1.2 specific tests against the local system.
