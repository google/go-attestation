# attest-tool

`attest-tool` is a simple utility to exercise attestation-related operations on your system.

## Building attest-tool

If your system has git and a [Go 1.15+ compiler](https://golang.org/dl/) installed, you can
install `attest-tool` from source by running the following commands:

```shell
git clone 'https://github.com/google/go-attestation' && cd go-attestation/attest/attest-tool
go build -o attest-tool ./ # compiled to ./attest-tool
```

## Testing attestation readiness

The main use-case of `attest-tool` is testing whether attestation works on the local system.

Once `attest-tool` has been built, you can run it in self-test mode like this:

```shell
./attest-tool self-test
```

After a few seconds, it should print out a 'PASS' message, or a 'FAIL' message with a
description of what went wrong.

On Linux, `attest-tool` either needs to be run as root, or granted access to the TPM (`/dev/tpmrm0`) device
& event log (`/sys/kernel/security/tpm0/binary_bios_measurements`)
