package test

import (
	"github.com/google/go-attestation/attest"
)

func FuzzParseEventLog(data []byte) int {
	attest.ParseEventLog(data)
	return 0
}

