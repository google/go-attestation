package internal

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// buildEFISignatureListData builds a raw EFI_SIGNATURE_LIST byte slice for testing.
// The returned bytes begin with the 28-byte header followed by `payloadLen` zero bytes.
func buildEFISignatureListData(sigType [16]byte, signatureListSize, signatureHeaderSize, signatureSize uint32, payloadLen int) []byte {
	buf := &bytes.Buffer{}
	buf.Write(sigType[:])
	writeUint32 := func(v uint32) {
		b := make([]byte, 4)
		b[0] = byte(v)
		b[1] = byte(v >> 8)
		b[2] = byte(v >> 16)
		b[3] = byte(v >> 24)
		buf.Write(b)
	}
	writeUint32(signatureListSize)
	writeUint32(signatureHeaderSize)
	writeUint32(signatureSize)
	buf.Write(make([]byte, payloadLen))
	return buf.Bytes()
}

// TestParseEfiSignatureListOversizedSignatureSize verifies that a crafted
// EFI_SIGNATURE_LIST with SignatureSize larger than the remaining list space
// is rejected without attempting a multi-gigabyte allocation.
// Prior to the fix, setting SignatureSize=0xFFFFFFFF caused a ~4 GiB
// make([]byte, ...) that crashed or OOM-killed the verifier process.
func TestParseEfiSignatureListOversizedSignatureSize(t *testing.T) {
	// certX509SigGUID: {a5c059a1-94e4-4aa7-87b5-ab155c2bf072}
	certX509SigGUID := [16]byte{0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a, 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72}

	// SignatureListSize=29 (header=28 + 1 payload byte), SignatureSize=0xFFFFFFFF
	// remainingListSize = 29-28 = 1; SignatureSize (0xFFFFFFFF) > 1 → must error.
	data := buildEFISignatureListData(certX509SigGUID, 29, 0, 0xFFFFFFFF, 1)

	_, _, err := parseEfiSignatureList(data)
	if err == nil {
		t.Fatal("parseEfiSignatureList: expected error for oversized SignatureSize, got nil (potential OOM)")
	}
}

func TestParseUEFIVariableData(t *testing.T) {
	data := []byte{0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0xd, 0x0, 0xe0, 0x98,
		0x3, 0x2b, 0x8c, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x53, 0x0, 0x65, 0x0, 0x63, 0x0, 0x75, 0x0, 0x72, 0x0,
		0x65, 0x0, 0x42, 0x0, 0x6f, 0x0, 0x6f, 0x0, 0x74, 0x0, 0x1}
	want := UEFIVariableData{
		Header: UEFIVariableDataHeader{
			VariableName:       efiGUID{Data1: 0x8be4df61, Data2: 0x93ca, Data3: 0x11d2, Data4: [8]uint8{0xaa, 0xd, 0x0, 0xe0, 0x98, 0x3, 0x2b, 0x8c}},
			UnicodeNameLength:  0xa,
			VariableDataLength: 0x1,
		},
		UnicodeName:  []uint16{0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x42, 0x6f, 0x6f, 0x74},
		VariableData: []uint8{0x1},
	}

	got, err := ParseUEFIVariableData(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ParseEFIVariableData() failed: %v", err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ParseUEFIVariableData() mismatch (-want +got):\n%s", diff)
	}
}
