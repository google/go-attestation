package attest

import (
	"bytes"
	"testing"
)

func TestMakeActivationBlob(t *testing.T) {
	blob, err := makeActivationBlob([]byte{1, 2, 3, 4, 5}, []byte{5, 6, 7, 8})
	if err != nil {
		t.Fatal(err)
	}

	if got, want := blob[0:2], []byte{0, 0x2b}; !bytes.Equal(got, want) {
		t.Errorf("tag = %v, want %v", got, want)
	}
	if got, want := blob[2:6], []byte{0, 0, 0, 0x0a}; !bytes.Equal(got, want) {
		t.Errorf("alg = %v, want %v", got, want)
	}
	if got, want := blob[6:8], []byte{0, 1}; !bytes.Equal(got, want) {
		t.Errorf("scheme = %v, want %v", got, want)
	}
	if got, want := blob[8:10], []byte{0, 5}; !bytes.Equal(got, want) {
		t.Errorf("len = %v, want %v", got, want)
	}
	if got, want := blob[10:15], []byte{1, 2, 3, 4, 5}; !bytes.Equal(got, want) {
		t.Errorf("symKey = %v, want %v", got, want)
	}
	if got, want := blob[15:35], []byte{133, 217, 101, 29, 154, 57, 154, 103, 224, 21, 208, 71, 253, 158, 106, 148, 30, 107, 32, 187}; !bytes.Equal(got, want) {
		t.Errorf("ak digest = %v, want %v", got, want)
	}
	if got, want := blob[35:37], []byte{0, 3}; !bytes.Equal(got, want) {
		t.Errorf("size of select = %v, want %v", got, want)
	}
	if got, want := blob[37:40], []byte{0, 0, 0}; !bytes.Equal(got, want) {
		t.Errorf("select bitfield = %v, want %v", got, want)
	}
	if got, want := blob[40:41], []byte{1}; !bytes.Equal(got, want) {
		t.Errorf("locality = %v, want %v", got, want)
	}
	if got, want := blob[41:61], bytes.Repeat([]byte{0}, 20); !bytes.Equal(got, want) {
		t.Errorf("select digest = %v, want %v", got, want)
	}
}
