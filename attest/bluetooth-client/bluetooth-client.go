package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/go-ble/ble"
	"github.com/go-ble/ble/examples/lib/dev"
	"github.com/google/go-attestation/attest"
)

var AuthCharUUID = ble.MustParse("ebee1790-50b3-4943-8396-16c0b7231cad")
var EkCharUUID = ble.MustParse("ebee1791-50b3-4943-8396-16c0b7231cad")
var AkCharUUID = ble.MustParse("ebee1792-50b3-4943-8396-16c0b7231cad")
var ActivateCharUUID = ble.MustParse("ebee1793-50b3-4943-8396-16c0b7231cad")
var AttestationCharUUID = ble.MustParse("ebee1794-50b3-4943-8396-16c0b7231cad")

func readCharacteristic(cln ble.Client, profile ble.Profile, uuid ble.UUID) ([]byte, error) {
	readlen := 0
	var buf []byte
	char := profile.Find(ble.NewCharacteristic(uuid))
	if char == nil {
		return nil, fmt.Errorf("unable to find uuid %s", uuid)
	}

	for {
		data, err := cln.ReadCharacteristic(char.(*ble.Characteristic))
		if err != nil {
			return nil, err
		}
		if len(data) == 0 {
			return nil, fmt.Errorf("0 byte read")
		}
		if readlen == 0 {
			if len(data) < 4 {
				return nil, fmt.Errorf("Read too little data: %v", data)
			}
			readlen = int(binary.LittleEndian.Uint32(data[0:4]))
			buf = append(buf, data[4:]...)
		} else {
			buf = append(buf, data...)
		}
		if len(buf) == readlen {
			return buf, nil
		}
	}
}

func writeCharacteristic(cln ble.Client, profile ble.Profile, uuid ble.UUID, buf []byte) error {
	written := 0
	char := profile.Find(ble.NewCharacteristic(uuid))
	if char == nil {
		return fmt.Errorf("unable to find uuid %s", uuid)
	}

	for {
		var writebuf [20]byte
		writelen := 20
		if written == 0 {
			binary.LittleEndian.PutUint32(writebuf[:], uint32(len(buf)))
			end := len(buf)
			if end > 16 {
				end = 16
			}
			copy(writebuf[4:20], buf[0:end])
			written = 16
		} else if written < len(buf) {
			end := written + 20
			if end > len(buf) {
				end = len(buf)
				writelen = end - written
			}
			copy(writebuf[0:20], buf[written:end])
			written = end
		} else {
			break
		}
		err := cln.WriteCharacteristic(char.(*ble.Characteristic), writebuf[:writelen], true)
		if err != nil {
			return err
		}
	}
	return nil
}

func filter(arg string) ble.AdvFilter {
	target := strings.ToLower(arg)
	return func(device ble.Advertisement) bool {
		if strings.ToLower(device.LocalName()) == target ||
			strings.ToLower(device.Addr().String()) == target {
			return true
		}
		return false
	}
}

func main() {
	var ap attest.AttestationParameters
	var ek rsa.PublicKey
	var att attest.PlatformParameters

	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s target keydata")
	}

	data, err := ioutil.ReadFile(os.Args[2])
	if len(data) != 16 {
		log.Fatalf("Authentication data is %d bytes long, should be 16", len(data))
	}

	block, err := aes.NewCipher(data)
	if err != nil {
		log.Fatalf("Failed to create cipher: %v", err)
	}

	ctx, _ := context.WithCancel(context.Background())

	d, err := dev.NewDevice("default")
	if err != nil {
		log.Fatalf("can't new device : %v", err)
	}
	ble.SetDefaultDevice(d)

	cln, err := ble.Connect(ctx, filter(os.Args[1]))
	if err != nil {
		log.Fatalf("Unable to connect: %v", err)
	}

	profile, err := cln.DiscoverProfile(true)
	if err != nil {
		log.Fatalf("Unable to obtain device profile: %v", err)
	}

	// Read the challenge from the server. We will encrypt it and pass it
	// back to the server in order to prove that we have access to the
	// authentication secret.
	auth, err := readCharacteristic(cln, *profile, AuthCharUUID)
	if err != nil {
		log.Fatalf("Unable to read auth challenge: %v", err)
	}

	if len(auth) != 32 {
		log.Fatalf("Challenge is %d bytes, should be 32", len(auth))
	}

	// Encrypt the challenge
	aescbc := cipher.NewCBCEncrypter(block, auth[0:16])
	ciphertext := make([]byte, 16)
	aescbc.CryptBlocks(ciphertext, auth[16:32])

	// Pass the encrypted challenge back to the server
	err = writeCharacteristic(cln, *profile, AuthCharUUID, ciphertext)
	if err != nil {
		log.Fatalf("Failed to write auth challenge: %v", err)
	}

	// Read the server's Endorsement Key
	encodedEk, err := readCharacteristic(cln, *profile, EkCharUUID)
	if err != nil {
		log.Fatalf("Unable to read ek: %v", err)
	}

	err = json.Unmarshal(encodedEk, &ek)
	if err != nil {
		log.Fatalf("Unable to unmarshal ek: %v", err)
	}

	// At this point we should verify that the EK certificate chains
	// back to a known TPM manufacturer, but that's not needed for this
	// PoC.  We should also save the EK and use it in future in order to
	// verify that we're talking to the same TPM.

	// Ask the remote TPM to generate an AK and send it to us. Instead,
	// we could persist the AK locally and send it back to the TPM. TODO.
	ak, err := readCharacteristic(cln, *profile, AkCharUUID)
	if err != nil {
		log.Fatalf("Unable to read ak: %v", err)
	}

	err = json.Unmarshal(ak, &ap)
	if err != nil {
		log.Fatalf("Unable to unmarshal ak: %v", err)
	}

	// We now have an AK and an EK. We need to verify that the AK
	// matches the EK in order to prove that we're talking to the same
	// TPM. This is done with credential activation (see
	// docs/credential-activation.md)
	activation := attest.ActivationParameters{
		TPMVersion: attest.TPMVersion12,
		EK:         &ek,
		AK:         ap,
	}

	secret, challenge, err := activation.Generate()
	if err != nil {
		log.Fatalf("Unable to generate activation challenge: %v", err)
	}

	encodedChallenge, err := json.Marshal(challenge)
	if err != nil {
		log.Fatalf("Unable to marshal challenge: %v", err)
	}

	err = writeCharacteristic(cln, *profile, ActivateCharUUID, encodedChallenge)
	if err != nil {
		log.Fatalf("Unable to write credential: %v", err)
	}

	// The remote will TPM now attempt to decrypt the secret with the EK
	// (proving it owns it) and check that the AK matches the appropriate
	// characteristics. If so, it'll return the decrypted secret to us.

	decrypted, err := readCharacteristic(cln, *profile, ActivateCharUUID)
	if err != nil {
		log.Fatalf("Unable to read decrypted secret: %v", err)
	}

	if subtle.ConstantTimeCompare(secret, decrypted) == 0 {
		log.Fatalf("Remote failed to generate correct secret - %v != %v", secret, decrypted)
	}

	// At this point, we know that the AK corresponds to the EK. We now
	// want a quote (a signed copy of the PCR values) and a copy of the
	// event log.
	nonce := make([]byte, 32)
	_, err = rand.Read(nonce)
	if err != nil {
		log.Fatalf("Unable to generate a nonce: %v", err)
	}

	err = writeCharacteristic(cln, *profile, AttestationCharUUID, nonce)
	if err != nil {
		log.Fatalf("Failed to write nonce: %v", err)
	}

	rawquote, err := readCharacteristic(cln, *profile, AttestationCharUUID)
	if err != nil {
		log.Fatalf("Failed to read quote: %v", err)
	}

	err = json.Unmarshal(rawquote, &att)
	if err != nil {
		log.Fatalf("Unable to marshal platform attestation: %v", err)
	}

	// Pull out the AK pub and verify that the quotes are signed with it.
	// Since we've already verified that the AK was generated from the EK,
	// we know that the quote is coming from the TPM.
	pub, err := attest.ParseAKPublic(attest.TPMVersion12, ap.Public)
	if err != nil {
		log.Fatalf("Failed to parse AK public: %v", err)
	}

	for i, q := range att.Quotes {
		if err := pub.Verify(q, att.PCRs, nonce); err != nil {
			log.Fatalf("quote[%d] verification failed: %v", i, err)
		}
	}

	// Make sure the event log is well formed.
	el, err := attest.ParseEventLog(att.EventLog)
	if err != nil {
		log.Fatalf("Failed to parse event log: %v", err)
	}

	// Verify that the event log matches the PCR values we got. We do this
	// by replaying the values in the event log in the same way that the
	// TPM responded to them originally. If the values in the log match
	// the values that were sent to the TPM, that means that the values
	// in the event log match what actually happened during boot.
	events, err := el.Verify(att.PCRs)
	if err != nil {
		log.Fatalf("Log failed to replay: %v", err)
	}

	// Finally, examine the event log to determine whether the system
	// had UEFI secure boot enabled. There is a specific event recorded
	// to PCR 7 that tells us this.
	sbState, err := attest.ParseSecurebootState(events)
	if err != nil {
		log.Fatalf("Failed to parse secure boot state: %v", err)
	}

	log.Printf("Validation succeeded - secure boot state is %v", sbState.Enabled)
}
