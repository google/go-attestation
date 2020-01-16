package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"io/ioutil"
	"log"
	"os"

	"github.com/go-ble/ble"
	"github.com/go-ble/ble/examples/lib/dev"
	"github.com/go-ble/ble/linux/hci/evt"
	"github.com/google/go-attestation/attest"
)

var TpmSvcUUID = ble.MustParse("99a84b8f-8d7c-47b0-b24e-800e00fa5d57")

var AuthCharUUID = ble.MustParse("ebee1790-50b3-4943-8396-16c0b7231cad")
var EkCharUUID = ble.MustParse("ebee1791-50b3-4943-8396-16c0b7231cad")
var AkCharUUID = ble.MustParse("ebee1792-50b3-4943-8396-16c0b7231cad")
var ActivateCharUUID = ble.MustParse("ebee1793-50b3-4943-8396-16c0b7231cad")
var AttestationCharUUID = ble.MustParse("ebee1794-50b3-4943-8396-16c0b7231cad")

var decrypted []byte
var encodedek []byte
var encodedak []byte
var encodedec []byte
var encodedattestation []byte
var nonce []byte
var tpm *attest.TPM
var ak *attest.AK
var marshaledak []byte
var authkey [16]byte
var authenticated bool

func writeBuf(written *int, buf []byte, rsp ble.ResponseWriter, force bool) bool {
	var writebuf [20]byte

	if authenticated == false && force == false {
		return false
	}

	writelen := 20
	if *written == 0 {
		binary.LittleEndian.PutUint32(writebuf[:], uint32(len(buf)))
		end := len(buf)
		if end > 16 {
			end = 16
		}
		copy(writebuf[4:end+4], buf[0:end])
		*written = end
		writelen = end + 4
	} else if *written < len(buf) {
		end := *written + 20
		if end > len(buf) {
			end = len(buf)
			writelen = end - *written
		}
		copy(writebuf[0:20], buf[*written:end])
		*written = end
	} else {
		writelen = 0
	}
	rsp.Write(writebuf[:writelen])
	if *written == len(buf) {
		return true
	}
	return false
}

func readBuf(readlen *int, buf *[]byte, req ble.Request) bool {
	if authenticated == false {
		return false
	}

	if *readlen == 0 {
		*readlen = int(binary.LittleEndian.Uint32(req.Data()[0:4]))
		*buf = append(*buf, req.Data()[4:]...)
	} else {
		*buf = append(*buf, req.Data()...)
	}
	if len(*buf) == *readlen {
		return true
	}
	return false
}

func AuthChar() *ble.Characteristic {
	var valid bool
	var data []byte
	written := 0

	block, err := aes.NewCipher(authkey[:])
	if err != nil {
		return nil
	}

	authnonce := make([]byte, 16)
	challenge := make([]byte, 16)

	_, err = rand.Read(nonce)
	if err != nil {
		return nil
	}
	_, err = rand.Read(challenge)
	if err != nil {
		return nil
	}

	data = append(data, authnonce...)
	data = append(data, challenge...)

	valid = true

	c := ble.NewCharacteristic(AuthCharUUID)
	c.HandleRead(ble.ReadHandlerFunc(func(req ble.Request, rsp ble.ResponseWriter) {
		if valid == false {
			_, err := rand.Read(authnonce)
			if err != nil {
				return
			}
			_, err = rand.Read(challenge)
			if err != nil {
				return
			}

			data = data[:0]
			data = append(data, authnonce...)
			data = append(data, challenge...)

			valid = true
		}

		complete := writeBuf(&written, data, rsp, true)
		if complete == true {
			written = 0
		}

	}))
	c.HandleWrite(ble.WriteHandlerFunc(func(req ble.Request, rsp ble.ResponseWriter) {
		written = 0
		if valid == false {
			return
		}

		valid = false
		if len(req.Data()) != 20 {
			return
		}
		aescbc := cipher.NewCBCDecrypter(block, authnonce)

		ciphertext := req.Data()[4:20]

		aescbc.CryptBlocks(ciphertext, ciphertext)

		if subtle.ConstantTimeCompare(challenge, ciphertext) != 0 {
			authenticated = true
		} else {
			log.Printf("Auth expected %v, got %v", challenge, ciphertext)
		}
	}))

	return c
}

func EkChar() *ble.Characteristic {
	written := 0

	// Read the Endorsement Key from the TPM and pass it back to the
	// client
	c := ble.NewCharacteristic(EkCharUUID)
	c.HandleRead(ble.ReadHandlerFunc(func(req ble.Request, rsp ble.ResponseWriter) {
		complete := writeBuf(&written, encodedek, rsp, false)
		if complete == true {
			written = 0
		}
	}))

	return c
}

func AkChar() *ble.Characteristic {
	var err error
	written := 0
	readlen := 0

	c := ble.NewCharacteristic(AkCharUUID)

	// Load an Attestation Key that was given to us by the client
	c.HandleWrite(ble.WriteHandlerFunc(func(req ble.Request, rsp ble.ResponseWriter) {
		written = 0
		complete := readBuf(&readlen, &marshaledak, req)
		if complete == true {
			ak, err = tpm.LoadAK(marshaledak)
			if err != nil {
				log.Fatalf("Failed to load AK: %v", err)
			}
			readlen = 0
		}
	}))

	// Generate a new Attestation Key and provide it to the client on
	// request
	c.HandleRead(ble.ReadHandlerFunc(func(req ble.Request, rsp ble.ResponseWriter) {
		if len(encodedak) == 0 {
			if ak == nil {
				ak, err = tpm.NewAK(nil)
				if err != nil {
					log.Fatalf("Failed to create AK: %v", err)
				}
			}

			encodedak, err = json.Marshal(ak.AttestationParameters())
			if err != nil {
				log.Fatalf("Failed to marshal AK: %v", err)
			}
		}
		complete := writeBuf(&written, encodedak, rsp, false)
		if complete == true {
			written = 0
		}
	}))

	return c
}

func ActivateChar() *ble.Characteristic {
	written := 0
	readlen := 0

	c := ble.NewCharacteristic(ActivateCharUUID)

	// The client has given us a Credential Activation
	// challenge. Decrypt it using the Endorsement Key in order to prove
	// that we are the legitimate TPM and that the Activation Key
	// matches the Endorsement Key.
	c.HandleWrite(ble.WriteHandlerFunc(func(req ble.Request, rsp ble.ResponseWriter) {
		written = 0
		complete := readBuf(&readlen, &encodedec, req)
		if complete == true {
			var ec attest.EncryptedCredential
			err := json.Unmarshal(encodedec, &ec)
			if err != nil {
				log.Fatalf("Failed to unmarshal encrypted credential: %v", err)
			}
			decrypted, err = ak.ActivateCredential(tpm, ec)
			if err != nil {
				log.Fatalf("Failed to activate credentials: %v", err)
			}
			readlen = 0
		}
	}))

	// Give the decrypted secret from the Credential Activation
	// challenge back to the client. The client will then compare it to
	// the secret it generated - if they match then we must have access
	// to the Endorsement Key (because otherwise we couldn't have
	// decrypted it)
	c.HandleRead(ble.ReadHandlerFunc(func(req ble.Request, rsp ble.ResponseWriter) {
		complete := writeBuf(&written, decrypted, rsp, false)
		if complete == true {
			written = 0
		}
	}))

	return c
}

func AttestationChar() *ble.Characteristic {
	written := 0
	readlen := 0

	c := ble.NewCharacteristic(AttestationCharUUID)

	// The client sends us a random nonce. The TPM will take this nonce
	// and add it to the list of PCR values, and then sign all of this
	// with the Attestation Key. The client will check that the
	// signature is valid and that the nonce matches the nonce it sent -
	// this avoids a replay attack where an attacker simply sends back
	// an old quote. The client is then able to look at the PCR values
	// and check whether they're valid.
	c.HandleWrite(ble.WriteHandlerFunc(func(req ble.Request, rsp ble.ResponseWriter) {
		written = 0
		complete := readBuf(&readlen, &nonce, req)
		if complete == true {
			att, err := tpm.AttestPlatform(ak, nonce, nil)
			if err != nil {
				log.Fatalf("Failed to perform attestation: %v", err)
			}

			encodedattestation, err = json.Marshal(att)
			if err != nil {
				log.Fatalf("Unable to marshal attestation data: %v", err)
			}
			readlen = 0
		}
	}))

	// Send the signed PCR quote back to the client
	c.HandleRead(ble.ReadHandlerFunc(func(req ble.Request, rsp ble.ResponseWriter) {
		complete := writeBuf(&written, encodedattestation, rsp, false)
		if complete == true {
			written = 0
		}
	}))

	return c
}

func connected(evt.LEConnectionComplete) {
	decrypted = decrypted[:0]
	encodedak = encodedak[:0]
	encodedec = encodedec[:0]
	encodedattestation = encodedattestation[:0]
	nonce = nonce[:0]
}

func disconnected(evt.DisconnectionComplete) {
	authenticated = false
}

func main() {
	var err error

	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s name keydata")
	}

	data, err := ioutil.ReadFile(os.Args[2])
	if err != nil {
		log.Fatalf("Failed to read authentication key data: %v", err)
	}
	if len(data) != 16 {
		log.Fatalf("Authentication data is %d bytes long, should be 16", len(data))
	}
	copy(authkey[:], data)

	tpm, err = attest.OpenTPM(nil)
	if err != nil {
		log.Fatalf("Failed to open TPM: %v", err)
	}

	eks, err := tpm.EKs()
	if err != nil {
		log.Fatalf("Failed to read EKs: %v", err)
	}

	encodedek, err = json.Marshal(eks[0].Public)
	if err != nil {
		log.Fatalf("Unable to marshal EK: %v", err)
	}

	d, err := dev.NewDevice("default", ble.OptConnectHandler(connected), ble.OptDisconnectHandler(disconnected))
	if err != nil {
		log.Fatalf("can't new device : %v", err)
	}
	ble.SetDefaultDevice(d)
	tpmSvc := ble.NewService(TpmSvcUUID)

	tpmSvc.AddCharacteristic(AuthChar())
	tpmSvc.AddCharacteristic(EkChar())
	tpmSvc.AddCharacteristic(AkChar())
	tpmSvc.AddCharacteristic(ActivateChar())
	tpmSvc.AddCharacteristic(AttestationChar())

	if err := ble.AddService(tpmSvc); err != nil {
		log.Fatalf("can't add service: %s", err)
	}
	ctx := ble.WithSigHandler(context.WithCancel(context.Background()))
	err = ble.AdvertiseNameAndServices(ctx, os.Args[1], tpmSvc.UUID)
	log.Fatalf("Exiting with %v", err)
}
