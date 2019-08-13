// Binary attest-tool performs attestation operations on the local system.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/go-attestation/attest"
	"github.com/google/go-attestation/attest/attest-tool/internal"
)

var (
	keyPath     = flag.String("key", "aik.json", "Path to the key file")
	nonceHex    = flag.String("nonce", "", "Hex string to use as nonce when quoting")
	randomNonce = flag.Bool("random-nonce", false, "Generate a random nonce instead of using one provided")
	useSHA256   = flag.Bool("sha256", false, "Use SHA256 for quote operatons")
)

func main() {
	flag.Parse()

	if *randomNonce {
		n := make([]byte, 8)
		rand.Read(n)
		*nonceHex = hex.EncodeToString(n)
	}

	tpm, err := attest.OpenTPM(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening the TPM: %v\n", err)
		os.Exit(1)
	}

	err = runCommand(tpm)
	tpm.Close()

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runCommand(tpm *attest.TPM) error {
	switch flag.Arg(0) {
	case "info":
		info, err := tpm.Info()
		if err != nil {
			return err
		}
		fmt.Printf("Version: %d\n", info.Version)
		fmt.Printf("Interface: %d\n", info.Interface)
		fmt.Printf("VendorInfo: %x\n", info.VendorInfo)
		fmt.Printf("Manufactorer: %v\n", info.Manufacturer)

	case "make-aik":
		k, err := tpm.MintAIK(nil)
		if err != nil {
			return fmt.Errorf("failed to mint an AIK: %v", err)
		}
		defer k.Close(tpm)
		b, err := k.Marshal()
		if err != nil {
			return err
		}
		return ioutil.WriteFile(*keyPath, b, 0644)

	case "quote":
		b, err := ioutil.ReadFile(*keyPath)
		if err != nil {
			return err
		}
		k, err := tpm.LoadAIK(b)
		if err != nil {
			return fmt.Errorf("failed to load AIK: %v", err)
		}
		defer k.Close(tpm)

		nonce, err := hex.DecodeString(*nonceHex)
		if err != nil {
			return err
		}
		alg := attest.HashSHA1
		if *useSHA256 {
			alg = attest.HashSHA256
		}

		q, err := k.Quote(tpm, nonce, alg)
		if err != nil {
			return fmt.Errorf("failed to generate quote: %v", err)
		}
		fmt.Printf("Quote: %x\n", q.Quote)
		fmt.Printf("Signature: %x\n", q.Signature)

	case "list-eks":
		eks, err := tpm.EKs()
		if err != nil {
			return fmt.Errorf("failed to read EKs: %v", err)
		}
		for _, ek := range eks {
			if ek.Cert != nil {
				fmt.Printf("EK certificate: %x\n", ek.Cert.Raw)
			}
		}

	case "list-pcrs":
		pcrs, alg, err := tpm.PCRs()
		if err != nil {
			return fmt.Errorf("failed to read PCRs: %v", err)
		}
		fmt.Printf("PCR digest: %v\n", alg)
		for _, pcr := range pcrs {
			fmt.Printf("PCR[%d]: %x\n", pcr.Index, pcr.Digest)
		}

	case "measurement-log":
		b, err := tpm.MeasurementLog()
		if err != nil {
			return fmt.Errorf("failed to read the measurement log: %v", err)
		}
		fmt.Printf("%x\n", b)

	case "dump":
		dumpData, err := runDump(tpm)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(dumpData)

	default:
		return fmt.Errorf("no such command %q", flag.Arg(0))
	}
	return nil
}

func runDump(tpm *attest.TPM) (*internal.Dump, error) {
	var (
		out internal.Dump
		err error
	)

	out.Static.TPMVersion = tpm.Version()
	if out.Static.EKPem, err = rsaEKPEM(tpm); err != nil {
		return nil, err
	}

	k, err := tpm.MintAIK(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to mint an AIK: %v", err)
	}
	defer k.Close(tpm)
	out.AIK = k.AttestationParameters()

	// Get a quote.
	if out.Quote.Nonce, err = hex.DecodeString(*nonceHex); err != nil {
		return nil, fmt.Errorf("failed decoding nonce hex: %v", err)
	}
	out.Quote.Alg = attest.HashSHA1
	if *useSHA256 {
		out.Quote.Alg = attest.HashSHA256
	}
	q, err := k.Quote(tpm, out.Quote.Nonce, out.Quote.Alg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate quote: %v", err)
	}
	out.Quote.Quote = q.Quote
	out.Quote.Signature = q.Signature

	// Get log information.
	if out.Log.Raw, err = tpm.MeasurementLog(); err != nil {
		return nil, fmt.Errorf("failed to read measurement log: %v", err)
	}
	// Get PCR values.
	pcrs, _, err := tpm.PCRs()
	if err != nil {
		return nil, fmt.Errorf("failed to read PCRs: %v", err)
	}
	for _, pcr := range pcrs {
		out.Log.PCRs = append(out.Log.PCRs, pcr)
	}

	return &out, nil
}

func rsaEKPEM(tpm *attest.TPM) ([]byte, error) {
	eks, err := tpm.EKs()
	if err != nil {
		return nil, fmt.Errorf("failed to read EKs: %v", err)
	}

	var (
		pk  *rsa.PublicKey
		buf bytes.Buffer
	)
	for _, ek := range eks {
		if ek.Cert != nil && ek.Cert.PublicKeyAlgorithm == x509.RSA {
			pk = ek.Cert.PublicKey.(*rsa.PublicKey)
			break
		} else if ek.Public != nil {
			pk = ek.Public.(*rsa.PublicKey)
			break
		}
	}

	if pk == nil {
		return nil, errors.New("no EK available")
	}

	if err := pem.Encode(&buf, &pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(pk)}); err != nil {
		return nil, fmt.Errorf("failed to PEM encode: %v", err)
	}
	return buf.Bytes(), nil
}
