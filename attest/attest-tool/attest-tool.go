// Binary attest-tool performs attestation operations on the local system.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/google/go-attestation/attest"
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
			return fmt.Errorf("MintAIK() failed: %v", err)
		}
		defer k.Close(tpm)
		b, err := k.Marshal()
		if err != nil {
			return err
		}
		return ioutil.WriteFile(*keyPath, b, 0755)

	case "quote":
		b, err := ioutil.ReadFile(*keyPath)
		if err != nil {
			return err
		}
		k, err := tpm.LoadAIK(b)
		if err != nil {
			return fmt.Errorf("tpm.LoadKey() failed: %v", err)
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
			return fmt.Errorf("Quote() failed: %v", err)
		}
		fmt.Printf("Quote: %x\n", q.Quote)
		fmt.Printf("Signature: %x\n", q.Signature)

	case "list-eks":
		eks, err := tpm.EKs()
		if err != nil {
			return fmt.Errorf("tpm.EKs() failed: %v", err)
		}
		for _, ek := range eks {
			if ek.Cert != nil {
				fmt.Printf("EK certificate: %x\n", ek.Cert.Raw)
			}
		}

	case "list-pcrs":
		pcrs, alg, err := tpm.PCRs()
		if err != nil {
			return fmt.Errorf("tpm.PCRs() failed: %v", err)
		}
		fmt.Printf("PCR digest: %v\n", alg)
		for _, pcr := range pcrs {
			fmt.Printf("PCR[%d]: %x\n", pcr.Index, pcr.Digest)
		}

	case "measurement-log":
		b, err := tpm.MeasurementLog()
		if err != nil {
			return fmt.Errorf("tpm.MeasurementLog() failed: %v", err)
		}
		fmt.Printf("%x\n", b)

	default:
		return fmt.Errorf("no such command %q", flag.Arg(0))
	}
	return nil
}
