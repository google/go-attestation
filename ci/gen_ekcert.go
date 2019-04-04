package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"time"
)

var simulatorStatePath = flag.String("state_path", "/tmp/sim/NVRAM/00.permall", "Path to ibmswtpm state file")

func ekPub() *rsa.PublicKey {
	out, err := exec.Command("tpm_getpubek", "-z").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	spl := strings.Split(string(out), "Public Key:")
	hexKey := strings.NewReplacer(" ", "", "\n", "", "\r", "", "\t", "").Replace(spl[1])

	modBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(modBytes),
		E: 65537,
	}
}

func generateCertificate(pub *rsa.PublicKey) []byte {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	return derBytes
}

func main() {
	flag.Parse()
	certBytes := generateCertificate(ekPub())

	f, err := os.OpenFile("/tmp/ekcert", os.O_RDWR|os.O_TRUNC|os.O_CREATE, 0755)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Write the header as documented in: TCG PC Specific Implementation
	// Specification, section 7.3.2.
	f.Write([]byte{0x10, 0x01, 0x00})
	certLength := make([]byte, 2)
	binary.BigEndian.PutUint16(certLength, uint16(len(certBytes)))
	f.Write(certLength)

	f.Write(certBytes)
	f.Close()

	cmd := exec.Command("tpm_nvwrite", "-z", "-i", "268496896", "-f", "/tmp/ekcert")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

}
