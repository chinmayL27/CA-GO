package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/youmark/pkcs8"
)

func main() {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	certTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "192.168.1.103",
			Organization: []string{"JHU"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, &privKey.PublicKey, privKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	// Save certificate
	certOut, _ := os.Create("CA.pem")
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	certOut.Close()
	log.Println("Saved CA.pem")

	// Encrypt and save private key using default PKCS#5 v2.0 options
	password := []byte("")
	encryptedKey, err := pkcs8.MarshalPrivateKey(privKey, password, pkcs8.DefaultOpts)
	if err != nil {
		log.Fatalf("Failed to encrypt private key: %v", err)
	}

	keyOut, _ := os.Create("CAPri.key")
	pem.Encode(keyOut, &pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: encryptedKey})
	keyOut.Close()
	log.Println("Saved CAPri.key")
}
