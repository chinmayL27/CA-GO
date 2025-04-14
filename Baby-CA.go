package main

import (
	"crypto/rand"
	"crypto/rsa"
	// "crypto/tls"
	"crypto/x509"
	// "crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
	"CA-GO/config"
)

var (
	caPrivateKey  *rsa.PrivateKey
	caCertificate *x509.Certificate
	flagDict      = make(map[string]bool)
	flagMutex     sync.Mutex
)

func loadCAKeys() {
	// Load CA private key
	keyData, err := os.ReadFile(config.CaPrivateKeyPath)
	if err != nil {
		log.Fatalf("Failed to read CA private key: %v", err)
	}
	block, _ := pem.Decode(keyData)

	// fmt.Println(block.Type)
	
	if block == nil || block.Type != "PRIVATE KEY" {
		log.Fatalf("Failed to decode CA private key")
	}

	caPrivateKeyParsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse CA private key: %v", err)
	}

	var ok = bool(false)

	caPrivateKey, ok = caPrivateKeyParsed.(*rsa.PrivateKey)
    if !ok {
        log.Fatalf("Parsed key is not an RSA private key")
    }


	// Load CA certificate
	certData, err := os.ReadFile(config.CaCertificatePath)
	if err != nil {
		log.Fatalf("Failed to read CA certificate: %v", err)
	}
	block, _ = pem.Decode(certData)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Fatalf("Failed to decode CA certificate")
	}
	caCertificate, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse CA certificate: %v", err)
	}
}

func generateCertificate(csr *x509.CertificateRequest) []byte {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(3 * 24 * time.Hour), // Valid for 3 days
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         false,
	}

	// Copy SAN extension from CSR
	for _, ext := range csr.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 17}) { // SAN OID
			template.ExtraExtensions = append(template.ExtraExtensions, ext)
		}
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, caCertificate, csr.PublicKey, caPrivateKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
}

func listenCSR() {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", config.ListenAddr, config.ListenPort))
	if err != nil {
		log.Fatalf("Failed to listen on port %d: %v", config.ListenPort, err)
	}
	defer listener.Close()

	fmt.Println(listener)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go func(conn net.Conn) {
			defer conn.Close()

			clientIP := conn.RemoteAddr().(*net.TCPAddr).IP.String()
			flagMutex.Lock()
			allowed := false
			for _, ip := range config.AllowedIPs {
				if ip == clientIP {
					allowed = true
					break
				}
			}
			flagged := flagDict[clientIP]
			flagMutex.Unlock()

			if !allowed || flagged {
				log.Printf("CA: IP %s is either not allowed or flagged.", clientIP)
				conn.Write([]byte("IP not allowed."))
				return
			}

			csrData := make([]byte, 2048)
			n, err := conn.Read(csrData)
			if err != nil {
				log.Printf("Failed to read CSR data: %v", err)
				return
			}

			block, _ := pem.Decode(csrData[:n])
			if block == nil || block.Type != "CERTIFICATE REQUEST" {
				log.Printf("Invalid CSR data received")
				return
			}

			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				log.Printf("Failed to parse CSR: %v", err)
				return
			}

			cert := generateCertificate(csr)
			conn.Write(cert)
		}(conn)
	}
}

func listenFlag() {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", config.ListenAddr, config.ListenFlagPort))
	if err != nil {
		log.Fatalf("Failed to listen on port %d: %v", config.ListenFlagPort, err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go func(conn net.Conn) {
			defer conn.Close()

			clientIP := conn.RemoteAddr().(*net.TCPAddr).IP.String()
			flagMutex.Lock()
			allowed := false
			for _, ip := range config.AllowedIPs {
				if ip == clientIP {
					allowed = true
					break
				}
			}
			flagMutex.Unlock()

			if !allowed {
				log.Printf("Flag server: connection from unallowed IP: %s", clientIP)
				return
			}

			data := make([]byte, 1024)
			n, err := conn.Read(data)
			if err != nil {
				log.Printf("Failed to read flag data: %v", err)
				return
			}

			if string(data[:n]) == "1\n" {
				flagMutex.Lock()
				flagDict[clientIP] = true
				flagMutex.Unlock()
				log.Printf("Flag server: flag updated for %s", clientIP)
			}
		}(conn)
	}
}

func main() {
	flagPtr := flag.Bool("f", false, "The CA will constantly receive flags from clients.")
	flag.Parse()

	loadCAKeys()

	if *flagPtr {
		log.Println("Flag value is set as True")
		go listenFlag()
	}

	listenCSR()
}