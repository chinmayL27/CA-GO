# Baby-CA (Go Version)

This is a Go implementation of the Baby-CA certificate authority.

## RSA Signature Scheme

The RSA signature scheme is the same as described in the original Python version.

## Communication

The communication flow is identical to the Python version. The CA listens on port 3000 for CSR requests and optionally on port 3001 for flag updates.

## Key Generation

The logic is a bit modified, and the following commands are to be used now

~~`
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048`~~

~~`openssl req -new -x509 -key private_key.pem -out certificate.pem -days 365 -passout pass:isi@jhu!2023
`~~

```
go get github.com/youmark/pkcs8

go run generate_ca.go
```

### Update the CA.pem file in each Node

```
CA: python3 -m http.server 8000

Node: iwr -uri http://192.168.1.103:8000/CA.pem -Outfile .\CA.pem

```

## Usage

### Baby-CA

```bash
go run Baby-CA.go [-f]

```

### Additional Commands

```
go run Baby-Client.go [-k] [-r]
```

### Notes

- The Go version uses the `crypto/x509` package for handling certificates and CSRs.
- The `crypto/rsa` package is used for RSA key generation and signing.
- The `net` package is used for TCP communication.
- The `sync.Mutex` is used to handle concurrent access to the `flagDict` map.

