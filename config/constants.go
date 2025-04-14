package config

// Configuration
const (
	ListenAddr        = "0.0.0.0"
	ListenPort        = 3000
	ListenFlagPort    = 3001
	CaCertificatePath = "certificate.pem"
	CaPrivateKeyPath  = "private_key.pem"
)

var AllowedIPs = []string{"192.168.1.100", "192.168.1.101", "192.168.1.102"}
