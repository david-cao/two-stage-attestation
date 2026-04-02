package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// RATLSGenerator creates RA-TLS credentials: an ephemeral TLS keypair with
// the TDX quote embedded in the X.509 certificate as an extension.
type RATLSGenerator struct {
	quoteGen QuoteGenerator
}

// TDX quote extension OID (under Anthropic's private arc; placeholder).
var quoteExtensionOID = []int{1, 3, 6, 1, 4, 1, 57264, 1, 1}

func NewRATLSGenerator(qg QuoteGenerator) *RATLSGenerator {
	return &RATLSGenerator{quoteGen: qg}
}

// Generate creates an ephemeral ECDSA keypair and self-signed X.509 cert
// with the TDX quote embedded as a non-critical extension.
func (g *RATLSGenerator) Generate() (certPEM []byte, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ECDSA key: %w", err)
	}

	// Serialize public key as report data for the quote.
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal public key: %w", err)
	}

	// Hash to 64 bytes for report data (pad or truncate the DER).
	reportData := make([]byte, 64)
	copy(reportData, pubDER)

	quote, _, err := g.quoteGen.GetQuote(reportData)
	if err != nil {
		return nil, nil, fmt.Errorf("get quote for RA-TLS: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "TDX Attestation Agent (RA-TLS)"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: []pkix.Extension{
			{
				Id:       quoteExtensionOID,
				Critical: false,
				Value:    quote,
			},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal private key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}
