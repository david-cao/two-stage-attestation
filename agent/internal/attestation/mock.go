package attestation

import "fmt"

// MockRTMRExtender records RTMR extensions without real hardware.
type MockRTMRExtender struct {
	Extensions []MockExtension
}

type MockExtension struct {
	Index  int
	Digest []byte
}

func NewMockRTMRExtender() *MockRTMRExtender {
	return &MockRTMRExtender{}
}

func (m *MockRTMRExtender) ExtendDigest(index int, digest []byte) error {
	if len(digest) != 48 {
		return fmt.Errorf("RTMR digest must be 48 bytes (SHA-384), got %d", len(digest))
	}
	m.Extensions = append(m.Extensions, MockExtension{Index: index, Digest: append([]byte(nil), digest...)})
	return nil
}

// MockQuoteGenerator returns a deterministic fake quote for testing.
type MockQuoteGenerator struct {
	QuoteData    []byte
	CertChain    []byte
	ReturnError  error
}

func NewMockQuoteGenerator() *MockQuoteGenerator {
	return &MockQuoteGenerator{
		QuoteData: []byte("mock-tdx-quote-data"),
		CertChain: []byte("mock-cert-chain"),
	}
}

func (m *MockQuoteGenerator) GetQuote(reportData []byte) ([]byte, []byte, error) {
	if m.ReturnError != nil {
		return nil, nil, m.ReturnError
	}
	if len(reportData) != 64 {
		return nil, nil, fmt.Errorf("report data must be 64 bytes, got %d", len(reportData))
	}
	return m.QuoteData, m.CertChain, nil
}
