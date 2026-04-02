package attestation

import (
	"fmt"

	"github.com/google/go-tdx-guest/client"
)

// QuoteGenerator abstracts TDX quote generation for testability.
type QuoteGenerator interface {
	// GetQuote generates a TDX quote with the given report data (64 bytes).
	// Returns the raw quote and the PEM certificate chain.
	GetQuote(reportData []byte) (quote []byte, certChain []byte, err error)
}

// TDXQuoteGenerator generates quotes via the TDX guest device.
type TDXQuoteGenerator struct{}

func NewTDXQuoteGenerator() *TDXQuoteGenerator {
	return &TDXQuoteGenerator{}
}

func (g *TDXQuoteGenerator) GetQuote(reportData []byte) ([]byte, []byte, error) {
	if len(reportData) != 64 {
		return nil, nil, fmt.Errorf("report data must be 64 bytes, got %d", len(reportData))
	}

	qp, err := client.GetQuoteProvider()
	if err != nil {
		return nil, nil, fmt.Errorf("get quote provider: %w", err)
	}

	var rd [64]byte
	copy(rd[:], reportData)

	rawQuote, err := qp.GetRawQuote(rd)
	if err != nil {
		return nil, nil, fmt.Errorf("get raw quote: %w", err)
	}

	// The certificate chain is typically embedded in the quote's signature
	// data. For now we return the raw quote; cert extraction happens during
	// verification.
	return rawQuote, nil, nil
}
