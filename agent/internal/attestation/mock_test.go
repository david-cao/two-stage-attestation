package attestation

import (
	"testing"
)

func TestMockRTMRExtender(t *testing.T) {
	m := NewMockRTMRExtender()

	digest := make([]byte, 48)
	digest[0] = 0xab
	if err := m.ExtendDigest(2, digest); err != nil {
		t.Fatalf("ExtendDigest: %v", err)
	}

	if len(m.Extensions) != 1 {
		t.Fatalf("expected 1 extension, got %d", len(m.Extensions))
	}
	if m.Extensions[0].Index != 2 {
		t.Fatalf("expected index 2, got %d", m.Extensions[0].Index)
	}
	if m.Extensions[0].Digest[0] != 0xab {
		t.Fatal("digest not recorded correctly")
	}
}

func TestMockRTMRExtenderRejectsWrongSize(t *testing.T) {
	m := NewMockRTMRExtender()
	if err := m.ExtendDigest(2, make([]byte, 32)); err == nil {
		t.Fatal("expected error for 32-byte digest")
	}
}

func TestMockQuoteGenerator(t *testing.T) {
	g := NewMockQuoteGenerator()
	reportData := make([]byte, 64)

	quote, cert, err := g.GetQuote(reportData)
	if err != nil {
		t.Fatalf("GetQuote: %v", err)
	}
	if len(quote) == 0 {
		t.Fatal("expected non-empty quote")
	}
	if len(cert) == 0 {
		t.Fatal("expected non-empty cert chain")
	}
}

func TestMockQuoteGeneratorRejectsWrongSize(t *testing.T) {
	g := NewMockQuoteGenerator()
	if _, _, err := g.GetQuote(make([]byte, 32)); err == nil {
		t.Fatal("expected error for 32-byte report data")
	}
}
