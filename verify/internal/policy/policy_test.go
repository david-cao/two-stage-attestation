package policy

import (
	"encoding/hex"
	"testing"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestCheckMatches(t *testing.T) {
	p := &Policy{
		Entries: []Entry{
			{
				Description: "test entry",
				RTMR2:       "aabbccdd",
			},
		},
	}

	m := &Measurements{
		MRTD:  make([]byte, 48),
		RTMR0: make([]byte, 48),
		RTMR1: make([]byte, 48),
		RTMR2: mustHex("aabbccdd"),
	}

	if err := p.Check(m); err != nil {
		t.Fatalf("expected match, got: %v", err)
	}
}

func TestCheckNoMatch(t *testing.T) {
	p := &Policy{
		Entries: []Entry{
			{
				Description: "test entry",
				RTMR2:       "aabbccdd",
			},
		},
	}

	m := &Measurements{
		MRTD:  make([]byte, 48),
		RTMR0: make([]byte, 48),
		RTMR1: make([]byte, 48),
		RTMR2: mustHex("11223344"),
	}

	if err := p.Check(m); err == nil {
		t.Fatal("expected no match")
	}
}

func TestCheckEmptyFieldSkipped(t *testing.T) {
	p := &Policy{
		Entries: []Entry{
			{
				Description: "wildcard",
				// All fields empty = matches anything.
			},
		},
	}

	m := &Measurements{
		MRTD:  make([]byte, 48),
		RTMR0: make([]byte, 48),
		RTMR1: make([]byte, 48),
		RTMR2: make([]byte, 48),
	}

	if err := p.Check(m); err != nil {
		t.Fatalf("expected match with empty policy fields, got: %v", err)
	}
}
