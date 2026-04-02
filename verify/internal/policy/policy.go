package policy

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// Policy defines expected measurement values for quote verification.
type Policy struct {
	// Entries is a list of approved measurement tuples. A quote is accepted
	// if it matches any entry.
	Entries []Entry `json:"entries"`
}

// Entry is one approved set of measurements.
type Entry struct {
	Description string `json:"description"`
	// Hex-encoded expected values. Empty string means "don't check".
	MRTD  string `json:"mrtd"`
	RTMR0 string `json:"rtmr0"`
	RTMR1 string `json:"rtmr1"`
	RTMR2 string `json:"rtmr2"`
}

// LoadPolicy reads a policy file from disk.
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	return &p, nil
}

// Measurements holds the measurement values extracted from a quote.
type Measurements struct {
	MRTD  []byte
	RTMR0 []byte
	RTMR1 []byte
	RTMR2 []byte
}

// Check returns nil if the measurements match any entry in the policy.
func (p *Policy) Check(m *Measurements) error {
	for i, e := range p.Entries {
		if err := matchEntry(&e, m); err == nil {
			return nil // matched entry i
		}
		_ = i
	}
	return fmt.Errorf("measurements do not match any policy entry")
}

func matchEntry(e *Entry, m *Measurements) error {
	checks := []struct {
		name     string
		expected string
		actual   []byte
	}{
		{"MRTD", e.MRTD, m.MRTD},
		{"RTMR[0]", e.RTMR0, m.RTMR0},
		{"RTMR[1]", e.RTMR1, m.RTMR1},
		{"RTMR[2]", e.RTMR2, m.RTMR2},
	}

	for _, c := range checks {
		if c.expected == "" {
			continue
		}
		expectedBytes, err := hex.DecodeString(c.expected)
		if err != nil {
			return fmt.Errorf("invalid hex in policy for %s: %w", c.name, err)
		}
		if !bytesEqual(expectedBytes, c.actual) {
			return fmt.Errorf("%s mismatch: expected %s, got %s",
				c.name, c.expected, hex.EncodeToString(c.actual))
		}
	}
	return nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
