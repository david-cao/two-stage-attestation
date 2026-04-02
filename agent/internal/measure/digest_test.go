package measure

import (
	"encoding/hex"
	"testing"
)

func TestParseManifestDigest(t *testing.T) {
	digest := "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
	raw, err := ParseManifestDigest(digest)
	if err != nil {
		t.Fatalf("ParseManifestDigest: %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(raw))
	}
	if hex.EncodeToString(raw) != "a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4" {
		t.Fatalf("unexpected digest bytes: %s", hex.EncodeToString(raw))
	}
}

func TestParseManifestDigestErrors(t *testing.T) {
	tests := []string{
		"",
		"nodash",
		"md5:abc",
		"sha256:zzzz",
		"sha256:abcd", // too short
	}
	for _, d := range tests {
		if _, err := ParseManifestDigest(d); err == nil {
			t.Errorf("expected error for %q", d)
		}
	}
}

func TestPadToSHA384(t *testing.T) {
	input := make([]byte, 32)
	input[0] = 0xff
	padded := PadToSHA384(input)
	if len(padded) != 48 {
		t.Fatalf("expected 48 bytes, got %d", len(padded))
	}
	if padded[0] != 0xff {
		t.Fatal("first byte should be 0xff")
	}
	for i := 32; i < 48; i++ {
		if padded[i] != 0 {
			t.Fatalf("byte %d should be zero, got %d", i, padded[i])
		}
	}
}

func TestComputeExpectedRTMR2(t *testing.T) {
	digest := "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
	result, err := ComputeExpectedRTMR2(digest)
	if err != nil {
		t.Fatalf("ComputeExpectedRTMR2: %v", err)
	}
	if len(result) != 48 {
		t.Fatalf("expected 48 bytes, got %d", len(result))
	}
	// The result should be deterministic.
	result2, _ := ComputeExpectedRTMR2(digest)
	if hex.EncodeToString(result) != hex.EncodeToString(result2) {
		t.Fatal("ComputeExpectedRTMR2 should be deterministic")
	}
}

func TestComputeWorkloadMeasurement(t *testing.T) {
	digest := "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
	cmd := []string{"echo", "hello"}

	m1 := ComputeWorkloadMeasurement(digest, cmd)
	if len(m1) != 48 {
		t.Fatalf("expected 48 bytes, got %d", len(m1))
	}

	// Deterministic.
	m2 := ComputeWorkloadMeasurement(digest, cmd)
	if hex.EncodeToString(m1) != hex.EncodeToString(m2) {
		t.Fatal("should be deterministic")
	}

	// Different command produces different measurement.
	m3 := ComputeWorkloadMeasurement(digest, []string{"sh", "-c", "exit"})
	if hex.EncodeToString(m1) == hex.EncodeToString(m3) {
		t.Fatal("different commands should produce different measurements")
	}

	// Same image, no command vs with command.
	m4 := ComputeWorkloadMeasurement(digest, nil)
	if hex.EncodeToString(m1) == hex.EncodeToString(m4) {
		t.Fatal("empty command should differ from non-empty")
	}
}

func TestComputeExpectedRTMR2From(t *testing.T) {
	pre := make([]byte, 48)
	pre[0] = 0xab // simulate non-zero initial RTMR[2]
	measurement := ComputeWorkloadMeasurement(
		"sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4",
		[]string{"echo", "hello"},
	)
	result := ComputeExpectedRTMR2From(pre, measurement)
	if len(result) != 48 {
		t.Fatalf("expected 48 bytes, got %d", len(result))
	}

	// Different pre-extension values produce different results.
	pre2 := make([]byte, 48)
	result2 := ComputeExpectedRTMR2From(pre2, measurement)
	if hex.EncodeToString(result) == hex.EncodeToString(result2) {
		t.Fatal("different pre-extension values should produce different results")
	}
}

func TestExtendSHA384(t *testing.T) {
	old := make([]byte, 48)
	data := make([]byte, 48)
	data[0] = 1
	result := ExtendSHA384(old, data)
	if len(result) != 48 {
		t.Fatalf("expected 48 bytes, got %d", len(result))
	}
	// Different inputs should produce different outputs.
	data2 := make([]byte, 48)
	data2[0] = 2
	result2 := ExtendSHA384(old, data2)
	if hex.EncodeToString(result) == hex.EncodeToString(result2) {
		t.Fatal("different inputs should produce different results")
	}
}
