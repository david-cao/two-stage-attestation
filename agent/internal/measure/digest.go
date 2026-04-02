package measure

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"strings"
)

// PadToSHA384 pads or truncates a SHA-256 digest (32 bytes) to 48 bytes
// (SHA-384 width) for RTMR extension. The digest is zero-padded on the right.
func PadToSHA384(sha256Digest []byte) []byte {
	padded := make([]byte, 48)
	copy(padded, sha256Digest)
	return padded
}

// ParseManifestDigest extracts the raw hash bytes from an OCI manifest digest
// string like "sha256:abcdef...".
func ParseManifestDigest(digest string) ([]byte, error) {
	parts := strings.SplitN(digest, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid digest format %q: expected algo:hex", digest)
	}
	if parts[0] != "sha256" {
		return nil, fmt.Errorf("unsupported digest algorithm %q, expected sha256", parts[0])
	}
	raw, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode hex digest: %w", err)
	}
	if len(raw) != sha256.Size {
		return nil, fmt.Errorf("digest length %d, expected %d", len(raw), sha256.Size)
	}
	return raw, nil
}

// DigestForRTMR converts an OCI manifest digest string to a 48-byte value
// suitable for RTMR extension.
func DigestForRTMR(manifestDigest string) ([]byte, error) {
	raw, err := ParseManifestDigest(manifestDigest)
	if err != nil {
		return nil, err
	}
	return PadToSHA384(raw), nil
}

// ComputeExpectedRTMR2 computes the expected RTMR[2] value after extending
// from the initial zero state with a single manifest digest.
// RTMR extension: new = SHA384(old || data), where old starts as 48 zero bytes.
func ComputeExpectedRTMR2(manifestDigest string) ([]byte, error) {
	padded, err := DigestForRTMR(manifestDigest)
	if err != nil {
		return nil, err
	}

	// RTMR[2] starts as 48 zero bytes.
	old := make([]byte, 48)

	return ExtendSHA384(old, padded), nil
}

// ExtendSHA384 computes SHA384(old || data), mimicking RTMR extension.
func ExtendSHA384(old, data []byte) []byte {
	combined := make([]byte, len(old)+len(data))
	copy(combined, old)
	copy(combined[len(old):], data)
	h := sha512.Sum384(combined)
	return h[:]
}
