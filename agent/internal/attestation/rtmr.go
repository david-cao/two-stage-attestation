package attestation

import (
	"fmt"
	"os"

	"github.com/google/go-tdx-guest/rtmr"
)

// RTMRExtender abstracts RTMR extension so it can be mocked in tests.
type RTMRExtender interface {
	// ExtendDigest extends the given RTMR index with digest (must be 48 bytes
	// for SHA-384).
	ExtendDigest(index int, digest []byte) error
}

// TDXRTMRExtender extends RTMRs via the kernel interface. It auto-detects
// whether to use the legacy configfs-tsm path (/sys/kernel/config/tsm/rtmrs)
// or the newer sysfs path (/sys/class/misc/tdx_guest/measurements/).
type TDXRTMRExtender struct{}

// NewTDXRTMRExtender creates a real RTMR extender that talks to the kernel.
func NewTDXRTMRExtender() (*TDXRTMRExtender, error) {
	return &TDXRTMRExtender{}, nil
}

func (e *TDXRTMRExtender) ExtendDigest(index int, digest []byte) error {
	if len(digest) != 48 {
		return fmt.Errorf("RTMR digest must be 48 bytes (SHA-384), got %d", len(digest))
	}
	return rtmr.ExtendDigest(index, digest)
}

// DetectTDX returns true if TDX hardware appears to be available.
func DetectTDX() bool {
	// Check configfs-tsm (standard path).
	if _, err := os.Stat("/sys/kernel/config/tsm"); err == nil {
		return true
	}
	// Check sysfs tdx_guest device (newer kernels).
	if _, err := os.Stat("/sys/class/misc/tdx_guest"); err == nil {
		return true
	}
	return false
}
