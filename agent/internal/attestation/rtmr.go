package attestation

import (
	"fmt"
	"os"

	"github.com/google/go-configfs-tsm/configfs/configfsi"
	"github.com/google/go-configfs-tsm/configfs/linuxtsm"
	"github.com/google/go-configfs-tsm/rtmr"
)

// RTMRExtender abstracts RTMR extension so it can be mocked in tests.
type RTMRExtender interface {
	// ExtendDigest extends the given RTMR index with digest (must be 48 bytes
	// for SHA-384).
	ExtendDigest(index int, digest []byte) error
}

// TDXRTMRExtender extends RTMRs via the configfs-tsm kernel interface.
type TDXRTMRExtender struct {
	client configfsi.Client
}

// NewTDXRTMRExtender creates a real RTMR extender that talks to the kernel.
func NewTDXRTMRExtender() (*TDXRTMRExtender, error) {
	client, err := linuxtsm.MakeClient()
	if err != nil {
		return nil, fmt.Errorf("open configfs-tsm client: %w", err)
	}
	return &TDXRTMRExtender{client: client}, nil
}

func (e *TDXRTMRExtender) ExtendDigest(index int, digest []byte) error {
	if len(digest) != 48 {
		return fmt.Errorf("RTMR digest must be 48 bytes (SHA-384), got %d", len(digest))
	}
	return rtmr.ExtendDigest(e.client, index, digest)
}

// DetectTDX returns true if TDX hardware appears to be available.
func DetectTDX() bool {
	// configfs-tsm is mounted at /sys/kernel/config/tsm when TDX is available.
	_, err := os.Stat("/sys/kernel/config/tsm")
	return err == nil
}
