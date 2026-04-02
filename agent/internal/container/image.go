package container

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// ImageManager handles OCI image operations via podman.
type ImageManager struct{}

func NewImageManager() *ImageManager {
	return &ImageManager{}
}

// Pull downloads an OCI image using podman.
func (m *ImageManager) Pull(imageRef string) error {
	cmd := exec.Command("podman", "pull", imageRef)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("podman pull %s: %w\n%s", imageRef, err, output)
	}
	return nil
}

// podmanInspect is the subset of podman inspect output we need.
type podmanInspect struct {
	Digest string `json:"Digest"`
}

// ManifestDigest returns the OCI manifest digest (sha256:...) for an image.
func (m *ImageManager) ManifestDigest(imageRef string) (string, error) {
	cmd := exec.Command("podman", "inspect", "--format", "{{.Digest}}", imageRef)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Fallback: try podman image inspect with JSON output.
		cmd = exec.Command("podman", "image", "inspect", imageRef)
		output, err = cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("podman image inspect %s: %w\n%s", imageRef, err, output)
		}

		var inspects []podmanInspect
		if err := json.Unmarshal(output, &inspects); err != nil {
			return "", fmt.Errorf("parse inspect output: %w", err)
		}
		if len(inspects) == 0 || inspects[0].Digest == "" {
			return "", fmt.Errorf("no digest found for image %s", imageRef)
		}
		return inspects[0].Digest, nil
	}

	digest := strings.TrimSpace(string(output))
	if digest == "" {
		return "", fmt.Errorf("empty digest for image %s", imageRef)
	}
	return digest, nil
}
