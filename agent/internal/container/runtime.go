package container

import (
	"fmt"
	"os/exec"
	"strings"
)

// Runtime manages container lifecycle via podman.
type Runtime struct{}

func NewRuntime() *Runtime {
	return &Runtime{}
}

// RunConfig describes how to run a container.
type RunConfig struct {
	ImageRef string
	Command  []string
	Env      []string
}

// Run starts a container in detached mode and returns its ID.
func (r *Runtime) Run(cfg RunConfig) (string, error) {
	args := []string{"run", "-d", "--rm"}

	for _, e := range cfg.Env {
		args = append(args, "-e", e)
	}

	args = append(args, cfg.ImageRef)
	args = append(args, cfg.Command...)

	cmd := exec.Command("podman", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("podman run: %w\n%s", err, output)
	}

	containerID := strings.TrimSpace(string(output))
	if containerID == "" {
		return "", fmt.Errorf("podman run returned empty container ID")
	}
	return containerID, nil
}

// Stop stops a running container.
func (r *Runtime) Stop(containerID string) error {
	cmd := exec.Command("podman", "stop", containerID)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("podman stop %s: %w\n%s", containerID, err, output)
	}
	return nil
}
