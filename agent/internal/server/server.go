package server

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/davidcao/attestation-two-stage/agent/internal/attestation"
	"github.com/davidcao/attestation-two-stage/agent/internal/container"
	"github.com/davidcao/attestation-two-stage/agent/internal/measure"
	pb "github.com/davidcao/attestation-two-stage/agent/api/v1"
)

// Server implements the AttestationAgent gRPC service.
type Server struct {
	pb.UnimplementedAttestationAgentServer

	rtmr     attestation.RTMRExtender
	quoteGen attestation.QuoteGenerator
	images   *container.ImageManager
	runtime  *container.Runtime
	ratls    *attestation.RATLSGenerator
}

// New creates a Server with the given attestation backends.
func New(rtmr attestation.RTMRExtender, quoteGen attestation.QuoteGenerator) *Server {
	return &Server{
		rtmr:     rtmr,
		quoteGen: quoteGen,
		images:   container.NewImageManager(),
		runtime:  container.NewRuntime(),
		ratls:    attestation.NewRATLSGenerator(quoteGen),
	}
}

func (s *Server) LaunchContainer(ctx context.Context, req *pb.LaunchRequest) (*pb.LaunchResponse, error) {
	if req.ImageRef == "" {
		return nil, fmt.Errorf("image_ref is required")
	}
	log.Printf("pulling image %s", req.ImageRef)

	// 1. Pull image.
	if err := s.images.Pull(req.ImageRef); err != nil {
		return nil, fmt.Errorf("pull image: %w", err)
	}

	// 2. Get manifest digest.
	digest, err := s.images.ManifestDigest(req.ImageRef)
	if err != nil {
		return nil, fmt.Errorf("get manifest digest: %w", err)
	}
	log.Printf("manifest digest: %s", digest)

	// 3. Compute workload measurement: pad48(SHA256(digest || "\0" || cmd...))
	workloadMeasurement := measure.ComputeWorkloadMeasurement(digest, req.Command)
	log.Printf("workload measurement: %s", hex.EncodeToString(workloadMeasurement))

	// 4. Extend RTMR[2] with the workload measurement.
	if err := s.rtmr.ExtendDigest(2, workloadMeasurement); err != nil {
		log.Printf("WARNING: RTMR extension failed (no TDX hardware?): %v", err)
	}

	// 5. Compute expected RTMR[2] assuming zero initial state (for bare metal).
	// On cloud CVMs the actual RTMR[2] will differ; use a pre-launch quote
	// to get the real initial value and recompute.
	zeroRTMR := make([]byte, 48)
	expectedRTMR2 := measure.ComputeExpectedRTMR2From(zeroRTMR, workloadMeasurement)

	// 6. Start container.
	containerID, err := s.runtime.Run(container.RunConfig{
		ImageRef: req.ImageRef,
		Command:  req.Command,
		Env:      req.Env,
	})
	if err != nil {
		return nil, fmt.Errorf("run container: %w", err)
	}
	log.Printf("started container %s", containerID)

	return &pb.LaunchResponse{
		ContainerId:          containerID,
		ManifestDigest:       digest,
		Rtmr2Value:           hex.EncodeToString(expectedRTMR2),
		WorkloadMeasurement:  hex.EncodeToString(workloadMeasurement),
	}, nil
}

func (s *Server) GetQuote(ctx context.Context, req *pb.QuoteRequest) (*pb.QuoteResponse, error) {
	if len(req.ReportData) != 64 {
		return nil, fmt.Errorf("report_data must be exactly 64 bytes, got %d", len(req.ReportData))
	}

	quote, certChain, err := s.quoteGen.GetQuote(req.ReportData)
	if err != nil {
		return nil, fmt.Errorf("generate quote: %w", err)
	}

	return &pb.QuoteResponse{
		Quote:     quote,
		CertChain: certChain,
	}, nil
}

func (s *Server) GetRATLSCredentials(ctx context.Context, req *pb.RATLSRequest) (*pb.RATLSResponse, error) {
	cert, key, err := s.ratls.Generate()
	if err != nil {
		return nil, fmt.Errorf("generate RA-TLS credentials: %w", err)
	}

	return &pb.RATLSResponse{
		Certificate: cert,
		PrivateKey:  key,
	}, nil
}

func (s *Server) GetStatus(ctx context.Context, req *pb.StatusRequest) (*pb.StatusResponse, error) {
	tdxAvailable := attestation.DetectTDX()
	msg := "agent running"
	if !tdxAvailable {
		msg = "agent running (TDX not available — attestation calls will fail)"
	}

	return &pb.StatusResponse{
		Ready:        true,
		TdxAvailable: tdxAvailable,
		Message:      msg,
	}, nil
}
