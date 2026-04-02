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

	// 3. Pad digest to 48 bytes and extend RTMR[2].
	paddedDigest, err := measure.DigestForRTMR(digest)
	if err != nil {
		return nil, fmt.Errorf("prepare digest for RTMR: %w", err)
	}

	if err := s.rtmr.ExtendDigest(2, paddedDigest); err != nil {
		log.Printf("WARNING: RTMR extension failed (no TDX hardware?): %v", err)
	}

	// 4. Compute expected RTMR[2] value for the response.
	expectedRTMR2, err := measure.ComputeExpectedRTMR2(digest)
	if err != nil {
		return nil, fmt.Errorf("compute expected RTMR[2]: %w", err)
	}

	// 5. Start container.
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
		ContainerId:    containerID,
		ManifestDigest: digest,
		Rtmr2Value:     hex.EncodeToString(expectedRTMR2),
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
